from __future__ import annotations

import base64
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.sensors.process_authority import (
    ProcessSensorAuthorityController,
    ProcessSensorMode,
)
from agent.sensors.rust_process_shadow import EPOCH_TICKS


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def clear_authority_env() -> None:
    for name in (
        "CYBERDEFENDER_PROCESS_SENSOR_MODE",
        "CYBERDEFENDER_RUST_PRIMARY_UNLOCK",
        "CYBERDEFENDER_RUST_PROCESS_SHADOW",
        "CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE",
        "CYBERDEFENDER_PROCESS_PYTHON_FAILURE_THRESHOLD",
        "CYBERDEFENDER_PROCESS_PYTHON_RECOVERY_THRESHOLD",
        "CYBERDEFENDER_PROCESS_RUST_HEALTHY_THRESHOLD",
        "CYBERDEFENDER_PROCESS_ALIGNMENT_MAX_AGE_SECONDS",
    ):
        os.environ.pop(name, None)


def provision_runtime() -> tuple[tempfile.TemporaryDirectory, CyberDefenderRuntime]:
    temp = tempfile.TemporaryDirectory(prefix="cyberdefender_authority_runtime_")
    os.environ["CYBERDEFENDER_STATE_DIR"] = temp.name
    storage_key = os.urandom(32)
    os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(storage_key).decode()

    km = KeyManager(Path(temp.name) / "keys", storage_key)
    if not km.generate_key() or not km.is_ready():
        raise AssertionError("test signing key provisioning failed")

    runtime = CyberDefenderRuntime(SafetyCore(), load_config())
    return temp, runtime


def python_snapshot(stamp: float) -> dict[str, Any]:
    return {
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": stamp,
        "process_count": 2,
        "processes": [
            {
                "pid": 100,
                "ppid": 4,
                "name": "parent.exe",
                "exe": "C:/parent.exe",
                "username": "test",
                "cmdline": ["parent.exe"],
                "create_time": 1000.0,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            },
            {
                "pid": 200,
                "ppid": 100,
                "name": "child.exe",
                "exe": "C:/child.exe",
                "username": "test",
                "cmdline": ["child.exe"],
                "create_time": 2000.0,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            },
        ],
    }


def rust_row(pid: int, ppid: int, created: float, name: str) -> dict[str, Any]:
    ticks = EPOCH_TICKS + int(created * 10_000_000)
    canonical = (ticks - EPOCH_TICKS) / 10_000_000.0
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "create_time": canonical,
        "creation_filetime": str(ticks),
        "exe": None,
        "username": None,
        "cmdline": None,
        "cpu_percent": None,
        "memory_percent": None,
    }


def rust_snapshot(stamp: float) -> dict[str, Any]:
    return {
        "schema": "cd.process.v4",
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": stamp,
        "partial": True,
        "skipped": 1,
        "process_count": 2,
        "processes": [
            rust_row(100, 4, 1000.0, "parent.exe"),
            rust_row(200, 100, 2000.0, "child.exe"),
        ],
        "skipped_processes": [
            {
                "pid": 0,
                "reason": "SYSTEM_IDLE_UNQUERYABLE",
                "win32_error": 87,
            }
        ],
    }


class FixedPythonSensor:
    def __init__(self, snapshot: dict[str, Any]):
        self.snapshot = snapshot
        self.calls = 0

    def collect(self) -> dict[str, Any]:
        self.calls += 1
        return self.snapshot

    def health_check(self) -> dict[str, Any]:
        return {"sensor": "ProcessSensor", "status": "HEALTHY", "version": "test"}

    def get_stats(self) -> dict[str, Any]:
        return {
            "sensor": "ProcessSensor",
            "version": "test",
            "collect_count": self.calls,
            "failed_count": 0,
        }


class FixedRustProbe:
    def __init__(self, snapshot: dict[str, Any]):
        self.snapshot = snapshot
        self.calls = 0

    def probe(self) -> dict[str, Any]:
        self.calls += 1
        return self.snapshot

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "RustProcessShadowProbe",
            "status": "HEALTHY",
            "mode": "SHADOW_ONLY",
            "version": "test",
            "probe_count": self.calls,
            "failed_count": 0,
            "last_error": None,
        }

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()


def main() -> int:
    clear_authority_env()
    temp, runtime = provision_runtime()
    try:
        controller = runtime.process_authority_controller
        check(controller is not None, "runtime wires ProcessSensorAuthorityController")
        check(
            runtime.process_sensor_mode == ProcessSensorMode.PYTHON_ONLY,
            "safe default remains PYTHON_ONLY for backward compatibility",
        )
        check(
            runtime.rust_process_shadow_enabled is False,
            "safe default does not execute Rust probe",
        )
        check(
            controller.compiled_primary_enabled is False,
            "production Rust primary remains compile-locked",
        )

        snap = python_snapshot(time.time())
        fixed = FixedPythonSensor(snap)
        runtime.process_sensor = fixed

        graph_sources: list[str | None] = []
        original_ingest = runtime.process_graph.ingest_snapshot

        def guarded(snapshot: Any) -> dict[str, Any]:
            graph_sources.append(snapshot.get("sensor"))
            return original_ingest(snapshot)

        runtime.process_graph.ingest_snapshot = guarded  # type: ignore[method-assign]
        result = runtime.update_process_graph()
        check(
            isinstance(result, dict) and result.get("accepted") is True,
            "normal runtime ProcessGraph update remains accepted",
        )
        check(
            graph_sources == ["ProcessSensor"],
            "authority foundation preserves Python-only ProcessGraph ownership",
        )
        check(
            runtime.last_process_authority_decision is not None
            and runtime.last_process_authority_decision.get("authoritative_sensor")
            == "ProcessSensor",
            "runtime records explicit Python authority decision",
        )

        health = runtime.health_snapshot()
        check(
            health.get("process_sensor_authority", {}).get("status") == "HEALTHY",
            "authority controller is first-class health telemetry",
        )
        check(
            health.get("process_sensor_authority", {}).get("authoritative_sensor")
            == "ProcessSensor",
            "health exposes authoritative process sensor",
        )

        # Invalid configuration must not broaden authority.
        os.environ["CYBERDEFENDER_PROCESS_SENSOR_MODE"] = "INVALID_PRIMARY"
        runtime._initialize_process_sensor_authority()
        check(
            runtime.process_sensor_mode == ProcessSensorMode.PYTHON_ONLY,
            "invalid runtime mode falls back to PYTHON_ONLY",
        )
        check(
            runtime.process_authority_config_error == "INVALID_PROCESS_SENSOR_MODE",
            "invalid runtime mode is observable",
        )
        check(
            runtime.process_authority_controller.health_check()["status"] == "DEGRADED",
            "invalid authority config degrades authority health only",
        )

        # Legacy shadow flag maps into the new mode model.
        os.environ.pop("CYBERDEFENDER_PROCESS_SENSOR_MODE", None)
        os.environ["CYBERDEFENDER_RUST_PROCESS_SHADOW"] = "1"
        runtime._initialize_process_sensor_authority()
        check(
            runtime.process_sensor_mode == ProcessSensorMode.RUST_SHADOW,
            "legacy Rust shadow flag maps to RUST_SHADOW mode",
        )

        # Legacy v0.4 shadow remains available as a distinct mode.  The new
        # persistent v0.5.1 RUST_CANARY path is covered by the dedicated
        # process_sensor_canary_runtime_integration_v1 regression.
        runtime.process_authority_controller = ProcessSensorAuthorityController(
            mode=ProcessSensorMode.RUST_SHADOW,
            rust_healthy_threshold=2,
        )
        runtime.process_sensor_mode = ProcessSensorMode.RUST_SHADOW
        runtime.rust_process_canary_enabled = False
        runtime.rust_process_shadow_enabled = True
        runtime.rust_process_sensor_sha256 = (
            ProcessSensorAuthorityController.PINNED_RUST_V04_SHA256
        )
        runtime.rust_process_sensor_binary_trusted = True
        fixed_rust = FixedRustProbe(rust_snapshot(time.time()))
        runtime.rust_process_shadow = fixed_rust

        graph_sources.clear()
        runtime.update_process_graph()
        runtime.update_process_graph()
        check(
            graph_sources == ["ProcessSensor", "ProcessSensor"],
            "RUST_SHADOW never changes ProcessGraph source ownership",
        )
        check(
            runtime.process_authority_controller.rust_healthy_streak >= 2,
            "legacy shadow accumulates bounded Rust health evidence",
        )
        check(
            runtime.process_authority_controller.last_rust_evidence is not None
            and runtime.process_authority_controller.last_rust_evidence.eligible,
            "legacy shadow records readiness evidence without promotion",
        )

        # Even explicit primary request + operator token cannot bypass release lock.
        runtime.process_authority_controller = ProcessSensorAuthorityController(
            mode=ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK,
            primary_unlock_token=(
                ProcessSensorAuthorityController.PRIMARY_UNLOCK_TOKEN
            ),
            compiled_primary_enabled=False,
        )
        runtime.process_sensor_mode = ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK
        check(
            not runtime.process_authority_controller.primary_runtime_unlocked(),
            "operator configuration cannot bypass compiled primary lock",
        )
        check(
            runtime.process_authority_controller.health_check()["status"] == "LOCKED",
            "requested but unavailable primary mode is explicitly LOCKED",
        )

        check(
            runtime.health_snapshot()["runtime"]["status"] == "HEALTHY",
            "authority foundation introduces no core runtime degradation",
        )

    finally:
        runtime.close()
        temp.cleanup()
        clear_authority_env()

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
