from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import time

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.sensors.process import ProcessSensor
from agent.sensors.rust_process_shadow import (
    EPOCH_TICKS,
    RustProcessShadowError,
    compare_shadow_to_authoritative,
    validate_rust_v04_snapshot,
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def rust_row(pid: int, ppid: int, created: float, name: str = "proc.exe") -> dict:
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


def rust_snapshot(rows: list[dict], skipped: list[dict], stamp: float) -> dict:
    return {
        "schema": "cd.process.v4",
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": stamp,
        "partial": bool(skipped),
        "skipped": len(skipped),
        "process_count": len(rows),
        "processes": rows,
        "skipped_processes": skipped,
    }


class FixedPythonSensor:
    def __init__(self, snapshot: dict):
        self.snapshot = snapshot
        self.calls = 0

    def collect(self):
        self.calls += 1
        return self.snapshot

    def health_check(self):
        return {"sensor": "FixedPythonSensor", "status": "HEALTHY", "version": "test"}


class FixedRustShadow:
    def __init__(self, snapshot: dict):
        self.snapshot = snapshot
        self.calls = 0

    def probe(self):
        self.calls += 1
        return self.snapshot

    def health_check(self):
        return {
            "component": "RustProcessShadowProbe",
            "status": "HEALTHY",
            "mode": "SHADOW_ONLY",
            "version": "test",
        }


class FailingRustShadow:
    def probe(self):
        raise RustProcessShadowError("injected shadow failure")

    def health_check(self):
        return {
            "component": "RustProcessShadowProbe",
            "status": "DEGRADED",
            "mode": "SHADOW_ONLY",
        }


def provision_runtime() -> tuple[tempfile.TemporaryDirectory, CyberDefenderRuntime]:
    temp = tempfile.TemporaryDirectory(prefix="cyberdefender_rust_shadow_")
    os.environ["CYBERDEFENDER_STATE_DIR"] = temp.name
    storage_key = os.urandom(32)
    os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(storage_key).decode()
    os.environ.pop("CYBERDEFENDER_RUST_PROCESS_SHADOW", None)
    os.environ.pop("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE", None)

    km = KeyManager(Path(temp.name) / "keys", storage_key)
    if not km.generate_key() or not km.is_ready():
        raise AssertionError("test signing key provisioning failed")

    runtime = CyberDefenderRuntime(SafetyCore(), load_config())
    return temp, runtime


def main() -> int:
    now = time.time() - 1.0
    row = rust_row(100, 4, now)
    raw = json.dumps(rust_snapshot([row], [], now + 0.1), separators=(",", ":")).encode()
    validated = validate_rust_v04_snapshot(raw, now=now + 0.1)
    check(validated["process_count"] == 1, "Rust v0.4 wire validator accepts canonical snapshot")

    invalid = json.loads(raw.decode())
    invalid["unexpected"] = True
    try:
        validate_rust_v04_snapshot(json.dumps(invalid).encode(), now=now + 0.1)
    except RustProcessShadowError:
        pass
    else:
        raise AssertionError("schema expansion was not rejected")
    print("[PASS] Rust wire validator rejects uncontracted schema expansion")

    py_snapshot = {
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": now + 0.1,
        "process_count": 2,
        "processes": [
            {
                "pid": 100,
                "ppid": 4,
                "name": "proc.exe",
                "exe": None,
                "username": None,
                "cmdline": None,
                "create_time": row["create_time"],
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            },
            {
                "pid": 200,
                "ppid": 100,
                "name": "child.exe",
                "exe": None,
                "username": None,
                "cmdline": None,
                "create_time": row["create_time"] + 0.5,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            },
        ],
    }
    rust_partial = rust_snapshot(
        [row],
        [{"pid": 200, "reason": "OPEN_ACCESS_DENIED", "win32_error": 5}],
        now + 0.2,
    )
    comparison = compare_shadow_to_authoritative(py_snapshot, rust_partial)
    check(comparison["verdict"] == "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS", "Partial Rust snapshot remains diagnostic-only evidence")
    check(comparison["identity_disagreements"]["count"] == 0, "Common PID identity matches ProcessGraph precision")
    check(comparison["python_only"]["with_rust_skip_reason"] == 1, "Skipped Python PID retains explicit Rust reason")

    temp, runtime = provision_runtime()
    try:
        check(isinstance(runtime.process_sensor, ProcessSensor), "Python ProcessSensor remains authoritative by default")
        check(runtime.rust_process_shadow_enabled is False, "Rust shadow is opt-in and disabled by default")

        fixed_python = FixedPythonSensor(py_snapshot)
        fixed_rust = FixedRustShadow(rust_partial)
        runtime.process_sensor = fixed_python
        runtime.rust_process_shadow_enabled = True
        runtime.rust_process_shadow = fixed_rust

        result = runtime.update_process_graph()
        check(isinstance(result, dict) and result.get("accepted") is True, "Authoritative Python snapshot is accepted by ProcessGraph")
        check(result.get("processes_valid") == 2, "Rust partial snapshot cannot reduce ProcessGraph process count")
        check(fixed_python.calls == 1 and fixed_rust.calls == 1, "Authoritative and shadow sensors each run once")
        check(runtime.last_rust_process_shadow_result is not None, "Shadow comparison is retained for diagnostics")
        check(runtime.last_rust_process_shadow_result["verdict"] == "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS", "Runtime records non-authoritative coverage-limited shadow verdict")

        running_nodes = [
            node for node in runtime.process_graph.nodes.values()
            if node.get("state") == "RUNNING"
        ]
        check(len(running_nodes) == 2, "Rust partial data never causes false ProcessGraph EXITED state")

        failures_before = runtime.component_failures
        degraded_before = runtime.degraded
        shadow_failures_before = runtime.rust_process_shadow_failures
        runtime.rust_process_shadow = FailingRustShadow()
        shadow_result = runtime._update_rust_process_shadow(py_snapshot)
        check(shadow_result is None, "Shadow probe failure is contained")
        check(runtime.component_failures == failures_before, "Shadow failure does not increment security component failures")
        check(runtime.degraded == degraded_before, "Shadow failure does not degrade authoritative runtime")
        check(runtime.rust_process_shadow_failures == shadow_failures_before + 1, "Shadow failure has isolated diagnostic counter")

        health = runtime.health_snapshot()
        check("rust_process_shadow" in health, "Rust shadow has explicit health surface")
        check(health["runtime"]["status"] == "HEALTHY", "Non-critical shadow failure does not change runtime HEALTHY state")

    finally:
        runtime.close()
        temp.cleanup()

    print("\nRUST PROCESS SHADOW RUNTIME v1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
