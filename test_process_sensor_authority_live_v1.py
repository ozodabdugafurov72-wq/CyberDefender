from __future__ import annotations

import base64
import os
from pathlib import Path
import tempfile
from typing import Any

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.sensors.process_authority import (
    ProcessSensorAuthorityController,
    ProcessSensorMode,
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def main() -> int:
    executable = str(
        os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or ""
    ).strip()
    if not executable:
        raise AssertionError(
            "CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE is required"
        )

    exe_path = Path(executable).expanduser().resolve()
    check(exe_path.is_file(), "RustProcessSensor executable exists")

    with tempfile.TemporaryDirectory(
        prefix="cyberdefender_process_authority_live_"
    ) as state_dir:
        old_env = {
            name: os.environ.get(name)
            for name in (
                "CYBERDEFENDER_STATE_DIR",
                "CYBERDEFENDER_STORAGE_KEY_B64",
                "CYBERDEFENDER_PROCESS_SENSOR_MODE",
                "CYBERDEFENDER_RUST_PROCESS_SHADOW",
                "CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE",
                "CYBERDEFENDER_RUST_PRIMARY_UNLOCK",
            )
        }

        try:
            os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
            storage_key = os.urandom(32)
            os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(
                storage_key
            ).decode()
            os.environ["CYBERDEFENDER_PROCESS_SENSOR_MODE"] = (
                ProcessSensorMode.RUST_CANARY
            )
            os.environ.pop("CYBERDEFENDER_RUST_PROCESS_SHADOW", None)
            os.environ["CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE"] = str(
                exe_path
            )
            os.environ.pop("CYBERDEFENDER_RUST_PRIMARY_UNLOCK", None)

            km = KeyManager(Path(state_dir) / "keys", storage_key)
            check(
                km.generate_key() and km.is_ready(),
                "Temporary signing key is provisioned",
            )

            runtime = CyberDefenderRuntime(SafetyCore(), load_config())
            try:
                controller = runtime.process_authority_controller
                graph = runtime.process_graph

                check(
                    controller is not None,
                    "Runtime initializes ProcessSensorAuthorityController",
                )
                check(
                    runtime.process_sensor_mode == ProcessSensorMode.RUST_CANARY,
                    "Runtime enters explicit RUST_CANARY mode",
                )
                check(
                    runtime.rust_process_shadow_enabled,
                    "RUST_CANARY enables non-authoritative Rust probe",
                )
                check(
                    runtime.rust_process_sensor_binary_trusted,
                    "Rust executable passes pinned binary hash gate",
                )
                check(
                    runtime.rust_process_sensor_sha256
                    == ProcessSensorAuthorityController.PINNED_RUST_V04_SHA256,
                    "Runtime records exact pinned Rust v0.4 SHA-256",
                )
                check(
                    controller.compiled_primary_enabled is False,
                    "Production Rust primary remains compile-locked",
                )
                check(graph is not None, "ProcessGraph is initialized")

                original_ingest = graph.ingest_snapshot
                graph_sources: list[str | None] = []

                def guarded_ingest(snapshot: Any) -> dict[str, Any]:
                    if not isinstance(snapshot, dict):
                        raise AssertionError("ProcessGraph received non-dict snapshot")
                    graph_sources.append(snapshot.get("sensor"))
                    if snapshot.get("sensor") != "ProcessSensor":
                        raise AssertionError(
                            "Canary attempted authoritative graph ingestion: "
                            f"{snapshot.get('sensor')!r}"
                        )
                    return original_ingest(snapshot)

                graph.ingest_snapshot = guarded_ingest  # type: ignore[method-assign]

                for cycle in range(1, 4):
                    result = runtime.update_process_graph()
                    check(
                        isinstance(result, dict) and result.get("accepted") is True,
                        f"Cycle {cycle}: Python-authoritative graph update accepted",
                    )
                    check(
                        len(graph_sources) == cycle,
                        f"Cycle {cycle}: exactly one ProcessGraph ingest occurred",
                    )
                    check(
                        all(source == "ProcessSensor" for source in graph_sources),
                        f"Cycle {cycle}: ProcessGraph source remains Python",
                    )
                    check(
                        runtime.last_rust_process_shadow_result is not None,
                        f"Cycle {cycle}: Rust comparison evidence recorded",
                    )
                    check(
                        runtime.last_rust_process_shadow_result.get("verdict")
                        in {
                            "ALIGNED_COMMON_SET",
                            "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
                        },
                        f"Cycle {cycle}: Rust parity remains aligned",
                    )
                    check(
                        runtime.last_rust_process_shadow_result
                        .get("identity_disagreements", {})
                        .get("count")
                        == 0,
                        f"Cycle {cycle}: identity disagreements remain zero",
                    )
                    check(
                        runtime.last_rust_process_shadow_result
                        .get("parent_disagreements", {})
                        .get("count")
                        == 0,
                        f"Cycle {cycle}: parent disagreements remain zero",
                    )

                evidence = controller.last_rust_evidence
                check(
                    evidence is not None and evidence.eligible,
                    "Canary accumulates authority-eligible Rust evidence",
                )
                check(
                    evidence.coverage_mode
                    in {"COMPLETE", "PARTIAL_EXPLICIT_COVERAGE"},
                    "Canary evidence has lifecycle-safe coverage mode",
                )
                check(
                    evidence.binary_trusted and evidence.probe_healthy,
                    "Canary evidence retains binary trust and probe health",
                )

                rust_snapshot = runtime.rust_process_shadow.last_snapshot
                check(
                    isinstance(rust_snapshot, dict),
                    "Validated live Rust snapshot remains available to canary controller",
                )

                first_loss = controller.decide(
                    python_snapshot=None,
                    rust_snapshot=rust_snapshot,
                    rust_evidence=evidence,
                )
                check(
                    first_loss.disposition == "HOLD_LAST_GRAPH_STATE",
                    "Canary first simulated Python loss holds graph state",
                )

                second_loss = controller.decide(
                    python_snapshot=None,
                    rust_snapshot=rust_snapshot,
                    rust_evidence=evidence,
                )
                check(
                    second_loss.authoritative_sensor is None
                    and second_loss.would_select_sensor == "RustProcessSensor"
                    and second_loss.disposition == "CANARY_NO_AUTHORITY_SWITCH",
                    "Canary proves would-failover readiness without authority switch",
                )

                check(
                    all(source == "ProcessSensor" for source in graph_sources),
                    "Canary simulation never injects Rust into ProcessGraph",
                )

                health = runtime.health_snapshot()
                check(
                    health.get("runtime", {}).get("status") == "HEALTHY",
                    "Canary authority telemetry does not degrade core runtime",
                )
                check(
                    health.get("process_sensor_authority", {}).get("mode")
                    == ProcessSensorMode.RUST_CANARY,
                    "Health exposes RUST_CANARY authority mode",
                )
                check(
                    health.get("process_sensor_authority", {}).get(
                        "compiled_primary_enabled"
                    )
                    is False,
                    "Health exposes production primary compile lock",
                )

                print("\nPROCESS SENSOR AUTHORITY LIVE v1: PASS")
                return 0
            finally:
                runtime.close()
        finally:
            for name, value in old_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


if __name__ == "__main__":
    raise SystemExit(main())
