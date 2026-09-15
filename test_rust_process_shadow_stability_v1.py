from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


CYCLES = 10
CYCLE_DELAY_SECONDS = 0.25
GOOD_VERDICTS = {
    "ALIGNED_COMMON_SET",
    "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
}


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def _runtime_counter(runtime: CyberDefenderRuntime, name: str) -> int:
    try:
        return int(getattr(runtime, name, 0))
    except (TypeError, ValueError):
        return -1


def main() -> int:
    executable = str(os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or "").strip()
    if not executable:
        raise AssertionError("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE is required")

    exe_path = Path(executable).expanduser().resolve()
    check(exe_path.is_file(), "RustProcessSensor executable exists")

    with tempfile.TemporaryDirectory(prefix="cyberdefender_rust_shadow_stability_") as state_dir:
        os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
        storage_key = os.urandom(32)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(storage_key).decode()
        os.environ["CYBERDEFENDER_RUST_PROCESS_SHADOW"] = "1"
        os.environ["CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE"] = str(exe_path)

        km = KeyManager(Path(state_dir) / "keys", storage_key)
        check(km.generate_key() and km.is_ready(), "Temporary signing key is provisioned")

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        try:
            check(runtime.rust_process_shadow_enabled, "Runtime Rust shadow flag is enabled")
            check(runtime.rust_process_shadow is not None, "Runtime initialized Rust shadow probe")

            graph = runtime.process_graph
            authoritative_sensor = runtime.process_sensor
            shadow_probe = runtime.rust_process_shadow
            check(graph is not None, "ProcessGraph is initialized")
            check(authoritative_sensor is not None, "Python ProcessSensor is initialized")
            check(shadow_probe is not None, "Rust shadow probe is initialized")

            original_ingest = graph.ingest_snapshot
            graph_ingest_sources: list[str | None] = []

            def guarded_ingest(snapshot: Any) -> dict[str, Any]:
                if not isinstance(snapshot, dict):
                    raise AssertionError("ProcessGraph received non-dict snapshot")
                graph_ingest_sources.append(snapshot.get("sensor"))
                if snapshot.get("sensor") != "ProcessSensor":
                    raise AssertionError(
                        "Non-authoritative sensor attempted ProcessGraph ingestion: "
                        f"{snapshot.get('sensor')!r}"
                    )
                return original_ingest(snapshot)

            graph.ingest_snapshot = guarded_ingest  # type: ignore[method-assign]

            baseline_component_failures = _runtime_counter(runtime, "component_failures")
            baseline_graph_failures = _runtime_counter(runtime, "process_graph_failures")
            baseline_sensor_failures = _runtime_counter(runtime, "process_sensor_failures")
            baseline_shadow_failures = _runtime_counter(runtime, "rust_process_shadow_failures")

            rows: list[dict[str, Any]] = []

            for cycle in range(1, CYCLES + 1):
                result = runtime.update_process_graph()
                check(
                    isinstance(result, dict) and result.get("accepted") is True,
                    f"Cycle {cycle}: authoritative ProcessGraph ingestion accepted",
                )

                comparison = runtime.last_rust_process_shadow_result
                check(isinstance(comparison, dict), f"Cycle {cycle}: shadow comparison recorded")
                check(
                    comparison.get("mode") == "SHADOW_ONLY",
                    f"Cycle {cycle}: Rust remains SHADOW_ONLY",
                )
                check(
                    comparison.get("verdict") in GOOD_VERDICTS,
                    f"Cycle {cycle}: common-set parity remains aligned",
                )
                check(
                    comparison.get("identity_disagreements", {}).get("count") == 0,
                    f"Cycle {cycle}: identity disagreements remain zero",
                )
                check(
                    comparison.get("parent_disagreements", {}).get("count") == 0,
                    f"Cycle {cycle}: parent disagreements remain zero",
                )
                check(
                    int(comparison.get("exact_graph_identity_matches", -1))
                    == int(comparison.get("common_processes", -2)),
                    f"Cycle {cycle}: every common PID has exact graph identity",
                )

                check(
                    len(graph_ingest_sources) == cycle,
                    f"Cycle {cycle}: exactly one ProcessGraph ingest occurred",
                )
                check(
                    all(source == "ProcessSensor" for source in graph_ingest_sources),
                    f"Cycle {cycle}: every graph ingest source is authoritative Python ProcessSensor",
                )

                probe_stats = shadow_probe.get_stats()
                check(
                    int(probe_stats.get("probe_count", -1)) == cycle,
                    f"Cycle {cycle}: exactly one Rust shadow probe occurred",
                )
                check(
                    int(probe_stats.get("failed_count", -1)) == 0,
                    f"Cycle {cycle}: Rust shadow transport/validation failures remain zero",
                )

                health = runtime.health_snapshot()
                check(
                    health.get("runtime", {}).get("status") == "HEALTHY",
                    f"Cycle {cycle}: authoritative runtime remains HEALTHY",
                )
                check(
                    health.get("rust_process_shadow", {}).get("mode") == "SHADOW_ONLY",
                    f"Cycle {cycle}: health surface remains explicitly non-authoritative",
                )

                check(
                    _runtime_counter(runtime, "component_failures") == baseline_component_failures,
                    f"Cycle {cycle}: component failures did not increase",
                )
                check(
                    _runtime_counter(runtime, "process_graph_failures") == baseline_graph_failures,
                    f"Cycle {cycle}: ProcessGraph failures did not increase",
                )
                check(
                    _runtime_counter(runtime, "process_sensor_failures") == baseline_sensor_failures,
                    f"Cycle {cycle}: authoritative ProcessSensor failures did not increase",
                )
                check(
                    _runtime_counter(runtime, "rust_process_shadow_failures") == baseline_shadow_failures,
                    f"Cycle {cycle}: isolated Rust shadow failure counter did not increase",
                )

                rows.append(
                    {
                        "cycle": cycle,
                        "graph_processes_valid": int(result.get("processes_valid", 0)),
                        "graph_nodes": int(result.get("node_count", 0)),
                        "graph_created": len(result.get("created", [])),
                        "graph_updated": len(result.get("updated", [])),
                        "graph_exited": len(result.get("exited", [])),
                        "python_process_count": int(comparison.get("python_process_count", 0)),
                        "rust_process_count": int(comparison.get("rust_process_count", 0)),
                        "common_processes": int(comparison.get("common_processes", 0)),
                        "python_only": int(comparison.get("python_only", {}).get("count", 0)),
                        "python_only_without_skip_reason": int(
                            comparison.get("python_only", {}).get("without_rust_skip_reason", 0)
                        ),
                        "rust_only": int(comparison.get("rust_only", {}).get("count", 0)),
                        "rust_partial": bool(comparison.get("rust_partial")),
                        "verdict": comparison.get("verdict"),
                    }
                )

                if cycle != CYCLES:
                    time.sleep(CYCLE_DELAY_SECONDS)

            sensor_stats = authoritative_sensor.get_stats()
            check(
                int(sensor_stats.get("collect_count", -1)) == CYCLES,
                "Python ProcessSensor collected exactly once per stability cycle",
            )
            check(
                len(graph_ingest_sources) == CYCLES,
                "ProcessGraph received exactly one authoritative snapshot per stability cycle",
            )
            check(
                int(shadow_probe.get_stats().get("probe_count", -1)) == CYCLES,
                "Rust shadow executed exactly once per stability cycle",
            )

            print("\nRUST SHADOW STABILITY SUMMARY")
            print(json.dumps(rows, indent=2, sort_keys=True))
            print("\nRUST PROCESS SHADOW STABILITY v1: PASS")
            return 0
        finally:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
