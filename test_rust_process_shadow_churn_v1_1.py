from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


GOOD_VERDICTS = {
    "ALIGNED_COMMON_SET",
    "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
}


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def counter(runtime: CyberDefenderRuntime, name: str) -> int:
    try:
        return int(getattr(runtime, name, 0))
    except (TypeError, ValueError):
        return -1


def graph_node_for_pid(graph: Any, pid: int) -> tuple[str | None, dict[str, Any] | None]:
    nodes = getattr(graph, "nodes", {})
    if not isinstance(nodes, dict):
        return None, None

    for identity, node in nodes.items():
        if not isinstance(node, dict):
            continue
        try:
            node_pid = int(node.get("pid"))
        except (TypeError, ValueError):
            continue
        if node_pid == pid:
            return str(identity), node
    return None, None


def rust_row_for_pid(shadow_probe: Any, pid: int) -> dict[str, Any] | None:
    snapshot = getattr(shadow_probe, "last_snapshot", None)
    if not isinstance(snapshot, dict):
        return None

    rows = snapshot.get("processes", [])
    if not isinstance(rows, list):
        return None

    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            row_pid = int(row.get("pid"))
        except (TypeError, ValueError):
            continue
        if row_pid == pid:
            return row
    return None


def tracked_identity_matches(
    graph: Any,
    shadow_probe: Any,
    pid: int,
) -> bool:
    _, graph_node = graph_node_for_pid(graph, pid)
    rust_row = rust_row_for_pid(shadow_probe, pid)

    if not isinstance(graph_node, dict) or not isinstance(rust_row, dict):
        return False

    try:
        graph_created = float(graph_node.get("create_time"))
        rust_created = float(rust_row.get("create_time"))
    except (TypeError, ValueError, OverflowError):
        return False

    return f"{graph_created:.6f}" == f"{rust_created:.6f}"


def assert_shadow_cycle(
    runtime: CyberDefenderRuntime,
    graph_ingest_sources: list[str | None],
    expected_cycle: int,
    baseline_component_failures: int,
    baseline_graph_failures: int,
    baseline_sensor_failures: int,
    baseline_shadow_failures: int,
) -> dict[str, Any]:
    result = runtime.update_process_graph()

    check(
        isinstance(result, dict) and result.get("accepted") is True,
        f"Cycle {expected_cycle}: authoritative ProcessGraph ingestion accepted",
    )

    comparison = runtime.last_rust_process_shadow_result
    check(
        isinstance(comparison, dict),
        f"Cycle {expected_cycle}: Rust shadow comparison recorded",
    )
    check(
        comparison.get("mode") == "SHADOW_ONLY",
        f"Cycle {expected_cycle}: Rust remains SHADOW_ONLY",
    )
    check(
        comparison.get("verdict") in GOOD_VERDICTS,
        f"Cycle {expected_cycle}: common-set parity remains aligned",
    )
    check(
        comparison.get("identity_disagreements", {}).get("count") == 0,
        f"Cycle {expected_cycle}: identity disagreements remain zero",
    )
    check(
        comparison.get("parent_disagreements", {}).get("count") == 0,
        f"Cycle {expected_cycle}: parent disagreements remain zero",
    )
    check(
        int(comparison.get("exact_graph_identity_matches", -1))
        == int(comparison.get("common_processes", -2)),
        f"Cycle {expected_cycle}: every common PID has exact graph identity",
    )

    # IMPORTANT:
    # Python and Rust snapshots are sequential, not atomic. During intentional
    # churn, a short-lived process may exist in the Python snapshot and exit
    # before Rust enumerates it. Such python-only-without-skip entries are
    # telemetry, not an automatic parity failure.
    python_only_without_skip = int(
        comparison.get("python_only", {}).get(
            "without_rust_skip_reason", 0
        )
    )

    check(
        len(graph_ingest_sources) == expected_cycle,
        f"Cycle {expected_cycle}: exactly one ProcessGraph ingest occurred",
    )
    check(
        all(source == "ProcessSensor" for source in graph_ingest_sources),
        f"Cycle {expected_cycle}: every graph ingest source is authoritative Python ProcessSensor",
    )

    health = runtime.health_snapshot()
    check(
        health.get("runtime", {}).get("status") == "HEALTHY",
        f"Cycle {expected_cycle}: authoritative runtime remains HEALTHY",
    )
    check(
        health.get("rust_process_shadow", {}).get("mode") == "SHADOW_ONLY",
        f"Cycle {expected_cycle}: Rust health surface remains non-authoritative",
    )

    check(
        counter(runtime, "component_failures") == baseline_component_failures,
        f"Cycle {expected_cycle}: component failures did not increase",
    )
    check(
        counter(runtime, "process_graph_failures") == baseline_graph_failures,
        f"Cycle {expected_cycle}: ProcessGraph failures did not increase",
    )
    check(
        counter(runtime, "process_sensor_failures") == baseline_sensor_failures,
        f"Cycle {expected_cycle}: authoritative ProcessSensor failures did not increase",
    )
    check(
        counter(runtime, "rust_process_shadow_failures") == baseline_shadow_failures,
        f"Cycle {expected_cycle}: isolated Rust shadow failure counter did not increase",
    )

    return {
        "cycle": expected_cycle,
        "graph_created": len(result.get("created", [])),
        "graph_updated": len(result.get("updated", [])),
        "graph_exited": len(result.get("exited", [])),
        "graph_nodes": int(result.get("node_count", 0)),
        "graph_processes_valid": int(result.get("processes_valid", 0)),
        "python_process_count": int(comparison.get("python_process_count", 0)),
        "rust_process_count": int(comparison.get("rust_process_count", 0)),
        "common_processes": int(comparison.get("common_processes", 0)),
        "python_only": int(comparison.get("python_only", {}).get("count", 0)),
        "python_only_without_skip_reason": python_only_without_skip,
        "rust_only": int(comparison.get("rust_only", {}).get("count", 0)),
        "rust_partial": bool(comparison.get("rust_partial")),
        "verdict": comparison.get("verdict"),
    }


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
        prefix="cyberdefender_rust_shadow_churn_v1_1_"
    ) as state_dir:
        os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
        storage_key = os.urandom(32)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(
            storage_key
        ).decode()
        os.environ["CYBERDEFENDER_RUST_PROCESS_SHADOW"] = "1"
        os.environ["CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE"] = str(exe_path)

        km = KeyManager(Path(state_dir) / "keys", storage_key)
        check(
            km.generate_key() and km.is_ready(),
            "Temporary signing key is provisioned",
        )

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        tracked_child: subprocess.Popen[Any] | None = None
        burst_children: list[subprocess.Popen[Any]] = []

        try:
            check(
                runtime.rust_process_shadow_enabled,
                "Runtime Rust shadow flag is enabled",
            )
            check(
                runtime.rust_process_shadow is not None,
                "Runtime initialized Rust shadow probe",
            )

            graph = runtime.process_graph
            authoritative_sensor = runtime.process_sensor
            shadow_probe = runtime.rust_process_shadow

            check(graph is not None, "ProcessGraph is initialized")
            check(
                authoritative_sensor is not None,
                "Python ProcessSensor is initialized",
            )
            check(
                shadow_probe is not None,
                "Rust shadow probe is initialized",
            )

            original_ingest = graph.ingest_snapshot
            graph_ingest_sources: list[str | None] = []

            def guarded_ingest(snapshot: Any) -> dict[str, Any]:
                if not isinstance(snapshot, dict):
                    raise AssertionError(
                        "ProcessGraph received non-dict snapshot"
                    )

                source = snapshot.get("sensor")
                graph_ingest_sources.append(source)

                if source != "ProcessSensor":
                    raise AssertionError(
                        "Non-authoritative sensor attempted ProcessGraph ingestion: "
                        f"{source!r}"
                    )

                return original_ingest(snapshot)

            graph.ingest_snapshot = guarded_ingest  # type: ignore[method-assign]

            baseline_component_failures = counter(
                runtime, "component_failures"
            )
            baseline_graph_failures = counter(
                runtime, "process_graph_failures"
            )
            baseline_sensor_failures = counter(
                runtime, "process_sensor_failures"
            )
            baseline_shadow_failures = counter(
                runtime, "rust_process_shadow_failures"
            )

            rows: list[dict[str, Any]] = []

            # Phase 1: clean baseline.
            rows.append(
                assert_shadow_cycle(
                    runtime,
                    graph_ingest_sources,
                    1,
                    baseline_component_failures,
                    baseline_graph_failures,
                    baseline_sensor_failures,
                    baseline_shadow_failures,
                )
            )

            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(
                    subprocess, "CREATE_NO_WINDOW", 0
                )

            # Phase 2: one intentionally long-lived tracked child.
            tracked_child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(30)",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            tracked_pid = int(tracked_child.pid)
            print(f"\nTracked churn PID started: {tracked_pid}")

            tracked_running_seen = False
            tracked_rust_seen = False
            tracked_identity_match_seen = False

            for cycle in range(2, 5):
                time.sleep(0.4)

                rows.append(
                    assert_shadow_cycle(
                        runtime,
                        graph_ingest_sources,
                        cycle,
                        baseline_component_failures,
                        baseline_graph_failures,
                        baseline_sensor_failures,
                        baseline_shadow_failures,
                    )
                )

                _, graph_node = graph_node_for_pid(
                    graph, tracked_pid
                )
                if (
                    isinstance(graph_node, dict)
                    and graph_node.get("state") == "RUNNING"
                ):
                    tracked_running_seen = True

                rust_row = rust_row_for_pid(
                    shadow_probe, tracked_pid
                )
                if isinstance(rust_row, dict):
                    tracked_rust_seen = True

                if tracked_identity_matches(
                    graph, shadow_probe, tracked_pid
                ):
                    tracked_identity_match_seen = True

            check(
                tracked_running_seen,
                "Authoritative ProcessGraph observed tracked child as RUNNING",
            )
            check(
                tracked_rust_seen,
                "Rust shadow observed long-lived tracked child",
            )
            check(
                tracked_identity_match_seen,
                "Tracked child graph identity matches Rust at six-decimal contract",
            )

            # Phase 3: intentional short-lived burst churn.
            for index in range(8):
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import time; "
                            f"time.sleep({0.55 + (index % 3) * 0.20})"
                        ),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                )
                burst_children.append(child)

            for cycle in range(5, 8):
                time.sleep(0.30)

                rows.append(
                    assert_shadow_cycle(
                        runtime,
                        graph_ingest_sources,
                        cycle,
                        baseline_component_failures,
                        baseline_graph_failures,
                        baseline_sensor_failures,
                        baseline_shadow_failures,
                    )
                )

                # The tracked child is deliberately long-lived, so it must not
                # disappear just because short-lived burst children churn.
                _, graph_node = graph_node_for_pid(
                    graph, tracked_pid
                )
                check(
                    isinstance(graph_node, dict)
                    and graph_node.get("state") == "RUNNING",
                    f"Cycle {cycle}: tracked child remains RUNNING during burst churn",
                )

                check(
                    rust_row_for_pid(shadow_probe, tracked_pid) is not None,
                    f"Cycle {cycle}: Rust still observes tracked child during burst churn",
                )

                check(
                    tracked_identity_matches(
                        graph, shadow_probe, tracked_pid
                    ),
                    f"Cycle {cycle}: tracked child identity remains aligned during burst churn",
                )

            for child in burst_children:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)

            # Phase 4: tracked child exits and authoritative graph must own
            # the lifecycle transition.
            tracked_child.terminate()
            try:
                tracked_child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tracked_child.kill()
                tracked_child.wait(timeout=5)

            print(f"Tracked churn PID stopped: {tracked_pid}")

            tracked_exited_seen = False
            exit_cycle = None

            for cycle in range(8, 13):
                time.sleep(0.45)

                rows.append(
                    assert_shadow_cycle(
                        runtime,
                        graph_ingest_sources,
                        cycle,
                        baseline_component_failures,
                        baseline_graph_failures,
                        baseline_sensor_failures,
                        baseline_shadow_failures,
                    )
                )

                _, graph_node = graph_node_for_pid(
                    graph, tracked_pid
                )

                if (
                    isinstance(graph_node, dict)
                    and graph_node.get("state") == "EXITED"
                ):
                    tracked_exited_seen = True
                    exit_cycle = cycle
                    break

            check(
                tracked_exited_seen,
                "Authoritative ProcessGraph observed tracked child transition to EXITED",
            )

            cycles_completed = len(graph_ingest_sources)
            sensor_stats = authoritative_sensor.get_stats()
            probe_stats = shadow_probe.get_stats()

            check(
                int(sensor_stats.get("collect_count", -1))
                == cycles_completed,
                "Python ProcessSensor collected exactly once per churn cycle",
            )
            check(
                int(probe_stats.get("probe_count", -1))
                == cycles_completed,
                "Rust shadow executed exactly once per churn cycle",
            )
            check(
                int(probe_stats.get("failed_count", -1)) == 0,
                "Rust shadow transport/validation failures remain zero",
            )

            total_unexplained_python_only = sum(
                int(row.get("python_only_without_skip_reason", 0))
                for row in rows
            )

            summary = {
                "schema": "cd.rust-shadow-churn.v1.1",
                "mode": "SHADOW_ONLY",
                "authoritative_sensor": "ProcessSensor",
                "shadow_sensor": "RustProcessSensor",
                "cycles_completed": cycles_completed,
                "tracked_pid": tracked_pid,
                "tracked_running_seen": tracked_running_seen,
                "tracked_rust_seen": tracked_rust_seen,
                "tracked_identity_match_seen": tracked_identity_match_seen,
                "tracked_exited_seen": tracked_exited_seen,
                "tracked_exit_cycle": exit_cycle,
                "burst_children": len(burst_children),
                "sequential_snapshot_churn_telemetry": {
                    "python_only_without_skip_reason_total": (
                        total_unexplained_python_only
                    ),
                    "note": (
                        "Allowed telemetry under intentional churn because "
                        "Python and Rust snapshots are sequential, not atomic."
                    ),
                },
                "graph_ingest_sources_all_authoritative": all(
                    source == "ProcessSensor"
                    for source in graph_ingest_sources
                ),
                "component_failures": counter(
                    runtime, "component_failures"
                ),
                "process_graph_failures": counter(
                    runtime, "process_graph_failures"
                ),
                "process_sensor_failures": counter(
                    runtime, "process_sensor_failures"
                ),
                "rust_process_shadow_failures": counter(
                    runtime, "rust_process_shadow_failures"
                ),
                "cycles": rows,
            }

            print("\nRUST SHADOW CHURN SUMMARY")
            print(json.dumps(summary, indent=2, sort_keys=True))
            print("\nRUST PROCESS SHADOW CHURN v1.1: PASS")
            return 0

        finally:
            for child in burst_children:
                if child.poll() is None:
                    try:
                        child.kill()
                    except Exception:
                        pass

            if tracked_child is not None and tracked_child.poll() is None:
                try:
                    tracked_child.kill()
                except Exception:
                    pass

            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
