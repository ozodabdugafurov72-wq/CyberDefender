from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any

import psutil

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


GOOD_VERDICTS = {
    "ALIGNED_COMMON_SET",
    "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
}

DEFAULT_DURATION_HOURS = 1.0
DEFAULT_INTERVAL_SECONDS = 5.0
DEFAULT_HEARTBEAT_SECONDS = 60.0


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _counter(runtime: CyberDefenderRuntime, name: str) -> int:
    try:
        return int(getattr(runtime, name, 0))
    except (TypeError, ValueError):
        return -1


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "CyberDefender Rust Process Sensor shadow soak/lifecycle test. "
            "Python ProcessSensor remains authoritative."
        )
    )
    parser.add_argument(
        "--duration-hours",
        type=float,
        default=DEFAULT_DURATION_HOURS,
        help="Soak duration in hours. Default: 1.0",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Delay between cycles. Default: 5.0",
    )
    parser.add_argument(
        "--heartbeat-seconds",
        type=float,
        default=DEFAULT_HEARTBEAT_SECONDS,
        help="Console heartbeat interval. Default: 60.0",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="",
        help="Optional JSONL output path. Default: repo logs/rust_shadow_soak_<timestamp>.jsonl",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if args.duration_hours <= 0:
        raise AssertionError("--duration-hours must be > 0")
    if args.interval_seconds <= 0:
        raise AssertionError("--interval-seconds must be > 0")
    if args.heartbeat_seconds <= 0:
        raise AssertionError("--heartbeat-seconds must be > 0")

    executable = str(
        os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or ""
    ).strip()
    if not executable:
        raise AssertionError(
            "CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE is required"
        )

    exe_path = Path(executable).expanduser().resolve()
    _check(exe_path.is_file(), "RustProcessSensor executable exists")

    started_wall = time.time()
    started_mono = time.monotonic()
    deadline = started_mono + (args.duration_hours * 3600.0)

    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(started_wall))
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
    else:
        output_path = (
            Path.cwd()
            / "logs"
            / f"rust_shadow_soak_{timestamp}.jsonl"
        ).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    process = psutil.Process(os.getpid())
    initial_rss = int(process.memory_info().rss)
    max_rss = initial_rss

    summary: dict[str, Any] = {
        "schema": "cd.rust-shadow-soak.v1",
        "status": "RUNNING",
        "mode": "SHADOW_ONLY",
        "authoritative_sensor": "ProcessSensor",
        "shadow_sensor": "RustProcessSensor",
        "started_at_epoch": started_wall,
        "requested_duration_hours": float(args.duration_hours),
        "interval_seconds": float(args.interval_seconds),
        "rust_executable": str(exe_path),
        "rust_executable_sha256": _sha256(exe_path),
        "cycles_completed": 0,
        "aligned_cycles": 0,
        "coverage_limited_cycles": 0,
        "identity_disagreement_cycles": 0,
        "parent_disagreement_cycles": 0,
        "unexplained_python_only_cycles": 0,
        "runtime_unhealthy_cycles": 0,
        "max_python_only": 0,
        "max_rust_only": 0,
        "max_common_processes": 0,
        "min_common_processes": None,
        "graph_created_total": 0,
        "graph_exited_total": 0,
        "initial_rss_bytes": initial_rss,
        "max_rss_bytes": initial_rss,
        "final_rss_bytes": initial_rss,
        "output_path": str(output_path),
    }

    with tempfile.TemporaryDirectory(
        prefix="cyberdefender_rust_shadow_soak_"
    ) as state_dir:
        os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
        storage_key = os.urandom(32)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(
            storage_key
        ).decode()
        os.environ["CYBERDEFENDER_RUST_PROCESS_SHADOW"] = "1"
        os.environ["CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE"] = str(exe_path)

        km = KeyManager(Path(state_dir) / "keys", storage_key)
        _check(
            km.generate_key() and km.is_ready(),
            "Temporary signing key is provisioned",
        )

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())

        graph = None
        authoritative_sensor = None
        shadow_probe = None
        log_fh = None

        try:
            _check(
                runtime.rust_process_shadow_enabled,
                "Runtime Rust shadow flag is enabled",
            )
            _check(
                runtime.rust_process_shadow is not None,
                "Runtime initialized Rust shadow probe",
            )

            graph = runtime.process_graph
            authoritative_sensor = runtime.process_sensor
            shadow_probe = runtime.rust_process_shadow

            _check(graph is not None, "ProcessGraph is initialized")
            _check(
                authoritative_sensor is not None,
                "Python ProcessSensor is initialized",
            )
            _check(
                shadow_probe is not None,
                "Rust shadow probe is initialized",
            )

            original_ingest = graph.ingest_snapshot
            ingest_count = 0
            invalid_ingest_source_count = 0

            def guarded_ingest(
                snapshot: Any,
            ) -> dict[str, Any]:
                nonlocal ingest_count, invalid_ingest_source_count

                if not isinstance(snapshot, dict):
                    raise AssertionError(
                        "ProcessGraph received non-dict snapshot"
                    )

                ingest_count += 1
                source = snapshot.get("sensor")

                if source != "ProcessSensor":
                    invalid_ingest_source_count += 1
                    raise AssertionError(
                        "Non-authoritative sensor attempted ProcessGraph "
                        f"ingestion: {source!r}"
                    )

                return original_ingest(snapshot)

            graph.ingest_snapshot = guarded_ingest  # type: ignore[method-assign]

            baseline_component_failures = _counter(
                runtime, "component_failures"
            )
            baseline_graph_failures = _counter(
                runtime, "process_graph_failures"
            )
            baseline_sensor_failures = _counter(
                runtime, "process_sensor_failures"
            )
            baseline_shadow_failures = _counter(
                runtime, "rust_process_shadow_failures"
            )

            sensor_stats_start = authoritative_sensor.get_stats()
            probe_stats_start = shadow_probe.get_stats()

            sensor_collect_start = _safe_int(
                sensor_stats_start.get("collect_count"), 0
            )
            probe_count_start = _safe_int(
                probe_stats_start.get("probe_count"), 0
            )
            probe_failed_start = _safe_int(
                probe_stats_start.get("failed_count"), 0
            )

            log_fh = output_path.open(
                "w",
                encoding="utf-8",
                buffering=1,
            )
            log_fh.write(
                json.dumps(
                    {
                        "type": "start",
                        **summary,
                    },
                    sort_keys=True,
                )
                + "\n"
            )

            print("RUST PROCESS SHADOW SOAK v1")
            print("=" * 72)
            print(f"Mode: SHADOW_ONLY")
            print("Authoritative sensor: ProcessSensor")
            print("Shadow sensor: RustProcessSensor")
            print(f"Duration: {args.duration_hours} hour(s)")
            print(f"Interval: {args.interval_seconds} second(s)")
            print(f"JSONL: {output_path}")
            print(f"Rust EXE SHA-256: {summary['rust_executable_sha256']}")
            print()

            cycle = 0
            next_heartbeat = started_mono

            while True:
                now_mono = time.monotonic()
                if cycle > 0 and now_mono >= deadline:
                    break

                cycle += 1
                cycle_started_mono = time.monotonic()
                cycle_started_wall = time.time()

                result = runtime.update_process_graph()
                _check(
                    isinstance(result, dict)
                    and result.get("accepted") is True,
                    f"Cycle {cycle}: authoritative ProcessGraph ingestion rejected",
                )

                comparison = runtime.last_rust_process_shadow_result
                _check(
                    isinstance(comparison, dict),
                    f"Cycle {cycle}: shadow comparison missing",
                )
                _check(
                    comparison.get("mode") == "SHADOW_ONLY",
                    f"Cycle {cycle}: Rust left SHADOW_ONLY mode",
                )
                _check(
                    comparison.get("verdict") in GOOD_VERDICTS,
                    f"Cycle {cycle}: parity verdict is not aligned: "
                    f"{comparison.get('verdict')!r}",
                )

                identity_count = _safe_int(
                    comparison.get(
                        "identity_disagreements", {}
                    ).get("count"),
                    -1,
                )
                parent_count = _safe_int(
                    comparison.get(
                        "parent_disagreements", {}
                    ).get("count"),
                    -1,
                )
                common_processes = _safe_int(
                    comparison.get("common_processes"), -1
                )
                exact_matches = _safe_int(
                    comparison.get(
                        "exact_graph_identity_matches"
                    ),
                    -2,
                )
                python_only = _safe_int(
                    comparison.get("python_only", {}).get("count"),
                    0,
                )
                python_only_without_reason = _safe_int(
                    comparison.get("python_only", {}).get(
                        "without_rust_skip_reason"
                    ),
                    0,
                )
                rust_only = _safe_int(
                    comparison.get("rust_only", {}).get("count"),
                    0,
                )

                _check(
                    identity_count == 0,
                    f"Cycle {cycle}: identity disagreement detected",
                )
                _check(
                    parent_count == 0,
                    f"Cycle {cycle}: parent disagreement detected",
                )
                _check(
                    exact_matches == common_processes,
                    f"Cycle {cycle}: not every common PID has exact graph identity",
                )
                _check(
                    python_only_without_reason == 0,
                    f"Cycle {cycle}: Python-only PID lacks Rust skip reason",
                )

                _check(
                    ingest_count == cycle,
                    f"Cycle {cycle}: expected exactly one ProcessGraph ingest",
                )
                _check(
                    invalid_ingest_source_count == 0,
                    f"Cycle {cycle}: non-authoritative graph ingest observed",
                )

                probe_stats = shadow_probe.get_stats()
                _check(
                    _safe_int(probe_stats.get("probe_count"), -1)
                    == probe_count_start + cycle,
                    f"Cycle {cycle}: Rust shadow probe count mismatch",
                )
                _check(
                    _safe_int(probe_stats.get("failed_count"), -1)
                    == probe_failed_start,
                    f"Cycle {cycle}: Rust shadow transport/validation failure increased",
                )

                health = runtime.health_snapshot()
                runtime_status = health.get(
                    "runtime", {}
                ).get("status")
                shadow_mode = health.get(
                    "rust_process_shadow", {}
                ).get("mode")

                _check(
                    runtime_status == "HEALTHY",
                    f"Cycle {cycle}: authoritative runtime is {runtime_status!r}",
                )
                _check(
                    shadow_mode == "SHADOW_ONLY",
                    f"Cycle {cycle}: shadow health surface changed mode",
                )

                _check(
                    _counter(runtime, "component_failures")
                    == baseline_component_failures,
                    f"Cycle {cycle}: component_failures increased",
                )
                _check(
                    _counter(runtime, "process_graph_failures")
                    == baseline_graph_failures,
                    f"Cycle {cycle}: process_graph_failures increased",
                )
                _check(
                    _counter(runtime, "process_sensor_failures")
                    == baseline_sensor_failures,
                    f"Cycle {cycle}: process_sensor_failures increased",
                )
                _check(
                    _counter(runtime, "rust_process_shadow_failures")
                    == baseline_shadow_failures,
                    f"Cycle {cycle}: isolated Rust shadow failure counter increased",
                )

                rss_bytes = int(process.memory_info().rss)
                max_rss = max(max_rss, rss_bytes)

                verdict = comparison.get("verdict")
                graph_created = len(result.get("created", []))
                graph_exited = len(result.get("exited", []))

                summary["cycles_completed"] = cycle
                summary["aligned_cycles"] += 1
                if verdict == "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS":
                    summary["coverage_limited_cycles"] += 1

                summary["max_python_only"] = max(
                    int(summary["max_python_only"]),
                    python_only,
                )
                summary["max_rust_only"] = max(
                    int(summary["max_rust_only"]),
                    rust_only,
                )
                summary["max_common_processes"] = max(
                    int(summary["max_common_processes"]),
                    common_processes,
                )

                current_min = summary["min_common_processes"]
                if current_min is None:
                    summary["min_common_processes"] = common_processes
                else:
                    summary["min_common_processes"] = min(
                        int(current_min),
                        common_processes,
                    )

                summary["graph_created_total"] += graph_created
                summary["graph_exited_total"] += graph_exited
                summary["max_rss_bytes"] = max_rss
                summary["final_rss_bytes"] = rss_bytes

                cycle_row = {
                    "type": "cycle",
                    "cycle": cycle,
                    "timestamp_epoch": cycle_started_wall,
                    "elapsed_seconds": round(
                        time.monotonic() - started_mono,
                        6,
                    ),
                    "cycle_duration_seconds": round(
                        time.monotonic() - cycle_started_mono,
                        6,
                    ),
                    "verdict": verdict,
                    "runtime_status": runtime_status,
                    "mode": comparison.get("mode"),
                    "python_process_count": _safe_int(
                        comparison.get("python_process_count")
                    ),
                    "rust_process_count": _safe_int(
                        comparison.get("rust_process_count")
                    ),
                    "common_processes": common_processes,
                    "exact_graph_identity_matches": exact_matches,
                    "identity_disagreements": identity_count,
                    "parent_disagreements": parent_count,
                    "python_only": python_only,
                    "python_only_without_skip_reason": python_only_without_reason,
                    "rust_only": rust_only,
                    "rust_partial": bool(
                        comparison.get("rust_partial")
                    ),
                    "rust_skipped": _safe_int(
                        comparison.get("rust_skipped")
                    ),
                    "graph_processes_valid": _safe_int(
                        result.get("processes_valid")
                    ),
                    "graph_nodes": _safe_int(
                        result.get("node_count")
                    ),
                    "graph_created": graph_created,
                    "graph_updated": len(
                        result.get("updated", [])
                    ),
                    "graph_exited": graph_exited,
                    "process_rss_bytes": rss_bytes,
                    "component_failures": _counter(
                        runtime, "component_failures"
                    ),
                    "process_graph_failures": _counter(
                        runtime, "process_graph_failures"
                    ),
                    "process_sensor_failures": _counter(
                        runtime, "process_sensor_failures"
                    ),
                    "rust_process_shadow_failures": _counter(
                        runtime, "rust_process_shadow_failures"
                    ),
                }
                log_fh.write(
                    json.dumps(cycle_row, sort_keys=True)
                    + "\n"
                )

                now_mono = time.monotonic()
                if now_mono >= next_heartbeat:
                    print(
                        "[HEARTBEAT] "
                        f"cycle={cycle} "
                        f"elapsed={cycle_row['elapsed_seconds']:.1f}s "
                        f"verdict={verdict} "
                        f"common={common_processes} "
                        f"py_only={python_only} "
                        f"rust_only={rust_only} "
                        f"rss_mb={rss_bytes / (1024 * 1024):.1f}"
                    )
                    next_heartbeat = (
                        now_mono + args.heartbeat_seconds
                    )

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(
                    min(args.interval_seconds, remaining)
                )

            sensor_stats_end = authoritative_sensor.get_stats()
            probe_stats_end = shadow_probe.get_stats()

            _check(
                _safe_int(
                    sensor_stats_end.get("collect_count"), -1
                )
                == sensor_collect_start + cycle,
                "Python ProcessSensor collect count does not equal soak cycles",
            )
            _check(
                ingest_count == cycle,
                "ProcessGraph ingest count does not equal soak cycles",
            )
            _check(
                _safe_int(
                    probe_stats_end.get("probe_count"), -1
                )
                == probe_count_start + cycle,
                "Rust shadow probe count does not equal soak cycles",
            )

            summary["status"] = "PASS"
            summary["finished_at_epoch"] = time.time()
            summary["elapsed_seconds"] = round(
                time.monotonic() - started_mono,
                6,
            )
            summary["final_rss_bytes"] = int(
                process.memory_info().rss
            )
            summary["max_rss_bytes"] = max_rss
            summary["rss_delta_bytes"] = (
                int(summary["final_rss_bytes"])
                - int(summary["initial_rss_bytes"])
            )

            log_fh.write(
                json.dumps(
                    {
                        "type": "summary",
                        **summary,
                    },
                    sort_keys=True,
                )
                + "\n"
            )

            print()
            print("RUST SHADOW SOAK SUMMARY")
            print(json.dumps(summary, indent=2, sort_keys=True))
            print()
            print("RUST PROCESS SHADOW SOAK v1: PASS")
            return 0

        except KeyboardInterrupt:
            summary["status"] = "INTERRUPTED"
            summary["finished_at_epoch"] = time.time()
            summary["elapsed_seconds"] = round(
                time.monotonic() - started_mono,
                6,
            )
            if log_fh is not None:
                log_fh.write(
                    json.dumps(
                        {
                            "type": "summary",
                            **summary,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            print()
            print("RUST PROCESS SHADOW SOAK v1: INTERRUPTED (NOT PASS)")
            return 130

        except Exception as exc:
            summary["status"] = "FAIL"
            summary["failure_type"] = type(exc).__name__
            summary["failure_message"] = str(exc)
            summary["finished_at_epoch"] = time.time()
            summary["elapsed_seconds"] = round(
                time.monotonic() - started_mono,
                6,
            )
            if log_fh is not None:
                log_fh.write(
                    json.dumps(
                        {
                            "type": "summary",
                            **summary,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            print()
            print(
                "RUST PROCESS SHADOW SOAK v1: FAIL "
                f"({type(exc).__name__}: {exc})"
            )
            return 1

        finally:
            if log_fh is not None:
                log_fh.flush()
                log_fh.close()
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
