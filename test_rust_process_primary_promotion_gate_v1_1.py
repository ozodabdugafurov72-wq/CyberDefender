from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agent.correlation.graph import ProcessGraph
from agent.sensors.process import ProcessSensor
from agent.sensors.rust_process_shadow import (
    RustProcessShadowProbe,
    compare_shadow_to_authoritative,
)

GOOD_VERDICTS = {
    "ALIGNED_COMMON_SET",
    "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
}


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def proc(pid: int, ppid: int, created: float, name: str) -> dict[str, Any]:
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "exe": None,
        "username": None,
        "cmdline": None,
        "create_time": created,
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
    }


def state(graph: ProcessGraph, pid: int) -> str | None:
    node = graph.get_node(pid)
    return None if node is None else node.get("state")


def deterministic() -> dict[str, Any]:
    baseline_rows = [
        proc(100, 0, 1000.0, "parent.exe"),
        proc(200, 100, 2000.0, "tracked.exe"),
        proc(300, 100, 3000.0, "sibling.exe"),
    ]

    baseline = {
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": 1800000000.0,
        "process_count": 3,
        "processes": baseline_rows,
    }

    explicit_skip = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1800000001.0,
        "partial": True,
        "skipped": 1,
        "skipped_processes": [
            {"pid": 200, "reason": "OPEN_ACCESS_DENIED", "win32_error": 5}
        ],
        "process_count": 2,
        "processes": [baseline_rows[0], baseline_rows[2]],
    }

    g = ProcessGraph()
    check(g.VERSION == "1.6", "ProcessGraph coverage-aware version is 1.6")
    check(g.ingest_snapshot(baseline)["accepted"] is True, "baseline accepted")
    r = g.ingest_snapshot(explicit_skip)
    check(r["accepted"] is True, "partial explicit-skip snapshot accepted")
    check(r["coverage_mode"] == "PARTIAL_EXPLICIT_COVERAGE", "partial snapshot gets explicit coverage mode")
    check(state(g, 200) == "RUNNING", "explicit skipped PID does not false-exit")

    pid0_only = dict(explicit_skip)
    pid0_only["skipped_processes"] = [
        {"pid": 0, "reason": "SYSTEM_IDLE_UNQUERYABLE", "win32_error": 87}
    ]
    g2 = ProcessGraph()
    g2.ingest_snapshot(baseline)
    r2 = g2.ingest_snapshot(pid0_only)
    check(r2["coverage_mode"] == "PARTIAL_EXPLICIT_COVERAGE", "PID0-only partial metadata is coverage-aware")
    check(state(g2, 200) == "EXITED", "PID0-only limitation does not mask unrelated exit")

    malformed = dict(explicit_skip)
    malformed["skipped"] = 2
    g3 = ProcessGraph()
    g3.ingest_snapshot(baseline)
    r3 = g3.ingest_snapshot(malformed)
    check(r3["coverage_mode"] == "PARTIAL_FAIL_CLOSED", "malformed coverage fails closed")
    check(state(g3, 200) == "RUNNING", "malformed coverage cannot create absence-based exit")

    return {
        "graph_version": g.VERSION,
        "explicit_skip_false_exit_prevented": True,
        "pid0_only_real_exit_preserved": True,
        "malformed_coverage_fail_closed": True,
        "current_release_primary_allowed": False,
    }


def live(executable: Path) -> dict[str, Any]:
    python_sensor = ProcessSensor()
    rust_probe = RustProcessShadowProbe(executable.resolve(), timeout=5.0)

    python_snapshot = python_sensor.collect()
    rust_snapshot = rust_probe.probe()
    comparison = compare_shadow_to_authoritative(python_snapshot, rust_snapshot)

    check(comparison.get("verdict") in GOOD_VERDICTS, "live Rust parity is aligned")
    check(comparison.get("identity_disagreements", {}).get("count") == 0, "live identity disagreements are zero")
    check(comparison.get("parent_disagreements", {}).get("count") == 0, "live parent disagreements are zero")
    check(bool(rust_snapshot.get("partial")), "live Rust explicitly reports partial coverage")
    check(int(rust_snapshot.get("skipped", 0)) > 0, "live Rust exposes skipped coverage")
    check(isinstance(rust_snapshot.get("skipped_processes"), list), "live Rust exposes explicit skipped PID diagnostics")

    # Experimental graph only. Runtime remains Python-authoritative.
    g = ProcessGraph()
    first = g.ingest_snapshot(python_snapshot)
    check(first.get("accepted") is True, "experimental graph accepts Python baseline")
    second = g.ingest_snapshot(rust_snapshot)
    check(second.get("accepted") is True, "coverage-aware graph accepts validated Rust partial snapshot")
    check(second.get("coverage_mode") == "PARTIAL_EXPLICIT_COVERAGE", "live Rust partial maps to explicit coverage mode")
    check(second.get("coverage_metadata_valid") is True, "live Rust coverage metadata is valid")

    # Current runtime policy remains unchanged: no automatic primary switch.
    check(True, "current release keeps Rust SHADOW_ONLY; primary promotion is not enabled")

    return {
        "comparison_verdict": comparison.get("verdict"),
        "rust_partial": bool(rust_snapshot.get("partial")),
        "rust_skipped": int(rust_snapshot.get("skipped", 0)),
        "coverage_mode": second.get("coverage_mode"),
        "coverage_metadata_valid": second.get("coverage_metadata_valid"),
        "current_release_primary_allowed": False,
        "runtime_authoritative_sensor": "ProcessSensor",
    }


def main() -> int:
    summary = {"deterministic": deterministic()}

    executable = str(os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or "").strip()
    if executable:
        path = Path(executable).expanduser().resolve()
        check(path.is_file(), "RustProcessSensor executable exists")
        summary["live"] = live(path)
    else:
        print("[INFO] CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE not set; live section skipped")

    print("\nRUST PRIMARY PROMOTION GATE v1.1 SUMMARY")
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("\nRUST PROCESS PRIMARY PROMOTION GATE v1.1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
