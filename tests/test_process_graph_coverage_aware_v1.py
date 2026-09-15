from __future__ import annotations

from agent.correlation.graph import ProcessGraph


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def proc(pid: int, ppid: int, created: float, name: str) -> dict:
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


def snap(rows: list[dict], **extra) -> dict:
    base = {
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": 1800000000.0,
        "process_count": len(rows),
        "processes": rows,
    }
    base.update(extra)
    return base


def node(graph: ProcessGraph, pid: int):
    return graph.get_node(pid)


def edge_exists(graph: ProcessGraph, parent_pid: int, child_pid: int) -> bool:
    parent = graph.get_node(parent_pid)
    child = graph.get_node(child_pid)
    if not parent or not child:
        return False
    return (parent["identity"], child["identity"]) in graph.edges


baseline_rows = [
    proc(100, 0, 1000.0, "parent.exe"),
    proc(200, 100, 2000.0, "tracked.exe"),
    proc(300, 100, 3000.0, "sibling.exe"),
]

# 1. Backward-compatible complete semantics.
g = ProcessGraph()
r = g.ingest_snapshot(snap(baseline_rows))
check(r["accepted"] is True, "complete baseline accepted")
check(r["coverage_mode"] == "COMPLETE", "legacy snapshot defaults to COMPLETE")
check(edge_exists(g, 100, 200), "baseline parent->tracked edge exists")
r = g.ingest_snapshot(snap([baseline_rows[0], baseline_rows[2]]))
check(r["coverage_mode"] == "COMPLETE", "second legacy snapshot remains COMPLETE")
check(node(g, 200)["state"] == "EXITED", "complete missing PID exits immediately")
check(not edge_exists(g, 100, 200), "complete exit removes edge")

# 2. Valid partial explicit skip protects exactly that PID.
g = ProcessGraph()
g.ingest_snapshot(snap(baseline_rows))
partial = snap(
    [baseline_rows[0], baseline_rows[2]],
    sensor="RustProcessSensor",
    version="0.4.0",
    partial=True,
    skipped=1,
    skipped_processes=[
        {"pid": 200, "reason": "OPEN_ACCESS_DENIED", "win32_error": 5}
    ],
)
r = g.ingest_snapshot(partial)
check(r["accepted"] is True, "valid partial snapshot accepted")
check(r["coverage_mode"] == "PARTIAL_EXPLICIT_COVERAGE", "valid partial uses explicit coverage")
check(r["coverage_metadata_valid"] is True, "valid partial metadata recognized")
check(node(g, 200)["state"] == "RUNNING", "explicitly skipped PID remains RUNNING")
check(edge_exists(g, 100, 200), "suppressed PID keeps graph edge")
check(any("pid:200@" in x for x in r["exit_suppressed"]), "suppression is observable")

# 3. PID0-only known limitation must not mask unrelated real exit.
g = ProcessGraph()
g.ingest_snapshot(snap(baseline_rows))
pid0_partial = snap(
    [baseline_rows[0], baseline_rows[2]],
    sensor="RustProcessSensor",
    version="0.4.0",
    partial=True,
    skipped=1,
    skipped_processes=[
        {"pid": 0, "reason": "SYSTEM_IDLE_UNQUERYABLE", "win32_error": 87}
    ],
)
r = g.ingest_snapshot(pid0_partial)
check(r["coverage_mode"] == "PARTIAL_EXPLICIT_COVERAGE", "PID0 partial uses explicit coverage")
check(node(g, 200)["state"] == "EXITED", "unrelated real exit still detected under PID0 limitation")

# 4. Count mismatch fails closed for absence-based exits.
g = ProcessGraph()
g.ingest_snapshot(snap(baseline_rows))
bad = snap(
    [baseline_rows[0], baseline_rows[2]],
    sensor="RustProcessSensor",
    version="0.4.0",
    partial=True,
    skipped=2,
    skipped_processes=[
        {"pid": 200, "reason": "OPEN_FAILED", "win32_error": 87}
    ],
)
r = g.ingest_snapshot(bad)
check(r["coverage_mode"] == "PARTIAL_FAIL_CLOSED", "count mismatch fails closed")
check(r["coverage_reason"] == "SKIPPED_COUNT_MISMATCH", "count mismatch reason explicit")
check(r["coverage_metadata_valid"] is False, "bad coverage metadata marked invalid")
check(node(g, 200)["state"] == "RUNNING", "fail-closed invalid metadata preserves RUNNING")
check(edge_exists(g, 100, 200), "fail-closed invalid metadata preserves edge")

# 5. observed+skipped overlap fails closed; positive observation remains usable.
g = ProcessGraph()
g.ingest_snapshot(snap(baseline_rows))
overlap = snap(
    baseline_rows,
    sensor="RustProcessSensor",
    version="0.4.0",
    partial=True,
    skipped=1,
    skipped_processes=[
        {"pid": 200, "reason": "OPEN_FAILED", "win32_error": 87}
    ],
)
r = g.ingest_snapshot(overlap)
check(r["coverage_mode"] == "PARTIAL_FAIL_CLOSED", "observed+skipped overlap fails closed")
check(r["coverage_reason"] == "SKIPPED_PID_ALSO_OBSERVED", "overlap reason explicit")
check(node(g, 200)["state"] == "RUNNING", "positive observed PID remains RUNNING")

# 6. Partial without explicit diagnostics fails closed.
g = ProcessGraph()
g.ingest_snapshot(snap(baseline_rows))
no_diag = snap(
    [baseline_rows[0], baseline_rows[2]],
    sensor="RustProcessSensor",
    version="0.4.0",
    partial=True,
    skipped=1,
)
r = g.ingest_snapshot(no_diag)
check(r["coverage_mode"] == "PARTIAL_FAIL_CLOSED", "partial without diagnostics fails closed")
check(node(g, 200)["state"] == "RUNNING", "missing PID preserved when diagnostics absent")

# 7. Complete snapshot cannot claim skipped processes.
g = ProcessGraph()
g.ingest_snapshot(snap(baseline_rows))
invalid_complete = snap(
    [baseline_rows[0], baseline_rows[2]],
    partial=False,
    skipped=1,
    skipped_processes=[{"pid": 200, "reason": "OPEN_FAILED"}],
)
r = g.ingest_snapshot(invalid_complete)
check(r["coverage_mode"] == "PARTIAL_FAIL_CLOSED", "complete+skipped contradiction fails closed")
check(r["coverage_reason"] == "COMPLETE_WITH_NONZERO_SKIPPED", "complete contradiction reason explicit")
check(node(g, 200)["state"] == "RUNNING", "contradictory complete metadata cannot cause exit")

# 8. PID reuse remains positive evidence under partial coverage.
g = ProcessGraph()
g.ingest_snapshot(snap(baseline_rows))
reuse_rows = [
    baseline_rows[0],
    proc(200, 100, 2222.0, "tracked-new.exe"),
    baseline_rows[2],
]
reuse_partial = snap(
    reuse_rows,
    sensor="RustProcessSensor",
    version="0.4.0",
    partial=True,
    skipped=1,
    skipped_processes=[
        {"pid": 0, "reason": "SYSTEM_IDLE_UNQUERYABLE", "win32_error": 87}
    ],
)
r = g.ingest_snapshot(reuse_partial)
check(len(r["pid_reuse"]) == 1, "PID reuse still detected under partial coverage")
check(g.pid_reuse_detected == 1, "PID reuse metric increments")
check(node(g, 200)["create_time"] == 2222.0, "PID index points to new identity")
check(node(g, 200)["state"] == "RUNNING", "new PID identity remains RUNNING")

# 9. Health/API remain compatible.
check(g.VERSION == "1.6", "ProcessGraph version bumped to 1.6")
check(g.health_check()["status"] == "HEALTHY", "ProcessGraph health remains HEALTHY")
stats = g.get_stats()
check(stats["graph"] == "ProcessGraph", "ProcessGraph stats API remains available")

print("\nPROCESSGRAPH COVERAGE-AWARE PRODUCTION v1: PASS")
