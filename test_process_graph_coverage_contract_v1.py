from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from agent.correlation.graph import ProcessGraph


ALLOWED_SKIP_REASONS = {
    "OPEN_ACCESS_DENIED",
    "OPEN_FAILED",
    "TIMES_FAILED",
    "SYSTEM_IDLE_UNQUERYABLE",
    "INVALID_CREATION_TIME",
    "CREATED_AFTER_SNAPSHOT_START",
    "INVALID_NAME",
}


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def process(
    pid: int,
    ppid: int,
    create_time: float,
    name: str,
) -> dict[str, Any]:
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "exe": None,
        "username": None,
        "cmdline": None,
        "create_time": create_time,
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
    }


def node_for_pid(
    graph: ProcessGraph,
    pid: int,
) -> tuple[str | None, dict[str, Any] | None]:
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


def edge_has_pid(
    graph: ProcessGraph,
    parent_pid: int,
    child_pid: int,
) -> bool:
    parent_identity, _ = node_for_pid(graph, parent_pid)
    child_identity, _ = node_for_pid(graph, child_pid)

    if parent_identity is None or child_identity is None:
        return False

    edges = getattr(graph, "edges", set())
    return (parent_identity, child_identity) in edges


@dataclass(frozen=True)
class CoverageDecision:
    coverage_mode: str
    metadata_valid: bool
    explicit_skipped_pids: frozenset[int]
    exit_candidates: frozenset[str]
    suppressed_missing: frozenset[str]
    reason: str


def _parse_skip_entries(
    snapshot: dict[str, Any],
) -> tuple[bool, set[int], str]:
    """
    Prototype wire normalization for the future ProcessGraph boundary.

    The production Rust validator already guarantees its own exact v0.4 wire.
    This contract layer deliberately accepts either:
      - skipped_processes: [{pid, reason, ...}]
      - skipped_examples:  [{pid, reason, ...}]
    so this test remains focused on lifecycle semantics, not wire naming.

    Before production integration, the exact validated field name must be
    wired directly from rust_process_shadow.py with no alias ambiguity.
    """

    raw_entries = snapshot.get("skipped_processes")
    if raw_entries is None:
        raw_entries = snapshot.get("skipped_examples")

    if raw_entries is None:
        raw_entries = []

    if not isinstance(raw_entries, list):
        return False, set(), "SKIP_LIST_NOT_LIST"

    seen: set[int] = set()

    for entry in raw_entries:
        if not isinstance(entry, dict):
            return False, set(), "SKIP_ENTRY_NOT_OBJECT"

        try:
            pid = int(entry.get("pid"))
        except (TypeError, ValueError):
            return False, set(), "SKIP_PID_INVALID"

        reason = entry.get("reason")
        if reason not in ALLOWED_SKIP_REASONS:
            return False, set(), "SKIP_REASON_INVALID"

        if pid < 0:
            return False, set(), "SKIP_PID_NEGATIVE"

        if pid in seen:
            return False, set(), "SKIP_PID_DUPLICATE"

        seen.add(pid)

    try:
        declared_skipped = int(snapshot.get("skipped", 0))
    except (TypeError, ValueError):
        return False, set(), "SKIPPED_COUNT_INVALID"

    if declared_skipped != len(seen):
        return False, set(), "SKIPPED_COUNT_MISMATCH"

    observed_pids: set[int] = set()
    raw_processes = snapshot.get("processes", [])

    if not isinstance(raw_processes, list):
        return False, set(), "PROCESSES_NOT_LIST"

    for row in raw_processes:
        if not isinstance(row, dict):
            continue
        try:
            observed_pids.add(int(row.get("pid")))
        except (TypeError, ValueError):
            continue

    if seen & observed_pids:
        return False, set(), "SKIPPED_PID_ALSO_OBSERVED"

    return True, seen, "OK"


def decide_missing_lifecycle(
    *,
    snapshot: dict[str, Any],
    known_running: dict[str, int],
    current_identities: set[str],
) -> CoverageDecision:
    """
    Candidate contract for ProcessGraph negative inference.

    Rules:
      1. Complete snapshot (partial false/absent, skipped=0):
         preserve current behavior: every missing RUNNING identity may EXIT.

      2. Partial snapshot with valid explicit skip metadata:
         - missing identity whose PID is explicitly skipped => SUPPRESS EXIT
         - other missing identities => EXIT candidate
         This allows PID 0 / access-denied coverage limits without globally
         disabling real exit detection.

      3. Partial snapshot with invalid/ambiguous skip metadata:
         fail closed for negative inference:
         - no missing identity may be marked EXITED from absence alone.
         - observed positive evidence can still update/create nodes elsewhere.

    This function does not mutate ProcessGraph.
    """

    missing = {
        identity
        for identity in known_running
        if identity not in current_identities
    }

    partial = bool(snapshot.get("partial", False))

    try:
        declared_skipped = int(snapshot.get("skipped", 0))
    except (TypeError, ValueError):
        declared_skipped = -1

    if not partial:
        if declared_skipped != 0:
            return CoverageDecision(
                coverage_mode="INVALID_COMPLETE_METADATA",
                metadata_valid=False,
                explicit_skipped_pids=frozenset(),
                exit_candidates=frozenset(),
                suppressed_missing=frozenset(missing),
                reason="COMPLETE_WITH_NONZERO_SKIPPED",
            )

        return CoverageDecision(
            coverage_mode="COMPLETE",
            metadata_valid=True,
            explicit_skipped_pids=frozenset(),
            exit_candidates=frozenset(missing),
            suppressed_missing=frozenset(),
            reason="COMPLETE_NEGATIVE_INFERENCE_ALLOWED",
        )

    valid, skipped_pids, parse_reason = _parse_skip_entries(
        snapshot
    )

    if not valid:
        return CoverageDecision(
            coverage_mode="PARTIAL_FAIL_CLOSED",
            metadata_valid=False,
            explicit_skipped_pids=frozenset(),
            exit_candidates=frozenset(),
            suppressed_missing=frozenset(missing),
            reason=parse_reason,
        )

    suppressed = {
        identity
        for identity in missing
        if known_running.get(identity) in skipped_pids
    }

    exit_candidates = missing - suppressed

    return CoverageDecision(
        coverage_mode="PARTIAL_EXPLICIT_COVERAGE",
        metadata_valid=True,
        explicit_skipped_pids=frozenset(skipped_pids),
        exit_candidates=frozenset(exit_candidates),
        suppressed_missing=frozenset(suppressed),
        reason="PARTIAL_SKIP_SCOPE_APPLIED",
    )


def apply_exit_decision_to_graph(
    graph: ProcessGraph,
    decision: CoverageDecision,
) -> list[str]:
    """
    Test-only prototype mutation.

    This intentionally mirrors only the current EXIT transition portion.
    It does NOT replace agent/correlation/graph.py.
    """
    exited: list[str] = []

    for identity in decision.exit_candidates:
        node = graph.nodes.get(identity)
        if node is None:
            continue
        if node.get("state") != "RUNNING":
            continue

        node["state"] = "EXITED"
        exited.append(identity)

        remove_edges = getattr(
            graph,
            "_remove_edges_for_identity",
            None,
        )
        if callable(remove_edges):
            remove_edges(identity)

    return exited


def baseline_snapshot() -> dict[str, Any]:
    return {
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": 1_800_000_000.0,
        "process_count": 3,
        "processes": [
            process(100, 0, 1000.0, "parent.exe"),
            process(200, 100, 2000.0, "tracked.exe"),
            process(300, 100, 3000.0, "sibling.exe"),
        ],
    }


def known_running_map(
    graph: ProcessGraph,
) -> dict[str, int]:
    result: dict[str, int] = {}
    for identity, node in graph.nodes.items():
        if not isinstance(node, dict):
            continue
        if node.get("state") != "RUNNING":
            continue
        try:
            result[str(identity)] = int(node.get("pid"))
        except (TypeError, ValueError):
            continue
    return result


def identities_for_snapshot_processes(
    graph: ProcessGraph,
    rows: list[dict[str, Any]],
) -> set[str]:
    identities: set[str] = set()

    normalize = getattr(graph, "_normalize_process", None)
    if not callable(normalize):
        raise AssertionError(
            "ProcessGraph._normalize_process unavailable"
        )

    for row in rows:
        normalized = normalize(row)
        if isinstance(normalized, dict):
            identity = normalized.get("identity")
            if isinstance(identity, str):
                identities.add(identity)

    return identities


def test_current_risk_control() -> None:
    graph = ProcessGraph()
    first = graph.ingest_snapshot(baseline_snapshot())

    check(
        first.get("accepted") is True,
        "CONTROL: current graph accepts complete baseline",
    )
    check(
        edge_has_pid(graph, 100, 200),
        "CONTROL: parent->tracked edge exists initially",
    )

    # Partial snapshot omits tracked PID 200 but says it was explicitly
    # skipped. Current ProcessGraph ignores coverage metadata.
    partial = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_001.0,
        "partial": True,
        "skipped": 1,
        "skipped_processes": [
            {
                "pid": 200,
                "reason": "OPEN_ACCESS_DENIED",
                "win32_error": 5,
            }
        ],
        "process_count": 2,
        "processes": [
            process(100, 0, 1000.0, "parent.exe"),
            process(300, 100, 3000.0, "sibling.exe"),
        ],
    }

    second = graph.ingest_snapshot(partial)
    check(
        second.get("accepted") is True,
        "CONTROL: current graph accepts partial-shaped snapshot",
    )

    _, tracked = node_for_pid(graph, 200)
    check(
        isinstance(tracked, dict)
        and tracked.get("state") == "EXITED",
        "CONTROL: current graph demonstrates false EXITED on explicit skipped PID",
    )
    check(
        not edge_has_pid(graph, 100, 200),
        "CONTROL: false EXITED also removes active edge",
    )


def test_candidate_contract() -> dict[str, Any]:
    summary: dict[str, Any] = {
        "schema": "cd.processgraph.coverage-contract.v1",
        "policy": (
            "complete=immediate-exit; "
            "partial-valid=protect-explicit-skips; "
            "partial-invalid=fail-closed-negative-inference"
        ),
        "cases": [],
    }

    # ------------------------------------------------------------
    # Case 1: complete snapshot preserves current semantics.
    # ------------------------------------------------------------
    graph1 = ProcessGraph()
    graph1.ingest_snapshot(baseline_snapshot())

    complete_rows = [
        process(100, 0, 1000.0, "parent.exe"),
        process(300, 100, 3000.0, "sibling.exe"),
    ]
    complete_snapshot = {
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": 1_800_000_001.0,
        "process_count": 2,
        "partial": False,
        "skipped": 0,
        "processes": complete_rows,
    }

    decision1 = decide_missing_lifecycle(
        snapshot=complete_snapshot,
        known_running=known_running_map(graph1),
        current_identities=identities_for_snapshot_processes(
            graph1,
            complete_rows,
        ),
    )

    check(
        decision1.coverage_mode == "COMPLETE",
        "CASE1: complete snapshot uses COMPLETE coverage mode",
    )
    check(
        len(decision1.exit_candidates) == 1,
        "CASE1: complete missing process remains immediate exit candidate",
    )

    apply_exit_decision_to_graph(graph1, decision1)
    _, tracked1 = node_for_pid(graph1, 200)

    check(
        isinstance(tracked1, dict)
        and tracked1.get("state") == "EXITED",
        "CASE1: complete snapshot preserves existing immediate EXITED semantics",
    )

    summary["cases"].append({
        "case": "complete_snapshot",
        "mode": decision1.coverage_mode,
        "exit_candidates": len(decision1.exit_candidates),
        "suppressed": len(decision1.suppressed_missing),
    })

    # ------------------------------------------------------------
    # Case 2: explicit skipped PID is protected.
    # ------------------------------------------------------------
    graph2 = ProcessGraph()
    graph2.ingest_snapshot(baseline_snapshot())

    partial_rows = [
        process(100, 0, 1000.0, "parent.exe"),
        process(300, 100, 3000.0, "sibling.exe"),
    ]
    partial_skipped = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_001.0,
        "partial": True,
        "skipped": 1,
        "skipped_processes": [
            {
                "pid": 200,
                "reason": "OPEN_ACCESS_DENIED",
                "win32_error": 5,
            }
        ],
        "process_count": 2,
        "processes": partial_rows,
    }

    decision2 = decide_missing_lifecycle(
        snapshot=partial_skipped,
        known_running=known_running_map(graph2),
        current_identities=identities_for_snapshot_processes(
            graph2,
            partial_rows,
        ),
    )

    tracked_identity2, _ = node_for_pid(graph2, 200)

    check(
        decision2.coverage_mode
        == "PARTIAL_EXPLICIT_COVERAGE",
        "CASE2: valid partial snapshot uses explicit coverage mode",
    )
    check(
        tracked_identity2 in decision2.suppressed_missing,
        "CASE2: explicitly skipped tracked PID is suppressed from exit",
    )
    check(
        tracked_identity2 not in decision2.exit_candidates,
        "CASE2: explicitly skipped tracked PID is not an exit candidate",
    )

    apply_exit_decision_to_graph(graph2, decision2)
    _, tracked2 = node_for_pid(graph2, 200)

    check(
        isinstance(tracked2, dict)
        and tracked2.get("state") == "RUNNING",
        "CASE2: explicitly skipped tracked PID remains RUNNING",
    )
    check(
        edge_has_pid(graph2, 100, 200),
        "CASE2: suppressed missing PID keeps its graph edge",
    )

    summary["cases"].append({
        "case": "partial_explicit_skip",
        "mode": decision2.coverage_mode,
        "exit_candidates": len(decision2.exit_candidates),
        "suppressed": len(decision2.suppressed_missing),
    })

    # ------------------------------------------------------------
    # Case 3: partial due PID0 does not disable unrelated real exits.
    # ------------------------------------------------------------
    graph3 = ProcessGraph()
    graph3.ingest_snapshot(baseline_snapshot())

    pid0_partial_rows = [
        process(100, 0, 1000.0, "parent.exe"),
        # tracked PID 200 is genuinely absent / exited
        process(300, 100, 3000.0, "sibling.exe"),
    ]
    pid0_partial = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_001.0,
        "partial": True,
        "skipped": 1,
        "skipped_processes": [
            {
                "pid": 0,
                "reason": "SYSTEM_IDLE_UNQUERYABLE",
                "win32_error": 87,
            }
        ],
        "process_count": 2,
        "processes": pid0_partial_rows,
    }

    decision3 = decide_missing_lifecycle(
        snapshot=pid0_partial,
        known_running=known_running_map(graph3),
        current_identities=identities_for_snapshot_processes(
            graph3,
            pid0_partial_rows,
        ),
    )

    tracked_identity3, _ = node_for_pid(graph3, 200)

    check(
        tracked_identity3 in decision3.exit_candidates,
        "CASE3: unrelated missing tracked PID remains exit candidate despite PID0 coverage limit",
    )
    check(
        tracked_identity3 not in decision3.suppressed_missing,
        "CASE3: PID0 skip does not protect unrelated tracked PID",
    )

    apply_exit_decision_to_graph(graph3, decision3)
    _, tracked3 = node_for_pid(graph3, 200)

    check(
        isinstance(tracked3, dict)
        and tracked3.get("state") == "EXITED",
        "CASE3: real exit remains detectable under PID0-only partial coverage",
    )

    summary["cases"].append({
        "case": "pid0_only_partial",
        "mode": decision3.coverage_mode,
        "exit_candidates": len(decision3.exit_candidates),
        "suppressed": len(decision3.suppressed_missing),
    })

    # ------------------------------------------------------------
    # Case 4: malformed partial metadata => fail closed.
    # ------------------------------------------------------------
    graph4 = ProcessGraph()
    graph4.ingest_snapshot(baseline_snapshot())

    malformed_partial = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_001.0,
        "partial": True,
        "skipped": 2,  # declared count does not match one entry
        "skipped_processes": [
            {
                "pid": 200,
                "reason": "OPEN_FAILED",
                "win32_error": 87,
            }
        ],
        "process_count": 2,
        "processes": partial_rows,
    }

    decision4 = decide_missing_lifecycle(
        snapshot=malformed_partial,
        known_running=known_running_map(graph4),
        current_identities=identities_for_snapshot_processes(
            graph4,
            partial_rows,
        ),
    )

    check(
        decision4.coverage_mode == "PARTIAL_FAIL_CLOSED",
        "CASE4: malformed partial metadata enters fail-closed coverage mode",
    )
    check(
        len(decision4.exit_candidates) == 0,
        "CASE4: malformed partial metadata permits no absence-based exits",
    )
    check(
        len(decision4.suppressed_missing) == 1,
        "CASE4: all missing running identities are suppressed",
    )

    apply_exit_decision_to_graph(graph4, decision4)
    _, tracked4 = node_for_pid(graph4, 200)

    check(
        isinstance(tracked4, dict)
        and tracked4.get("state") == "RUNNING",
        "CASE4: fail-closed metadata preserves tracked RUNNING state",
    )
    check(
        edge_has_pid(graph4, 100, 200),
        "CASE4: fail-closed metadata preserves graph edge",
    )

    summary["cases"].append({
        "case": "malformed_partial",
        "mode": decision4.coverage_mode,
        "reason": decision4.reason,
        "exit_candidates": len(decision4.exit_candidates),
        "suppressed": len(decision4.suppressed_missing),
    })

    # ------------------------------------------------------------
    # Case 5: skipped PID reappears => no stale suppression concept.
    # ------------------------------------------------------------
    graph5 = ProcessGraph()
    graph5.ingest_snapshot(baseline_snapshot())

    decision5a = decide_missing_lifecycle(
        snapshot=partial_skipped,
        known_running=known_running_map(graph5),
        current_identities=identities_for_snapshot_processes(
            graph5,
            partial_rows,
        ),
    )
    apply_exit_decision_to_graph(graph5, decision5a)

    reappeared_rows = list(baseline_snapshot()["processes"])
    reappeared_snapshot = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_002.0,
        "partial": True,
        "skipped": 1,
        "skipped_processes": [
            {
                "pid": 0,
                "reason": "SYSTEM_IDLE_UNQUERYABLE",
                "win32_error": 87,
            }
        ],
        "process_count": 3,
        "processes": reappeared_rows,
    }

    # Feed the actual observed positive data through current graph; the
    # candidate coverage policy only governs absence-based exits.
    graph5.ingest_snapshot({
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": 1_800_000_002.0,
        "process_count": 3,
        "processes": reappeared_rows,
    })

    _, tracked5 = node_for_pid(graph5, 200)

    check(
        isinstance(tracked5, dict)
        and tracked5.get("state") == "RUNNING",
        "CASE5: reappearing tracked PID is RUNNING again",
    )

    decision5b = decide_missing_lifecycle(
        snapshot=reappeared_snapshot,
        known_running=known_running_map(graph5),
        current_identities=identities_for_snapshot_processes(
            graph5,
            reappeared_rows,
        ),
    )

    check(
        len(decision5b.suppressed_missing) == 0,
        "CASE5: reappeared PID has no stale suppression",
    )

    summary["cases"].append({
        "case": "reappearance",
        "mode": decision5b.coverage_mode,
        "exit_candidates": len(decision5b.exit_candidates),
        "suppressed": len(decision5b.suppressed_missing),
    })

    # ------------------------------------------------------------
    # Case 6: skipped PID cannot also be observed.
    # ------------------------------------------------------------
    graph6 = ProcessGraph()
    graph6.ingest_snapshot(baseline_snapshot())

    invalid_overlap = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_001.0,
        "partial": True,
        "skipped": 1,
        "skipped_processes": [
            {
                "pid": 200,
                "reason": "OPEN_FAILED",
                "win32_error": 87,
            }
        ],
        "process_count": 3,
        "processes": list(baseline_snapshot()["processes"]),
    }

    decision6 = decide_missing_lifecycle(
        snapshot=invalid_overlap,
        known_running=known_running_map(graph6),
        current_identities=identities_for_snapshot_processes(
            graph6,
            invalid_overlap["processes"],
        ),
    )

    check(
        decision6.coverage_mode == "PARTIAL_FAIL_CLOSED",
        "CASE6: observed+skipped PID conflict fails closed",
    )
    check(
        decision6.reason == "SKIPPED_PID_ALSO_OBSERVED",
        "CASE6: overlap failure reason is explicit",
    )

    summary["cases"].append({
        "case": "skip_observed_overlap",
        "mode": decision6.coverage_mode,
        "reason": decision6.reason,
    })

    return summary


def main() -> int:
    test_current_risk_control()
    summary = test_candidate_contract()

    print("\nPROCESSGRAPH COVERAGE CONTRACT SUMMARY")
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("\nPROCESSGRAPH COVERAGE CONTRACT v1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
