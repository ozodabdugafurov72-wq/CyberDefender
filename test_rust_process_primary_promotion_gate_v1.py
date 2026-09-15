from __future__ import annotations

import argparse
from dataclasses import dataclass
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


@dataclass(frozen=True)
class PromotionDecision:
    future_primary_eligible: bool
    current_release_primary_allowed: bool
    reasons: tuple[str, ...]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def evaluate_candidate(
    rust_snapshot: dict[str, Any],
    comparison: dict[str, Any],
) -> PromotionDecision:
    reasons: list[str] = []

    if comparison.get("verdict") not in GOOD_VERDICTS:
        reasons.append("PARITY_NOT_ALIGNED")

    if bool(rust_snapshot.get("partial")):
        reasons.append("PARTIAL_SNAPSHOT")

    try:
        skipped = int(rust_snapshot.get("skipped", 0))
    except (TypeError, ValueError):
        skipped = -1

    if skipped != 0:
        reasons.append("SKIPPED_PROCESSES")

    identity_disagreements = int(
        comparison.get("identity_disagreements", {}).get("count", -1)
    )
    parent_disagreements = int(
        comparison.get("parent_disagreements", {}).get("count", -1)
    )

    if identity_disagreements != 0:
        reasons.append("IDENTITY_DISAGREEMENT")

    if parent_disagreements != 0:
        reasons.append("PARENT_DISAGREEMENT")

    future_eligible = not reasons

    # P0.8.5.2 policy: Rust is shadow-only. Even a hypothetical complete
    # snapshot cannot become primary until a separately reviewed promotion
    # implementation exists.
    current_release_allowed = False

    if not current_release_allowed:
        reasons.append("PRIMARY_PROMOTION_NOT_IMPLEMENTED")

    return PromotionDecision(
        future_primary_eligible=future_eligible,
        current_release_primary_allowed=current_release_allowed,
        reasons=tuple(reasons),
    )


def select_authoritative_snapshot(
    python_snapshot: dict[str, Any] | None,
    rust_snapshot: dict[str, Any] | None,
    decision: PromotionDecision | None,
) -> tuple[str | None, dict[str, Any] | None, str]:
    if isinstance(python_snapshot, dict):
        return "ProcessSensor", python_snapshot, "PYTHON_AUTHORITATIVE"

    if (
        isinstance(rust_snapshot, dict)
        and isinstance(decision, PromotionDecision)
        and decision.current_release_primary_allowed
        and decision.future_primary_eligible
    ):
        return "RustProcessSensor", rust_snapshot, "RUST_PRIMARY"

    # Fail closed: a partial or otherwise ineligible Rust snapshot must
    # never be used as an authoritative full-snapshot replacement.
    return None, None, "NO_SAFE_AUTHORITATIVE_SNAPSHOT"


def graph_state_for_pid(
    graph: ProcessGraph,
    pid: int,
) -> str | None:
    nodes = getattr(graph, "nodes", {})
    if not isinstance(nodes, dict):
        return None

    for node in nodes.values():
        if not isinstance(node, dict):
            continue
        try:
            node_pid = int(node.get("pid"))
        except (TypeError, ValueError):
            continue
        if node_pid == pid:
            state = node.get("state")
            return str(state) if state is not None else None

    return None


def synthetic_process(
    pid: int,
    ppid: int,
    created: float,
    name: str,
) -> dict[str, Any]:
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


def deterministic_contract_test() -> dict[str, Any]:
    baseline = {
        "sensor": "ProcessSensor",
        "version": "1.0",
        "timestamp": 1_800_000_000.0,
        "process_count": 3,
        "processes": [
            synthetic_process(100, 0, 1000.0, "parent.exe"),
            synthetic_process(200, 100, 2000.0, "tracked.exe"),
            synthetic_process(300, 100, 3000.0, "sibling.exe"),
        ],
    }

    partial_rust_graph_shape = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_001.0,
        "partial": True,
        "skipped": 1,
        "process_count": 2,
        "processes": [
            synthetic_process(100, 0, 1000.0, "parent.exe"),
            synthetic_process(300, 100, 3000.0, "sibling.exe"),
        ],
    }

    comparison = {
        "verdict": "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
        "identity_disagreements": {"count": 0},
        "parent_disagreements": {"count": 0},
    }

    decision = evaluate_candidate(
        partial_rust_graph_shape,
        comparison,
    )

    check(
        not decision.future_primary_eligible,
        "Synthetic partial Rust snapshot is not future-primary eligible",
    )
    check(
        "PARTIAL_SNAPSHOT" in decision.reasons,
        "Promotion decision records PARTIAL_SNAPSHOT",
    )
    check(
        "SKIPPED_PROCESSES" in decision.reasons,
        "Promotion decision records SKIPPED_PROCESSES",
    )
    check(
        not decision.current_release_primary_allowed,
        "Current P0.8.5.2 release keeps Rust primary disabled",
    )

    # Unsafe control experiment: current ProcessGraph has full-snapshot
    # semantics and does not understand `partial=True`.
    unsafe_graph = ProcessGraph()
    first = unsafe_graph.ingest_snapshot(baseline)
    check(
        first.get("accepted") is True,
        "Unsafe-control graph accepts complete baseline",
    )
    check(
        graph_state_for_pid(unsafe_graph, 200) == "RUNNING",
        "Unsafe-control tracked PID starts RUNNING",
    )

    unsafe_second = unsafe_graph.ingest_snapshot(
        partial_rust_graph_shape
    )
    check(
        unsafe_second.get("accepted") is True,
        "Current ProcessGraph accepts partial-shaped snapshot without coverage semantics",
    )
    check(
        graph_state_for_pid(unsafe_graph, 200) == "EXITED",
        "Direct partial snapshot demonstrates false EXITED risk",
    )

    # Safe path: Python is authoritative, so partial Rust is diagnostics only.
    safe_graph = ProcessGraph()
    safe_first = safe_graph.ingest_snapshot(baseline)
    check(
        safe_first.get("accepted") is True,
        "Safe graph accepts authoritative Python baseline",
    )

    source, selected, disposition = select_authoritative_snapshot(
        baseline,
        partial_rust_graph_shape,
        decision,
    )
    check(
        source == "ProcessSensor",
        "Python remains selected when partial Rust is available",
    )
    check(
        disposition == "PYTHON_AUTHORITATIVE",
        "Selection disposition is PYTHON_AUTHORITATIVE",
    )
    check(
        selected is baseline,
        "Selected snapshot is the authoritative Python object",
    )

    safe_second = safe_graph.ingest_snapshot(selected)
    check(
        safe_second.get("accepted") is True,
        "Safe graph accepts selected Python snapshot",
    )
    check(
        graph_state_for_pid(safe_graph, 200) == "RUNNING",
        "Partial Rust evidence cannot create false EXITED in safe path",
    )

    # Fail-closed fallback: if Python is absent, do not silently promote
    # partial Rust and do not mutate ProcessGraph lifecycle state.
    preserved_graph = ProcessGraph()
    preserved_first = preserved_graph.ingest_snapshot(baseline)
    check(
        preserved_first.get("accepted") is True,
        "Fail-closed graph accepts initial trusted baseline",
    )

    source2, selected2, disposition2 = select_authoritative_snapshot(
        None,
        partial_rust_graph_shape,
        decision,
    )
    check(
        source2 is None and selected2 is None,
        "Python unavailable + partial Rust yields no authoritative snapshot",
    )
    check(
        disposition2 == "NO_SAFE_AUTHORITATIVE_SNAPSHOT",
        "Fallback disposition is explicitly fail-closed",
    )
    check(
        graph_state_for_pid(preserved_graph, 200) == "RUNNING",
        "Fail-closed path preserves prior graph lifecycle state",
    )

    # A hypothetical complete/aligned Rust snapshot is still not primary in
    # current release. This prevents accidental policy drift.
    hypothetical_complete = dict(partial_rust_graph_shape)
    hypothetical_complete["partial"] = False
    hypothetical_complete["skipped"] = 0
    hypothetical_complete["process_count"] = 3
    hypothetical_complete["processes"] = list(baseline["processes"])

    complete_comparison = {
        "verdict": "ALIGNED_COMMON_SET",
        "identity_disagreements": {"count": 0},
        "parent_disagreements": {"count": 0},
    }
    complete_decision = evaluate_candidate(
        hypothetical_complete,
        complete_comparison,
    )

    check(
        complete_decision.future_primary_eligible,
        "Hypothetical complete/aligned Rust sample clears future-eligibility checks",
    )
    check(
        not complete_decision.current_release_primary_allowed,
        "Hypothetical complete Rust still cannot bypass current SHADOW_ONLY policy",
    )
    check(
        "PRIMARY_PROMOTION_NOT_IMPLEMENTED"
        in complete_decision.reasons,
        "Current-release block reason is explicit",
    )

    return {
        "schema": "cd.rust-primary-promotion-gate.v1",
        "deterministic_partial_false_exit_demonstrated": True,
        "safe_python_fallback_preserves_running_state": True,
        "python_missing_partial_rust_fail_closed": True,
        "current_release_primary_allowed": False,
        "partial_decision_reasons": list(decision.reasons),
        "hypothetical_complete_future_eligible": (
            complete_decision.future_primary_eligible
        ),
        "hypothetical_complete_current_release_allowed": (
            complete_decision.current_release_primary_allowed
        ),
    }


def live_contract_test(executable: Path) -> dict[str, Any]:
    python_sensor = ProcessSensor()
    rust_probe = RustProcessShadowProbe(
        executable.resolve(),
        timeout=5.0,
    )

    python_snapshot = python_sensor.collect()
    rust_snapshot = rust_probe.probe()
    comparison = compare_shadow_to_authoritative(
        python_snapshot,
        rust_snapshot,
    )
    decision = evaluate_candidate(
        rust_snapshot,
        comparison,
    )

    check(
        comparison.get("verdict") in GOOD_VERDICTS,
        "Live Rust common-set parity is aligned",
    )
    check(
        comparison.get("identity_disagreements", {}).get("count") == 0,
        "Live Rust identity disagreements are zero",
    )
    check(
        comparison.get("parent_disagreements", {}).get("count") == 0,
        "Live Rust parent disagreements are zero",
    )
    check(
        int(comparison.get("exact_graph_identity_matches", -1))
        == int(comparison.get("common_processes", -2)),
        "Live Rust all common ProcessGraph identities match",
    )

    # v0.4 Windows evidence currently has the known PID 0 coverage limit.
    check(
        bool(rust_snapshot.get("partial")),
        "Live Rust v0.4 reports partial coverage explicitly",
    )
    check(
        int(rust_snapshot.get("skipped", 0)) > 0,
        "Live Rust v0.4 reports at least one skipped PID",
    )
    check(
        not decision.future_primary_eligible,
        "Live partial Rust snapshot is blocked from future-primary eligibility",
    )
    check(
        "PARTIAL_SNAPSHOT" in decision.reasons,
        "Live promotion block includes PARTIAL_SNAPSHOT",
    )
    check(
        not decision.current_release_primary_allowed,
        "Live Rust remains blocked from current-release primary role",
    )

    source, selected, disposition = select_authoritative_snapshot(
        python_snapshot,
        rust_snapshot,
        decision,
    )
    check(
        source == "ProcessSensor",
        "Live selector keeps Python ProcessSensor authoritative",
    )
    check(
        selected is python_snapshot,
        "Live selector returns the Python snapshot object",
    )
    check(
        disposition == "PYTHON_AUTHORITATIVE",
        "Live selector disposition is PYTHON_AUTHORITATIVE",
    )

    graph = ProcessGraph()
    result = graph.ingest_snapshot(selected)
    check(
        isinstance(result, dict) and result.get("accepted") is True,
        "Live selected Python snapshot is accepted by ProcessGraph",
    )
    check(
        int(result.get("processes_valid", 0)) > 0,
        "Live authoritative ProcessGraph contains processes",
    )

    source2, selected2, disposition2 = select_authoritative_snapshot(
        None,
        rust_snapshot,
        decision,
    )
    check(
        source2 is None and selected2 is None,
        "Live Python-loss simulation does not promote partial Rust",
    )
    check(
        disposition2 == "NO_SAFE_AUTHORITATIVE_SNAPSHOT",
        "Live Python-loss simulation fails closed",
    )

    return {
        "schema": "cd.rust-primary-promotion-live.v1",
        "mode": "SHADOW_ONLY",
        "authoritative_sensor": source,
        "comparison_verdict": comparison.get("verdict"),
        "python_process_count": comparison.get("python_process_count"),
        "rust_process_count": comparison.get("rust_process_count"),
        "common_processes": comparison.get("common_processes"),
        "rust_partial": bool(rust_snapshot.get("partial")),
        "rust_skipped": int(rust_snapshot.get("skipped", 0)),
        "future_primary_eligible": decision.future_primary_eligible,
        "current_release_primary_allowed": (
            decision.current_release_primary_allowed
        ),
        "block_reasons": list(decision.reasons),
        "python_loss_disposition": disposition2,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-test-only",
        action="store_true",
        help="Run deterministic contract only; do not execute Rust EXE.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    deterministic = deterministic_contract_test()

    summary: dict[str, Any] = {
        "deterministic": deterministic,
    }

    if not args.self_test_only:
        executable = str(
            os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or ""
        ).strip()
        if not executable:
            raise AssertionError(
                "CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE is required"
            )

        exe_path = Path(executable).expanduser().resolve()
        check(
            exe_path.is_file(),
            "RustProcessSensor executable exists",
        )
        summary["live"] = live_contract_test(exe_path)

    print("\nRUST PRIMARY PROMOTION GATE SUMMARY")
    print(json.dumps(summary, indent=2, sort_keys=True))
    print("\nRUST PROCESS PRIMARY PROMOTION GATE v1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
