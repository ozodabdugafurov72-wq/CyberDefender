from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import time
from typing import Any

from agent.correlation.graph import ProcessGraph
from agent.sensors.process import ProcessSensor
from agent.sensors.rust_process_shadow import (
    RustProcessShadowProbe,
    compare_shadow_to_authoritative,
)

EXPECTED_RUST_SHA256 = (
    "ada90a9ee632b225196348213ef05970828c38ceb0c69eb3776c7e8cb9bedd2d"
)

GOOD_VERDICTS = {
    "ALIGNED_COMMON_SET",
    "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
}


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class RustEvidence:
    binary_trusted: bool
    probe_healthy: bool
    snapshot_validated: bool
    coverage_valid: bool
    coverage_mode: str | None
    alignment_verdict: str | None
    identity_disagreements: int
    parent_disagreements: int
    alignment_age_seconds: float
    healthy_streak: int


@dataclass(frozen=True)
class FailoverDecision:
    authoritative_sensor: str | None
    disposition: str
    may_ingest: bool
    reason: str


class ProcessSensorFailoverController:
    """
    Test-only state machine for the future authoritative sensor selector.

    It does NOT modify CyberDefenderRuntime and does NOT enable production
    Rust primary mode.

    Safety contract:
      - Python remains primary while healthy.
      - One transient Python failure does not switch sensors.
      - Rust failover requires explicit enable + bounded hysteresis + trust,
        validation, coverage and recent alignment evidence.
      - If neither source is safe, return no snapshot (preserve graph state).
      - Failback to Python also requires hysteresis to prevent flapping.
    """

    def __init__(
        self,
        *,
        failover_enabled: bool,
        python_failure_threshold: int = 2,
        python_recovery_threshold: int = 2,
        rust_healthy_threshold: int = 2,
        max_alignment_age_seconds: float = 30.0,
    ) -> None:
        if python_failure_threshold < 1:
            raise ValueError("python_failure_threshold")
        if python_recovery_threshold < 1:
            raise ValueError("python_recovery_threshold")
        if rust_healthy_threshold < 1:
            raise ValueError("rust_healthy_threshold")
        if max_alignment_age_seconds <= 0:
            raise ValueError("max_alignment_age_seconds")

        self.failover_enabled = bool(failover_enabled)
        self.python_failure_threshold = python_failure_threshold
        self.python_recovery_threshold = python_recovery_threshold
        self.rust_healthy_threshold = rust_healthy_threshold
        self.max_alignment_age_seconds = max_alignment_age_seconds

        self.state = "PYTHON_PRIMARY"
        self.python_failure_streak = 0
        self.python_recovery_streak = 0

    def _rust_gate(
        self,
        evidence: RustEvidence | None,
    ) -> tuple[bool, str]:
        if evidence is None:
            return False, "RUST_EVIDENCE_MISSING"

        if not evidence.binary_trusted:
            return False, "RUST_BINARY_UNTRUSTED"

        if not evidence.probe_healthy:
            return False, "RUST_PROBE_UNHEALTHY"

        if not evidence.snapshot_validated:
            return False, "RUST_SNAPSHOT_UNVALIDATED"

        if not evidence.coverage_valid:
            return False, "RUST_COVERAGE_INVALID"

        if evidence.coverage_mode not in {
            "COMPLETE",
            "PARTIAL_EXPLICIT_COVERAGE",
        }:
            return False, "RUST_COVERAGE_MODE_UNSAFE"

        if evidence.alignment_verdict not in GOOD_VERDICTS:
            return False, "RUST_ALIGNMENT_NOT_GOOD"

        if evidence.identity_disagreements != 0:
            return False, "RUST_IDENTITY_DISAGREEMENT"

        if evidence.parent_disagreements != 0:
            return False, "RUST_PARENT_DISAGREEMENT"

        if evidence.alignment_age_seconds > self.max_alignment_age_seconds:
            return False, "RUST_ALIGNMENT_STALE"

        if evidence.healthy_streak < self.rust_healthy_threshold:
            return False, "RUST_HEALTH_STREAK_TOO_SHORT"

        return True, "RUST_GATE_PASS"

    def decide(
        self,
        *,
        python_snapshot: dict[str, Any] | None,
        rust_snapshot: dict[str, Any] | None,
        rust_evidence: RustEvidence | None,
    ) -> FailoverDecision:
        python_ok = isinstance(python_snapshot, dict)

        if self.state == "PYTHON_PRIMARY":
            self.python_recovery_streak = 0

            if python_ok:
                self.python_failure_streak = 0
                return FailoverDecision(
                    "ProcessSensor",
                    "PYTHON_AUTHORITATIVE",
                    True,
                    "PYTHON_HEALTHY",
                )

            self.python_failure_streak += 1

            if self.python_failure_streak < self.python_failure_threshold:
                return FailoverDecision(
                    None,
                    "HOLD_LAST_GRAPH_STATE",
                    False,
                    "PYTHON_FAILURE_NOT_CONFIRMED",
                )

            if not self.failover_enabled:
                return FailoverDecision(
                    None,
                    "NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                    False,
                    "RUST_FAILOVER_DISABLED",
                )

            rust_ok, reason = self._rust_gate(rust_evidence)
            if not rust_ok or not isinstance(rust_snapshot, dict):
                return FailoverDecision(
                    None,
                    "NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                    False,
                    reason,
                )

            self.state = "RUST_FAILOVER"
            self.python_recovery_streak = 0

            return FailoverDecision(
                "RustProcessSensor",
                "RUST_FAILOVER_AUTHORITATIVE",
                True,
                "PYTHON_FAILURE_CONFIRMED_RUST_GATE_PASS",
            )

        # RUST_FAILOVER state
        if python_ok:
            self.python_recovery_streak += 1
        else:
            self.python_recovery_streak = 0

        if (
            python_ok
            and self.python_recovery_streak
            >= self.python_recovery_threshold
        ):
            self.state = "PYTHON_PRIMARY"
            self.python_failure_streak = 0
            self.python_recovery_streak = 0

            return FailoverDecision(
                "ProcessSensor",
                "PYTHON_FAILBACK_AUTHORITATIVE",
                True,
                "PYTHON_RECOVERY_CONFIRMED",
            )

        rust_ok, reason = self._rust_gate(rust_evidence)
        if not rust_ok or not isinstance(rust_snapshot, dict):
            return FailoverDecision(
                None,
                "NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                False,
                reason,
            )

        return FailoverDecision(
            "RustProcessSensor",
            "RUST_FAILOVER_AUTHORITATIVE",
            True,
            "RUST_REMAINS_SAFE",
        )


def synthetic_rust_evidence(**overrides: Any) -> RustEvidence:
    values = {
        "binary_trusted": True,
        "probe_healthy": True,
        "snapshot_validated": True,
        "coverage_valid": True,
        "coverage_mode": "PARTIAL_EXPLICIT_COVERAGE",
        "alignment_verdict": "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
        "identity_disagreements": 0,
        "parent_disagreements": 0,
        "alignment_age_seconds": 1.0,
        "healthy_streak": 2,
    }
    values.update(overrides)
    return RustEvidence(**values)


def deterministic_contract() -> None:
    py = {"sensor": "ProcessSensor", "processes": []}
    rust = {
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "partial": True,
        "skipped": 1,
        "processes": [],
    }
    good = synthetic_rust_evidence()

    # Current release policy remains disabled.
    disabled = ProcessSensorFailoverController(
        failover_enabled=False,
    )
    d1 = disabled.decide(
        python_snapshot=py,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    check(
        d1.authoritative_sensor == "ProcessSensor",
        "CURRENT: Python remains authoritative while healthy",
    )

    d2 = disabled.decide(
        python_snapshot=None,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    check(
        d2.disposition == "HOLD_LAST_GRAPH_STATE",
        "CURRENT: first Python failure preserves graph state",
    )

    d3 = disabled.decide(
        python_snapshot=None,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    check(
        d3.authoritative_sensor is None
        and d3.reason == "RUST_FAILOVER_DISABLED",
        "CURRENT: confirmed Python failure still cannot promote Rust",
    )

    # Isolated future-policy prototype.
    enabled = ProcessSensorFailoverController(
        failover_enabled=True,
    )

    check(
        enabled.decide(
            python_snapshot=py,
            rust_snapshot=rust,
            rust_evidence=good,
        ).authoritative_sensor == "ProcessSensor",
        "FUTURE: healthy Python wins even when Rust is eligible",
    )

    first_fail = enabled.decide(
        python_snapshot=None,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    check(
        first_fail.disposition == "HOLD_LAST_GRAPH_STATE",
        "FUTURE: one Python failure does not cause failover",
    )

    second_fail = enabled.decide(
        python_snapshot=None,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    check(
        second_fail.authoritative_sensor == "RustProcessSensor",
        "FUTURE: confirmed Python failure + good Rust gate enters failover",
    )

    first_recovery = enabled.decide(
        python_snapshot=py,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    check(
        first_recovery.authoritative_sensor == "RustProcessSensor",
        "FUTURE: one Python recovery sample does not flap back",
    )

    second_recovery = enabled.decide(
        python_snapshot=py,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    check(
        second_recovery.authoritative_sensor == "ProcessSensor"
        and second_recovery.disposition
        == "PYTHON_FAILBACK_AUTHORITATIVE",
        "FUTURE: confirmed Python recovery performs bounded failback",
    )

    bad_cases = [
        ("RUST_BINARY_UNTRUSTED", {"binary_trusted": False}),
        ("RUST_PROBE_UNHEALTHY", {"probe_healthy": False}),
        ("RUST_SNAPSHOT_UNVALIDATED", {"snapshot_validated": False}),
        ("RUST_COVERAGE_INVALID", {"coverage_valid": False}),
        (
            "RUST_COVERAGE_MODE_UNSAFE",
            {"coverage_mode": "PARTIAL_FAIL_CLOSED"},
        ),
        (
            "RUST_ALIGNMENT_NOT_GOOD",
            {"alignment_verdict": "REVIEW_REQUIRED"},
        ),
        (
            "RUST_IDENTITY_DISAGREEMENT",
            {"identity_disagreements": 1},
        ),
        (
            "RUST_PARENT_DISAGREEMENT",
            {"parent_disagreements": 1},
        ),
        (
            "RUST_ALIGNMENT_STALE",
            {"alignment_age_seconds": 31.0},
        ),
        (
            "RUST_HEALTH_STREAK_TOO_SHORT",
            {"healthy_streak": 1},
        ),
    ]

    for expected_reason, override in bad_cases:
        controller = ProcessSensorFailoverController(
            failover_enabled=True,
        )
        controller.decide(
            python_snapshot=py,
            rust_snapshot=rust,
            rust_evidence=good,
        )
        controller.decide(
            python_snapshot=None,
            rust_snapshot=rust,
            rust_evidence=synthetic_rust_evidence(**override),
        )
        decision = controller.decide(
            python_snapshot=None,
            rust_snapshot=rust,
            rust_evidence=synthetic_rust_evidence(**override),
        )
        check(
            decision.authoritative_sensor is None
            and decision.reason == expected_reason,
            f"GATE: {expected_reason} fails closed",
        )

    # If Rust becomes unsafe while in failover, stale Rust is never reused.
    unsafe_active = ProcessSensorFailoverController(
        failover_enabled=True,
    )
    unsafe_active.decide(
        python_snapshot=py,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    unsafe_active.decide(
        python_snapshot=None,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    unsafe_active.decide(
        python_snapshot=None,
        rust_snapshot=rust,
        rust_evidence=good,
    )
    active_loss = unsafe_active.decide(
        python_snapshot=None,
        rust_snapshot=None,
        rust_evidence=synthetic_rust_evidence(
            probe_healthy=False,
        ),
    )
    check(
        active_loss.authoritative_sensor is None
        and not active_loss.may_ingest,
        "ACTIVE FAILOVER: unsafe Rust yields no authoritative snapshot",
    )


def coverage_evidence(snapshot: dict[str, Any]) -> tuple[bool, str | None]:
    graph = ProcessGraph()
    result = graph.ingest_snapshot(snapshot)

    if not isinstance(result, dict) or not result.get("accepted"):
        return False, None

    return (
        bool(result.get("coverage_metadata_valid")),
        result.get("coverage_mode"),
    )


def live_contract(exe_path: Path) -> None:
    check(
        ProcessGraph.VERSION == "1.6",
        "LIVE: ProcessGraph coverage-aware version is 1.6",
    )

    actual_hash = sha256_file(exe_path)
    check(
        actual_hash == EXPECTED_RUST_SHA256,
        "LIVE: Rust executable matches pinned v0.4 SHA-256",
    )

    python_sensor = ProcessSensor()
    rust_probe = RustProcessShadowProbe(
        exe_path,
        timeout=5.0,
    )

    python_baseline = python_sensor.collect()
    rust1 = rust_probe.probe()
    aligned_at = time.monotonic()

    comparison = compare_shadow_to_authoritative(
        python_baseline,
        rust1,
    )

    check(
        comparison.get("verdict") in GOOD_VERDICTS,
        "LIVE: baseline Python/Rust alignment is good",
    )
    check(
        comparison.get("identity_disagreements", {}).get("count") == 0,
        "LIVE: identity disagreements are zero",
    )
    check(
        comparison.get("parent_disagreements", {}).get("count") == 0,
        "LIVE: parent disagreements are zero",
    )

    # Additional successful Rust samples establish the test-only health streak.
    rust2 = rust_probe.probe()
    coverage_valid2, coverage_mode2 = coverage_evidence(rust2)

    check(
        coverage_valid2,
        "LIVE: second Rust snapshot has valid ProcessGraph coverage metadata",
    )
    check(
        coverage_mode2 in {
            "COMPLETE",
            "PARTIAL_EXPLICIT_COVERAGE",
        },
        "LIVE: second Rust snapshot has safe coverage mode",
    )

    evidence2 = RustEvidence(
        binary_trusted=True,
        probe_healthy=True,
        snapshot_validated=True,
        coverage_valid=coverage_valid2,
        coverage_mode=coverage_mode2,
        alignment_verdict=comparison.get("verdict"),
        identity_disagreements=int(
            comparison.get("identity_disagreements", {}).get("count", -1)
        ),
        parent_disagreements=int(
            comparison.get("parent_disagreements", {}).get("count", -1)
        ),
        alignment_age_seconds=(
            time.monotonic() - aligned_at
        ),
        healthy_streak=2,
    )

    # Current release remains disabled.
    current = ProcessSensorFailoverController(
        failover_enabled=False,
    )
    check(
        current.decide(
            python_snapshot=python_baseline,
            rust_snapshot=rust2,
            rust_evidence=evidence2,
        ).authoritative_sensor == "ProcessSensor",
        "LIVE CURRENT: Python remains authoritative",
    )

    current.decide(
        python_snapshot=None,
        rust_snapshot=rust2,
        rust_evidence=evidence2,
    )
    current_block = current.decide(
        python_snapshot=None,
        rust_snapshot=rust2,
        rust_evidence=evidence2,
    )
    check(
        current_block.reason == "RUST_FAILOVER_DISABLED",
        "LIVE CURRENT: Rust primary failover remains disabled",
    )

    # Isolated future-policy simulation only; does not touch runtime main.
    future = ProcessSensorFailoverController(
        failover_enabled=True,
    )
    future.decide(
        python_snapshot=python_baseline,
        rust_snapshot=rust2,
        rust_evidence=evidence2,
    )

    first_fail = future.decide(
        python_snapshot=None,
        rust_snapshot=rust2,
        rust_evidence=evidence2,
    )
    check(
        first_fail.disposition == "HOLD_LAST_GRAPH_STATE",
        "LIVE FUTURE: first simulated Python loss holds graph state",
    )

    rust3 = rust_probe.probe()
    coverage_valid3, coverage_mode3 = coverage_evidence(rust3)
    evidence3 = RustEvidence(
        binary_trusted=True,
        probe_healthy=True,
        snapshot_validated=True,
        coverage_valid=coverage_valid3,
        coverage_mode=coverage_mode3,
        alignment_verdict=comparison.get("verdict"),
        identity_disagreements=int(
            comparison.get("identity_disagreements", {}).get("count", -1)
        ),
        parent_disagreements=int(
            comparison.get("parent_disagreements", {}).get("count", -1)
        ),
        alignment_age_seconds=(
            time.monotonic() - aligned_at
        ),
        healthy_streak=3,
    )

    failover = future.decide(
        python_snapshot=None,
        rust_snapshot=rust3,
        rust_evidence=evidence3,
    )
    check(
        failover.authoritative_sensor == "RustProcessSensor",
        "LIVE FUTURE: confirmed Python loss can select gated Rust candidate",
    )

    # Prove selected Rust snapshot is acceptable to a disposable graph only.
    experimental_graph = ProcessGraph()
    baseline_result = experimental_graph.ingest_snapshot(
        python_baseline
    )
    check(
        baseline_result.get("accepted") is True,
        "LIVE FUTURE: experimental graph accepts Python baseline",
    )
    rust_result = experimental_graph.ingest_snapshot(
        rust3
    )
    check(
        rust_result.get("accepted") is True
        and rust_result.get("coverage_metadata_valid") is True,
        "LIVE FUTURE: experimental graph accepts gated Rust snapshot",
    )

    # Failback hysteresis.
    python_recovery1 = python_sensor.collect()
    rust4 = rust_probe.probe()
    coverage_valid4, coverage_mode4 = coverage_evidence(rust4)
    evidence4 = RustEvidence(
        binary_trusted=True,
        probe_healthy=True,
        snapshot_validated=True,
        coverage_valid=coverage_valid4,
        coverage_mode=coverage_mode4,
        alignment_verdict=comparison.get("verdict"),
        identity_disagreements=0,
        parent_disagreements=0,
        alignment_age_seconds=(
            time.monotonic() - aligned_at
        ),
        healthy_streak=4,
    )

    recovery1 = future.decide(
        python_snapshot=python_recovery1,
        rust_snapshot=rust4,
        rust_evidence=evidence4,
    )
    check(
        recovery1.authoritative_sensor == "RustProcessSensor",
        "LIVE FUTURE: first Python recovery sample does not flap back",
    )

    python_recovery2 = python_sensor.collect()
    recovery2 = future.decide(
        python_snapshot=python_recovery2,
        rust_snapshot=rust4,
        rust_evidence=evidence4,
    )
    check(
        recovery2.authoritative_sensor == "ProcessSensor",
        "LIVE FUTURE: second Python recovery sample returns authority to Python",
    )

    print("\nLIVE CONTRACT SUMMARY")
    print("  current_release_failover_enabled: false")
    print("  future_test_policy_failover: proven in isolated controller only")
    print(f"  rust_coverage_mode: {coverage_mode3}")
    print(f"  rust_binary_sha256: {actual_hash}")
    print("  runtime_main_modified: false")
    print("  production_rust_primary_enabled: false")


def main() -> int:
    deterministic_contract()

    executable = str(
        os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or ""
    ).strip()

    if executable:
        exe_path = Path(executable).expanduser().resolve()
        check(
            exe_path.is_file(),
            "RustProcessSensor executable exists",
        )
        live_contract(exe_path)
    else:
        print(
            "[INFO] CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE not set; "
            "live contract skipped."
        )

    print("\nPROCESS SENSOR FAILOVER CONTROLLER CONTRACT v1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
