"""
CyberDefender Resource Safety Plane v1.1
Deterministic Recovery / Hysteresis Validation

This test intentionally does NOT depend on live host CPU/RAM.

Test topology:

    Deterministic ResourceGuard
             |
             v
    ResourceSafetyPlane
             |
             +--> BackpressureController
             +--> EventRateLimiter
             +--> EvidenceRetentionPolicy
             +--> BoundedDurableSpool

Safety objectives
-----------------
1. NORMAL baseline is deterministic.
2. Queue pressure reaches DEGRADED.
3. Queue pressure reaches CRITICAL.
4. CRITICAL never disables security pipeline.
5. LOW/MEDIUM may be shed at CRITICAL.
6. HIGH remains admitted.
7. Security evidence remains KEEP.
8. One healthy sample does not recover immediately.
9. Required healthy confirmations recover to NORMAL.
10. Post-recovery pressure does not immediately flap to CRITICAL.
11. No exception escapes.
12. Real host CPU/RAM cannot affect the result.

This is a standalone deterministic validation script.
It is intentionally executable both directly and through pytest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict


# ----------------------------------------------------------------------
# Project root
# ----------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ----------------------------------------------------------------------
# CyberDefender components
# ----------------------------------------------------------------------

from agent.core.resource_guard import ResourceGuard
from agent.core.resource_safety_plane import ResourceSafetyPlane
from agent.core.backpressure_controller import BackpressureController
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.evidence_retention import EvidenceRetentionPolicy
from agent.core.bounded_durable_spool import (
    BoundedDurableSpool,
    SpoolPolicy,
)


# ----------------------------------------------------------------------
# Deterministic metric provider
# ----------------------------------------------------------------------

class DeterministicResourceProvider:
    """
    Controlled ResourceGuard metric source.

    The provider intentionally returns healthy metrics regardless of
    the real machine's CPU/RAM state.

    This prevents test contamination from:
        - browser usage
        - Windows background processes
        - antivirus
        - IDE
        - Docker
        - other workloads
        - VM pressure
        - memory fragmentation
    """

    def __init__(self) -> None:
        self.host = {
            "cpu_percent": 10.0,
            "memory_percent": 40.0,
            "memory_available_mb": 4096.0,
        }

        self.agent = {
            "cpu_percent": 1.0,
            "memory_rss_mb": 128.0,
            "memory_percent": 1.0,
            "threads": 4,
        }

    def host_metrics(self) -> Dict[str, float]:
        return dict(self.host)

    def agent_metrics(self) -> Dict[str, Any]:
        return dict(self.agent)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

RESULTS = []


def check(label: str, condition: bool) -> None:
    """
    Record and print one deterministic assertion.
    """

    if condition:
        print(f"PASS | {label}")
        RESULTS.append(
            {
                "label": label,
                "status": "PASS",
            }
        )
        return

    print(f"FAIL | {label}")
    RESULTS.append(
        {
            "label": label,
            "status": "FAIL",
        }
    )

    raise AssertionError(label)


def state_of(result: Any) -> str:
    """
    Safely extract a state from either:
        - a plain string
        - a dictionary containing {"state": ...}
        - any other unexpected value

    Invalid/unknown values are normalized to an empty string so
    assertions fail cleanly instead of raising unrelated exceptions.
    """

    if isinstance(result, str):
        return result.strip().upper()

    if isinstance(result, dict):
        value = result.get("state", "")
        if isinstance(value, str):
            return value.strip().upper()

    return ""


# ----------------------------------------------------------------------
# Test fixture
# ----------------------------------------------------------------------

def build_plane() -> ResourceSafetyPlane:
    """
    Build a completely deterministic Resource Safety Plane.

    Important:
        ResourceGuard uses injected metrics.
        Therefore the test does not depend on the real host.
    """

    provider = DeterministicResourceProvider()

    resource_guard = ResourceGuard(
        host_metrics_provider=provider.host_metrics,
        agent_metrics_provider=provider.agent_metrics,
    )

    spool_path = (
        PROJECT_ROOT
        / "state"
        / "resource_safety_recovery_v1_1.jsonl"
    )

    spool_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    spool = BoundedDurableSpool(
        str(spool_path),
        SpoolPolicy(
            max_events=10,
            max_bytes=64 * 1024,
        ),
    )

    return ResourceSafetyPlane(
        resource_guard=resource_guard,
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
        evidence_retention=EvidenceRetentionPolicy(),
        bounded_spool=spool,
    )


# ----------------------------------------------------------------------
# Main deterministic validation
# ----------------------------------------------------------------------

def main() -> int:
    print()
    print(
        "=== RESOURCE SAFETY PLANE v1.1 "
        "DETERMINISTIC RECOVERY TEST ==="
    )
    print()

    plane = build_plane()

    # ==============================================================
    # BASELINE
    # ==============================================================

    normal = plane.evaluate(
        100,
        1000,
    )

    check(
        "Baseline -> NORMAL",
        state_of(normal) == "NORMAL",
    )

    check(
        "Baseline resource state -> NORMAL",
        state_of(normal.get("resource_state", {}))
        == "NORMAL",
    )

    check(
        "Baseline backpressure state -> NORMAL",
        state_of(normal.get("backpressure_state", {}))
        == "NORMAL",
    )

    check(
        "Baseline security pipeline available",
        normal["allow_security_pipeline"] is True,
    )

    # ==============================================================
    # ENTER DEGRADED
    #
    # Queue occupancy = 85%
    #
    # BackpressureController:
    #     60% elevated
    #     80% degraded
    #     95% critical
    #
    # escalation_confirmations = 2
    # ==============================================================

    degraded_1 = plane.evaluate(
        850,
        1000,
    )

    check(
        "First degraded pressure preserves security pipeline",
        degraded_1["allow_security_pipeline"] is True,
    )

    check(
        "First degraded pressure does not jump to CRITICAL",
        state_of(degraded_1) != "CRITICAL",
    )

    degraded_2 = plane.evaluate(
        850,
        1000,
    )

    check(
        "Second degraded pressure -> DEGRADED",
        state_of(degraded_2) == "DEGRADED",
    )

    check(
        "DEGRADED resource state remains NORMAL",
        state_of(
            degraded_2["resource_state"]
        ) == "NORMAL",
    )

    check(
        "DEGRADED backpressure state -> DEGRADED",
        state_of(
            degraded_2["backpressure_state"]
        ) == "DEGRADED",
    )

    check(
        "DEGRADED security pipeline available",
        degraded_2["allow_security_pipeline"] is True,
    )

    # ==============================================================
    # ENTER CRITICAL
    #
    # Queue occupancy = 96%
    # ==============================================================

    critical_1 = plane.evaluate(
        960,
        1000,
    )

    check(
        "Critical pressure produces protected state",
        state_of(critical_1)
        in {
            "DEGRADED",
            "CRITICAL",
        },
    )

    check(
        "Critical pressure never disables security pipeline",
        critical_1["allow_security_pipeline"] is True,
    )

    if state_of(critical_1) != "CRITICAL":
        critical_2 = plane.evaluate(
            960,
            1000,
        )
    else:
        critical_2 = critical_1

    check(
        "Critical pressure reaches CRITICAL",
        state_of(critical_2) == "CRITICAL",
    )

    check(
        "CRITICAL resource state remains NORMAL",
        state_of(
            critical_2["resource_state"]
        ) == "NORMAL",
    )

    check(
        "CRITICAL backpressure state -> CRITICAL",
        state_of(
            critical_2["backpressure_state"]
        ) == "CRITICAL",
    )

    check(
        "CRITICAL LOW disabled",
        plane.get_runtime_policy()["allow_low"] is False,
    )

    check(
        "CRITICAL MEDIUM disabled",
        plane.get_runtime_policy()["allow_medium"] is False,
    )

    check(
        "CRITICAL HIGH retained",
        plane.get_runtime_policy()["allow_high"] is True,
    )

    check(
        "CRITICAL evidence retained",
        plane.get_runtime_policy()[
            "security_evidence"
        ] == "KEEP",
    )

    # ==============================================================
    # RECOVERY SAMPLE 1
    #
    # Queue occupancy = 10%
    #
    # First healthy sample:
    #     CRITICAL must NOT immediately become NORMAL.
    # ==============================================================

    recovery_1 = plane.evaluate(
        100,
        1000,
    )

    check(
        "Recovery sample 1 does not immediately become NORMAL",
        state_of(recovery_1) != "NORMAL",
    )

    check(
        "Recovery sample 1 preserves security pipeline",
        recovery_1["allow_security_pipeline"] is True,
    )

    check(
        "Recovery sample 1 resource state -> NORMAL",
        state_of(
            recovery_1["resource_state"]
        ) == "NORMAL",
    )

    # ==============================================================
    # RECOVERY SAMPLE 2
    #
    # BackpressureController recovery_confirmations = 2
    #
    # Therefore this sample must reach NORMAL.
    # ==============================================================

    recovery_2 = plane.evaluate(
        100,
        1000,
    )

    check(
        "Recovery confirmation reaches NORMAL",
        state_of(recovery_2) == "NORMAL",
    )

    check(
        "Recovered resource state -> NORMAL",
        state_of(
            recovery_2["resource_state"]
        ) == "NORMAL",
    )

    check(
        "Recovered backpressure state -> NORMAL",
        state_of(
            recovery_2["backpressure_state"]
        ) == "NORMAL",
    )

    check(
        "Recovered security pipeline available",
        recovery_2["allow_security_pipeline"] is True,
    )

    # ==============================================================
    # ANTI-FLAPPING
    #
    # One pressure spike must not immediately reach CRITICAL.
    # ==============================================================

    spike = plane.evaluate(
        850,
        1000,
    )

    check(
        "Single post-recovery spike is not CRITICAL",
        state_of(spike) != "CRITICAL",
    )

    check(
        "Post-recovery spike preserves security pipeline",
        spike["allow_security_pipeline"] is True,
    )

    # ==============================================================
    # PRESSURE CLEARED
    # ==============================================================

    cleared = plane.evaluate(
        100,
        1000,
    )

    check(
        "Pressure clear prevents CRITICAL escalation",
        state_of(cleared) != "CRITICAL",
    )

    check(
        "Pressure clear preserves security pipeline",
        cleared["allow_security_pipeline"] is True,
    )

    # ==============================================================
    # FINAL HEALTH
    # ==============================================================

    health = plane.health_check()

    check(
        "Safety Plane health is HEALTHY",
        health["status"] == "HEALTHY",
    )

    check(
        "Critical security survival invariant enabled",
        health[
            "security_pipeline_survives_critical"
        ] is True,
    )

    # ==============================================================
    # FINAL STATS
    # ==============================================================

    stats = plane.get_stats()

    check(
        "Final plane state -> NORMAL",
        stats["state"] == "NORMAL",
    )

    check(
        "No unexpected plane failures",
        stats["failures"] == 0,
    )

    print()
    print("=== DETERMINISTIC RECOVERY RESULT ===")

    passed = sum(
        1
        for item in RESULTS
        if item["status"] == "PASS"
    )

    failed = sum(
        1
        for item in RESULTS
        if item["status"] == "FAIL"
    )

    print(f"PASS: {passed}")
    print(f"FAIL: {failed}")

    print()
    print("State machine:")
    print("  NORMAL -> DEGRADED -> CRITICAL")
    print("  CRITICAL -> DEGRADED -> NORMAL")
    print()
    print(
        "Deterministic host metrics: ENABLED"
    )
    print(
        "Live CPU/RAM contamination: BLOCKED"
    )
    print(
        "Security pipeline preservation: VERIFIED"
    )
    print(
        "Recovery hysteresis: VERIFIED"
    )
    print(
        "Anti-flapping: VERIFIED"
    )

    print()

    if failed:
        print(
            "RESULT: FAIL"
        )
        return 1

    print(
        "RESULT: PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())