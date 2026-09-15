"""
CyberDefender — Resource Safety Plane v1.0.1
Recovery / Hysteresis / Anti-Flapping regression test.

Production EventBus/main.py are NOT modified.

The test verifies:
1. NORMAL -> DEGRADED requires escalation confirmation.
2. DEGRADED -> CRITICAL requires escalation confirmation.
3. CRITICAL does not recover from a single clean sample.
4. Recovery requires the configured confirmation count.
5. A pressure/recovery oscillation does not instantly create unsafe
   state transitions.
"""

from agent.core.resource_guard import ResourceGuard
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.backpressure_controller import BackpressureController
from agent.core.evidence_retention import EvidenceRetentionPolicy
from agent.core.bounded_durable_spool import (
    BoundedDurableSpool,
    SpoolPolicy,
)
from agent.core.resource_safety_plane import ResourceSafetyPlane


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"{status} | {label}")

    if not condition:
        raise AssertionError(label)


def build_plane():
    spool = BoundedDurableSpool(
        r".\state\resource_safety_recovery_test.jsonl",
        SpoolPolicy(
            max_events=10,
            max_bytes=64 * 1024,
        ),
    )

    return ResourceSafetyPlane(
        resource_guard=ResourceGuard(),
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
        evidence_retention=EvidenceRetentionPolicy(),
        bounded_spool=spool,
    )


def main():
    print("=== RESOURCE SAFETY PLANE RECOVERY TEST ===")

    plane = build_plane()

    # ---------------------------------------------------------
    # 1. NORMAL baseline
    # ---------------------------------------------------------

    result = plane.evaluate(100, 1000)

    check(
        "Baseline -> NORMAL",
        result["state"] == "NORMAL",
    )

    # ---------------------------------------------------------
    # 2. NORMAL -> DEGRADED
    #
    # BackpressureController uses escalation confirmation.
    # ---------------------------------------------------------

    first_degraded = plane.evaluate(850, 1000)

    check(
        "DEGRADED confirmation 1 -> remains NORMAL",
        first_degraded["state"] == "NORMAL",
    )

    second_degraded = plane.evaluate(850, 1000)

    check(
        "DEGRADED confirmation 2 -> DEGRADED",
        second_degraded["state"] == "DEGRADED",
    )

    # ---------------------------------------------------------
    # 3. DEGRADED -> CRITICAL
    # ---------------------------------------------------------

    first_critical = plane.evaluate(960, 1000)

    check(
        "CRITICAL confirmation 1 -> remains DEGRADED",
        first_critical["state"] == "DEGRADED",
    )

    second_critical = plane.evaluate(960, 1000)

    check(
        "CRITICAL confirmation 2 -> CRITICAL",
        second_critical["state"] == "CRITICAL",
    )

    critical_policy = plane.get_runtime_policy()

    check(
        "CRITICAL LOW disabled",
        critical_policy["allow_low"] is False,
    )

    check(
        "CRITICAL MEDIUM disabled",
        critical_policy["allow_medium"] is False,
    )

    check(
        "CRITICAL HIGH protected",
        critical_policy["allow_high"] is True,
    )

    check(
        "CRITICAL security evidence protected",
        critical_policy["security_evidence"] == "KEEP",
    )

    # ---------------------------------------------------------
    # 4. Single clean sample must NOT immediately recover.
    # ---------------------------------------------------------

    recovery_1 = plane.evaluate(100, 1000)

    check(
        "Recovery confirmation 1 -> not NORMAL",
        recovery_1["state"] != "NORMAL",
    )

    check(
        "Recovery confirmation 1 -> pipeline survives",
        recovery_1["allow_security_pipeline"] is True,
    )

    # ---------------------------------------------------------
    # 5. Second clean sample should complete recovery according
    #    to the configured recovery confirmation count.
    # ---------------------------------------------------------

    recovery_2 = plane.evaluate(100, 1000)

    check(
        "Recovery confirmation 2 -> NORMAL",
        recovery_2["state"] == "NORMAL",
    )

    check(
        "Recovered pipeline available",
        recovery_2["allow_security_pipeline"] is True,
    )

    # ---------------------------------------------------------
    # 6. Anti-flapping check.
    #
    # One bad sample after recovery must not immediately jump
    # back to CRITICAL.
    # ---------------------------------------------------------

    flap_1 = plane.evaluate(960, 1000)

    check(
        "Single pressure spike cannot jump to CRITICAL",
        flap_1["state"] != "CRITICAL",
    )

    check(
        "Single pressure spike keeps security pipeline alive",
        flap_1["allow_security_pipeline"] is True,
    )

    # Clear pressure before escalation confirmation completes.
    flap_clear = plane.evaluate(100, 1000)

    check(
        "Pressure cleared before escalation -> no CRITICAL",
        flap_clear["state"] != "CRITICAL",
    )

    check(
        "Anti-flapping security pipeline available",
        flap_clear["allow_security_pipeline"] is True,
    )

    stats = plane.get_stats()

    check(
        "No integration failures",
        stats["failures"] == 0,
    )

    print()
    print("RECOVERY / HYSTERESIS TEST: PASS")
    print("Anti-flapping protection: PASS")
    print("Security pipeline preservation: PASS")
    print("Production EventBus/main.py: UNMODIFIED")


if __name__ == "__main__":
    main()
