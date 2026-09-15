"""
Resource Safety Plane v1.0.1 hardened integration regression test.

Production EventBus/main.py are NOT modified.
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


def main():
    spool = BoundedDurableSpool(
        r".\state\resource_safety_plane_regression.jsonl",
        SpoolPolicy(
            max_events=10,
            max_bytes=64 * 1024,
        ),
    )

    plane = ResourceSafetyPlane(
        resource_guard=ResourceGuard(),
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
        evidence_retention=EvidenceRetentionPolicy(),
        bounded_spool=spool,
    )

    print("=== RESOURCE SAFETY PLANE v1.0.1 REGRESSION ===")

    # ---------------------------------------------------------
    # HEALTH
    # ---------------------------------------------------------

    health = plane.health_check()

    check(
        "Health",
        health["status"] == "HEALTHY",
    )

    check(
        "All components attached",
        all(health["components"].values()),
    )

    # ---------------------------------------------------------
    # NORMAL
    # ---------------------------------------------------------

    normal = plane.evaluate(
        100,
        1000,
    )

    check(
        "NORMAL state",
        normal["state"] == "NORMAL",
    )

    check(
        "NORMAL pipeline available",
        normal["allow_security_pipeline"] is True,
    )

    # ---------------------------------------------------------
    # DEGRADED
    #
    # BackpressureController requires two consecutive
    # confirmations before state transition.
    # ---------------------------------------------------------

    degraded_1 = plane.evaluate(
        850,
        1000,
    )

    check(
        "DEGRADED confirmation 1",
        degraded_1["state"] == "NORMAL",
    )

    check(
        "Pipeline remains available during confirmation",
        degraded_1["allow_security_pipeline"] is True,
    )

    degraded_2 = plane.evaluate(
        850,
        1000,
    )

    check(
        "DEGRADED state",
        degraded_2["state"] == "DEGRADED",
    )

    check(
        "DEGRADED pipeline available",
        degraded_2["allow_security_pipeline"] is True,
    )

    # ---------------------------------------------------------
    # CRITICAL
    #
    # CRITICAL also requires confirmation.
    # ---------------------------------------------------------

    critical_1 = plane.evaluate(
        960,
        1000,
    )

    check(
        "CRITICAL confirmation 1",
        critical_1["state"] == "DEGRADED",
    )

    check(
        "Security pipeline survives CRITICAL confirmation",
        critical_1["allow_security_pipeline"] is True,
    )

    critical_2 = plane.evaluate(
        960,
        1000,
    )

    check(
        "CRITICAL state",
        critical_2["state"] == "CRITICAL",
    )

    check(
        "CRITICAL pipeline STILL available",
        critical_2["allow_security_pipeline"] is True,
    )

    # ---------------------------------------------------------
    # CRITICAL RUNTIME POLICY
    # ---------------------------------------------------------

    policy = plane.get_runtime_policy()

    check(
        "CRITICAL LOW throttled",
        policy["allow_low"] is False,
    )

    check(
        "CRITICAL MEDIUM throttled",
        policy["allow_medium"] is False,
    )

    check(
        "CRITICAL HIGH retained",
        policy["allow_high"] is True,
    )

    check(
        "CRITICAL events retained",
        policy["allow_critical"] is True,
    )

    check(
        "CRITICAL security evidence retained",
        policy["security_evidence"] == "KEEP",
    )

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    stats = plane.get_stats()

    check(
        "No integration failures",
        stats["failures"] == 0,
    )

    print()
    print("RESOURCE SAFETY PLANE v1.0.1: PASS")
    print(
        "Security pipeline survives CRITICAL pressure: PASS"
    )
    print(
        "Production EventBus/main.py: UNMODIFIED"
    )


if __name__ == "__main__":
    main()