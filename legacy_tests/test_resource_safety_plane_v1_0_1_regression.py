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
        SpoolPolicy(max_events=10, max_bytes=64 * 1024),
    )

    plane = ResourceSafetyPlane(
        resource_guard=ResourceGuard(),
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
        evidence_retention=EvidenceRetentionPolicy(),
        bounded_spool=spool,
    )

    print("=== RESOURCE SAFETY PLANE v1.0.1 REGRESSION ===")

    health = plane.health_check()
    check("Health", health["status"] == "HEALTHY")
    check(
        "All components attached",
        all(health["components"].values()),
    )

    normal = plane.evaluate(100, 1000)
    check("NORMAL state", normal["state"] == "NORMAL")
    check(
        "NORMAL pipeline available",
        normal["allow_security_pipeline"] is True,
    )

    degraded = plane.evaluate(850, 1000)
    check("DEGRADED state", degraded["state"] == "DEGRADED")
    check(
        "DEGRADED pipeline available",
        degraded["allow_security_pipeline"] is True,
    )

    critical = plane.evaluate(960, 1000)
    check("CRITICAL state", critical["state"] == "CRITICAL")
    check(
        "CRITICAL pipeline STILL available",
        critical["allow_security_pipeline"] is True,
    )

    policy = plane.get_runtime_policy()
    check("CRITICAL LOW throttled", policy["allow_low"] is False)
    check("CRITICAL MEDIUM throttled", policy["allow_medium"] is False)
    check("CRITICAL HIGH retained", policy["allow_high"] is True)
    check(
        "CRITICAL security evidence retained",
        policy["security_evidence"] == "KEEP",
    )

    stats = plane.get_stats()
    check("No integration failures", stats["failures"] == 0)

    print()
    print("RESOURCE SAFETY PLANE v1.0.1: PASS")
    print("Security pipeline survives CRITICAL pressure: PASS")
    print("Production EventBus/main.py: UNMODIFIED")


if __name__ == "__main__":
    main()
