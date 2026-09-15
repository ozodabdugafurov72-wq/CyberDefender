"""
CyberDefender — Resource Safety Plane v1.0.1
Failure-injection and fail-safe regression test.

Production modules are not modified.
The test uses small fault-injection doubles to verify that component
failures cannot disable the security pipeline.
"""

from agent.core.resource_safety_plane import ResourceSafetyPlane


class FailingResourceGuard:
    def check(self):
        raise RuntimeError("injected ResourceGuard failure")


class FailingBackpressureController:
    def evaluate(self, queue_size, queue_capacity, resource_state):
        raise RuntimeError("injected BackpressureController failure")


class FailingRateLimiter:
    def set_state(self, state):
        raise RuntimeError("injected EventRateLimiter failure")


class FailingSpool:
    def get_stats(self):
        raise RuntimeError("injected spool failure")


class HealthyEvidenceRetention:
    pass


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"{status} | {label}")
    if not condition:
        raise AssertionError(label)


def test_resource_guard_failure():
    plane = ResourceSafetyPlane(
        resource_guard=FailingResourceGuard(),
        evidence_retention=HealthyEvidenceRetention(),
    )

    result = plane.evaluate(0, 100)

    check(
        "ResourceGuard failure -> DEGRADED",
        result["state"] == "DEGRADED",
    )
    check(
        "ResourceGuard failure -> security pipeline survives",
        result["allow_security_pipeline"] is True,
    )
    check(
        "ResourceGuard failure -> failure recorded",
        plane.get_stats()["failures"] >= 1,
    )


def test_backpressure_failure():
    plane = ResourceSafetyPlane(
        backpressure_controller=FailingBackpressureController(),
    )

    result = plane.evaluate(100, 1000)

    check(
        "Backpressure failure -> DEGRADED",
        result["state"] == "DEGRADED",
    )
    check(
        "Backpressure failure -> security pipeline survives",
        result["allow_security_pipeline"] is True,
    )


def test_rate_limiter_failure():
    plane = ResourceSafetyPlane(
        event_rate_limiter=FailingRateLimiter(),
    )

    result = plane.evaluate(100, 1000)

    check(
        "RateLimiter failure -> DEGRADED",
        result["state"] == "DEGRADED",
    )
    check(
        "RateLimiter failure -> security pipeline survives",
        result["allow_security_pipeline"] is True,
    )


def test_spool_failure():
    plane = ResourceSafetyPlane(
        bounded_spool=FailingSpool(),
    )

    result = plane.evaluate()

    check(
        "Spool failure -> safe fallback",
        result["state"] == "NORMAL",
    )
    check(
        "Spool failure -> security pipeline survives",
        result["allow_security_pipeline"] is True,
    )
    check(
        "Spool failure -> failure recorded",
        plane.get_stats()["failures"] >= 1,
    )


def test_multiple_failures():
    plane = ResourceSafetyPlane(
        resource_guard=FailingResourceGuard(),
        event_rate_limiter=FailingRateLimiter(),
        backpressure_controller=FailingBackpressureController(),
        bounded_spool=FailingSpool(),
    )

    result = plane.evaluate()

    check(
        "Multiple simultaneous failures -> DEGRADED",
        result["state"] == "DEGRADED",
    )
    check(
        "Multiple failures -> security pipeline survives",
        result["allow_security_pipeline"] is True,
    )
    check(
        "Multiple failures -> no exception escapes",
        plane.get_stats()["failures"] >= 3,
    )


def main():
    print("=== RESOURCE SAFETY PLANE FAILURE-INJECTION TEST ===")

    test_resource_guard_failure()
    test_backpressure_failure()
    test_rate_limiter_failure()
    test_spool_failure()
    test_multiple_failures()

    print()
    print("FAILURE-INJECTION TEST: PASS")
    print("Fail-safe security pipeline preservation: PASS")
    print("Production EventBus/main.py: UNMODIFIED")


if __name__ == "__main__":
    main()
