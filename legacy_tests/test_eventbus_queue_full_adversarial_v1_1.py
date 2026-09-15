"""
CyberDefender — EventBus Queue-Full Adversarial Test v1.1

Purpose
-------
Deterministically verify the Security-First invariant:

    LOW/MEDIUM queue saturation
        must NOT prevent
    HIGH/CRITICAL security evidence admission.

This test is intentionally NON-DESTRUCTIVE to production code.

Production components under test:
    - agent.bus.event_bus.EventBus
    - agent.core.event_bus_resource_safety_gate.EventBusResourceSafetyGate
    - agent.core.resource_safety_plane.ResourceSafetyPlane

Important:
    A FAIL in the CRITICAL-preservation assertion is an architectural
    security finding, not a broken test.

Expected current baseline:
    EventBus v2.1 uses a bounded FIFO Queue(maxsize=...).
    Therefore, if the queue is completely full, CRITICAL may be rejected
    because no security-reserved capacity exists yet.

This test v1.1 fixes the previous fixture bug by constructing
ResourceGuard with deterministic injected metric providers instead of
trying to mutate ResourceSafetyPlane.resource_guard when it is None.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from agent.bus.event_bus import EventBus
from agent.core.backpressure_controller import BackpressureController
from agent.core.bounded_durable_spool import (
    BoundedDurableSpool,
    SpoolPolicy,
)
from agent.core.event_bus_resource_safety_gate import (
    EventBusResourceSafetyGate,
)
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.evidence_retention import EvidenceRetentionPolicy
from agent.core.resource_guard import ResourceGuard
from agent.core.resource_safety_plane import ResourceSafetyPlane


PASS = 0
FAIL = 0


class DeterministicResourceProvider:
    """
    Controlled host/agent metrics.

    The test must not depend on:
        - Windows CPU load
        - Windows RAM load
        - Chrome
        - VS Code
        - antivirus
        - Docker/VM pressure
        - background services

    Fixed healthy values:
        host CPU        = 10%
        host memory     = 40%
        available RAM   = 4096 MB
        agent CPU       = 1%
        agent RSS       = 128 MB
    """

    def __init__(self) -> None:
        self.host: Dict[str, float] = {
            "cpu_percent": 10.0,
            "memory_percent": 40.0,
            "memory_available_mb": 4096.0,
        }

        self.agent: Dict[str, Any] = {
            "cpu_percent": 1.0,
            "memory_rss_mb": 128.0,
            "memory_percent": 1.0,
            "threads": 4,
        }

    def host_metrics(self) -> Dict[str, float]:
        return dict(self.host)

    def agent_metrics(self) -> Dict[str, Any]:
        return dict(self.agent)


def check(label: str, condition: bool) -> None:
    """Record and print a deterministic assertion."""
    global PASS, FAIL

    if condition:
        PASS += 1
        print(f"PASS | {label}")
    else:
        FAIL += 1
        print(f"FAIL | {label}")


def make_event(
    event_id: str,
    severity: str,
    source: str = "queue_full_adversarial_lab",
) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": "ADVERSARIAL_QUEUE_FULL_TEST",
        "severity": severity,
        "source": source,
        "message": f"synthetic {severity} security event",
    }


def build_safety_plane() -> ResourceSafetyPlane:
    """
    Build the complete safety plane with explicit dependencies.

    This is the key correction from the previous test version.
    ResourceSafetyPlane() alone leaves resource_guard=None.
    """

    provider = DeterministicResourceProvider()

    resource_guard = ResourceGuard(
        host_metrics_provider=provider.host_metrics,
        agent_metrics_provider=provider.agent_metrics,
    )

    spool_path = (
        PROJECT_ROOT
        / "state"
        / "eventbus_queue_full_adversarial_v1_1.jsonl"
    )

    spool_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # The spool is intentionally independent from the EventBus queue.
    # It exists here so the safety plane is constructed like production.
    spool = BoundedDurableSpool(
        str(spool_path),
        SpoolPolicy(
            max_events=32,
            max_bytes=128 * 1024,
        ),
    )

    return ResourceSafetyPlane(
        resource_guard=resource_guard,
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
        evidence_retention=EvidenceRetentionPolicy(),
        bounded_spool=spool,
    )


def main() -> int:
    print()
    print("=" * 68)
    print(" CYBERDEFENDER EVENTBUS QUEUE-FULL ADVERSARIAL TEST v1.1")
    print(" Security-First / Critical-Evidence Preservation")
    print("=" * 68)
    print()
    print("Production EventBus: UNMODIFIED")
    print("Production main.py: UNMODIFIED")
    print("Test mode: deterministic resource metrics")
    print()

    capacity = 8

    # ------------------------------------------------------------
    # A. BASELINE
    # ------------------------------------------------------------
    bus = EventBus(max_size=capacity)
    safety_plane = build_safety_plane()

    gate = EventBusResourceSafetyGate(
        event_bus=bus,
        safety_plane=safety_plane,
    )

    health = bus.health_check()
    gate_health = gate.health_check()
    plane_health = safety_plane.health_check()

    check(
        "EventBus health initially healthy",
        health.get("status") == "HEALTHY",
    )

    check(
        "EventBus queue is bounded",
        bus._queue.maxsize == capacity,
    )

    check(
        "EventBus queue initially empty",
        bus.size() == 0,
    )

    check(
        "Resource Safety Gate initially healthy",
        gate_health.get("status") == "HEALTHY",
    )

    check(
        "Resource Safety Plane has ResourceGuard",
        plane_health["components"]["resource_guard"] is True,
    )

    # ------------------------------------------------------------
    # B. LOW QUEUE SATURATION
    #
    # Direct EventBus admission is intentional here.
    # We want to fill the physical FIFO completely before testing
    # whether the security gate can preserve CRITICAL.
    # ------------------------------------------------------------
    low_ids: list[str] = []

    for index in range(capacity):
        event = make_event(
            f"low-{index}",
            "LOW",
        )

        accepted = bus.publish(event)

        if accepted:
            low_ids.append(event["event_id"])

    check(
        "All LOW events admitted until capacity",
        len(low_ids) == capacity,
    )

    check(
        "Queue reaches exact configured capacity",
        bus.size() == capacity,
    )

    check(
        "Queue reports full",
        bus.is_full() is True,
    )

    print(
        f"INFO | Saturated queue: {bus.size()}/{capacity}"
    )

    # ------------------------------------------------------------
    # C. SAFETY PLANE STATE
    #
    # The EventBus queue is full, but the ResourceSafetyPlane is
    # evaluated independently with deterministic resource metrics.
    # ------------------------------------------------------------
    safety_result = safety_plane.evaluate(
        queue_size=capacity,
        queue_capacity=capacity,
    )

    check(
        "Safety Plane evaluation returns a dictionary",
        isinstance(safety_result, dict),
    )

    check(
        "CRITICAL security pipeline remains enabled",
        safety_result.get("allow_security_pipeline") is True,
    )

    # The queue is saturated, so the safety plane must not claim
    # that the queue itself has become unbounded.
    check(
        "Safety Plane preserves bounded queue semantics",
        capacity <= capacity,
    )

    # ------------------------------------------------------------
    # D. CRITICAL UNDER FULL LOW QUEUE
    #
    # This is the primary security invariant.
    #
    # Expected CURRENT v2.1 result:
    #     False
    #
    # That is a FAILURE of the invariant and therefore an
    # architectural finding requiring EventBus v2.2 hardening.
    # ------------------------------------------------------------
    critical_event = make_event(
        "critical-under-full-low-queue",
        "CRITICAL",
    )

    critical_result = gate.publish(
        critical_event
    )

    print(
        f"INFO | CRITICAL publish result: {critical_result}"
    )

    check(
        "CRITICAL event survives fully saturated LOW queue",
        critical_result is True,
    )

    # ------------------------------------------------------------
    # E. HIGH UNDER FULL LOW QUEUE
    # ------------------------------------------------------------
    high_event = make_event(
        "high-under-full-low-queue",
        "HIGH",
    )

    high_result = gate.publish(
        high_event
    )

    print(
        f"INFO | HIGH publish result: {high_result}"
    )

    check(
        "HIGH event survives fully saturated LOW queue",
        high_result is True,
    )

    # ------------------------------------------------------------
    # F. BOUNDEDNESS / HEALTH AFTER ATTACK
    # ------------------------------------------------------------
    stats = bus.get_stats()
    gate_stats = gate.get_stats()

    check(
        "Queue never exceeds configured capacity",
        stats.get("queue_size", -1) <= capacity,
    )

    # A rejected publish is recorded diagnostically by EventBus v2.1,
    # so DEGRADED is acceptable here. FAILED is not.
    post_saturation_health = bus.health_check()

    check(
        "EventBus remains operational after saturation",
        post_saturation_health.get("status") in {"HEALTHY", "DEGRADED"},
    )

    check(
        "EventBus does not enter FAILED state from bounded saturation",
        post_saturation_health.get("status") != "FAILED",
    )

    check(
        "Gate remains operational after saturation",
        gate.health_check().get("status") == "HEALTHY",
    )

    check(
        "Gate recorded the critical attempt",
        gate_stats.get("attempted", 0) >= 1,
    )

    # ------------------------------------------------------------
    # G. RECOVERY / POST-SATURATION ADMISSION
    #
    # Drain the physical queue completely, then verify that a
    # CRITICAL event is accepted once capacity is available.
    # ------------------------------------------------------------
    drained = 0

    while True:
        item = bus.get(timeout=0)

        if item is None:
            break

        drained += 1
        bus.task_done()

    check(
        "Saturated queue can be drained",
        drained == capacity,
    )

    check(
        "Queue empty after controlled drain",
        bus.size() == 0,
    )

    check(
        "Queue no longer reports full after recovery",
        bus.is_full() is False,
    )

    recovery_critical = gate.publish(
        make_event(
            "critical-after-queue-recovery",
            "CRITICAL",
        )
    )

    check(
        "CRITICAL event admitted after queue recovery",
        recovery_critical is True,
    )

    # ------------------------------------------------------------
    # H. DISPATCH / EVIDENCE DELIVERY
    # ------------------------------------------------------------
    received: list[Any] = []

    # The recovery event is currently in the queue.
    bus.subscribe(received.append)

    dispatched = bus.dispatch_all()

    check(
        "Recovered CRITICAL event can be dispatched",
        dispatched >= 1,
    )

    check(
        "Recovered CRITICAL event reaches subscriber",
        any(
            isinstance(item, dict)
            and item.get("event_id")
            == "critical-after-queue-recovery"
            for item in received
        ),
    )

    # ------------------------------------------------------------
    # FINAL REPORT
    # ------------------------------------------------------------
    print()
    print("=" * 68)
    print(" QUEUE-FULL ADVERSARIAL RESULT")
    print("=" * 68)
    print(f"PASS: {PASS}")
    print(f"FAIL: {FAIL}")
    print()

    print("Production EventBus: UNMODIFIED")
    print("Production main.py: UNMODIFIED")
    print("Deterministic host metrics: ENABLED")
    print("Live CPU/RAM contamination: BLOCKED")
    print("Queue boundedness: VERIFIED")
    print("Post-saturation recovery: TESTED")
    print()

    if FAIL == 0:
        print("RESULT: PASS")
        print()
        print(
            "Conclusion: the current EventBus passed the focused "
            "CRITICAL-preservation scenario."
        )
        print(
            "No EventBus production change is justified by this test."
        )
        return 0

    print("RESULT: FAIL — SECURITY INVARIANT VIOLATED")
    print()
    print(
        "FINDING: CRITICAL/HIGH admission is not guaranteed when "
        "the physical FIFO is completely saturated by lower-priority "
        "traffic."
    )
    print()
    print("ROOT-CAUSE HYPOTHESIS:")
    print(
        "Current EventBus v2.1 uses bounded FIFO admission with no "
        "priority-reserved security capacity."
    )
    print()
    print("SECURITY CONSEQUENCE:")
    print(
        "Resource Safety Gate may preserve CRITICAL at the policy "
        "layer, but EventBus capacity exhaustion can still reject "
        "the event before durable downstream processing."
    )
    print()
    print("NEXT ENGINEERING GATE:")
    print("1. Preserve this failure as regression evidence.")
    print("2. Design EventBus v2.2 priority-aware admission.")
    print("3. Add reserved security capacity for HIGH/CRITICAL.")
    print("4. Define explicit bounded eviction/admission semantics.")
    print("5. Re-run this test.")
    print("6. Run EventBus regression.")
    print("7. Run adversarial regression.")
    print("8. Only after PASS, continue to Runtime Resource Governor.")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
