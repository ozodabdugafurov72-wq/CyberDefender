"""
CyberDefender — EventBus Queue-Full Adversarial Test v1.0

Purpose:
- Prove whether the current bounded EventBus can preserve HIGH/CRITICAL
  security events when the FIFO queue is already full of LOW/MEDIUM events.
- DO NOT modify production EventBus.
- FAIL is an architectural finding, not a test-framework failure.

Expected decision:
PASS -> current EventBus has sufficient admission behavior for this scenario.
FAIL -> root cause is lack of priority-aware reserved capacity/admission.
        Only then should EventBus v2.2 hardening be designed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from agent.bus.event_bus import EventBus
from agent.core.event_bus_resource_safety_gate import EventBusResourceSafetyGate
from agent.core.resource_safety_plane import ResourceSafetyPlane


PASS = 0
FAIL = 0


def check(name: str, condition: bool) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS | {name}")
    else:
        FAIL += 1
        print(f"FAIL | {name}")


def make_event(event_id: str, severity: str) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": "ADVERSARIAL_QUEUE_TEST",
        "severity": severity,
        "source": "queue_full_adversarial_lab",
        "message": f"synthetic {severity} event",
    }


def build_plane() -> ResourceSafetyPlane:
    """
    Deterministic healthy resource provider.

    This prevents the test result from depending on the real machine's
    CPU/RAM pressure.
    """
    plane = ResourceSafetyPlane()

    plane.resource_guard._host_metrics_provider = lambda: {
        "cpu_percent": 10.0,
        "memory_percent": 30.0,
        "available_memory_mb": 4096.0,
    }

    plane.resource_guard._agent_metrics_provider = lambda: {
        "cpu_percent": 1.0,
        "rss_mb": 128.0,
    }

    return plane


def main() -> int:
    print()
    print("=== EVENTBUS QUEUE-FULL ADVERSARIAL TEST v1.0 ===")
    print("Production EventBus: UNMODIFIED")
    print("Production main.py: UNMODIFIED")
    print("Test mode: deterministic resource metrics")
    print()

    # Small queue makes saturation deterministic and cheap.
    capacity = 8
    bus = EventBus(max_size=capacity)
    plane = build_plane()

    gate = EventBusResourceSafetyGate(
        event_bus=bus,
        resource_safety_plane=plane,
    )

    check(
        "Initial EventBus health is available",
        bus.health_check().get("status") in {"HEALTHY", "DEGRADED"},
    )

    # ------------------------------------------------------------
    # A. Fill the bounded FIFO queue with LOW/MEDIUM traffic.
    # ------------------------------------------------------------
    low_ids = []
    for i in range(capacity):
        event = make_event(f"low-{i}", "LOW")
        accepted = bus.publish(event)
        if accepted:
            low_ids.append(event["event_id"])

    stats = bus.get_stats()

    check(
        "Bounded queue reached configured capacity",
        stats.get("queue_size") == capacity,
    )

    check(
        "Low/medium saturation did not exceed queue capacity",
        stats.get("queue_size", -1) <= capacity,
    )

    # ------------------------------------------------------------
    # B. Attack the saturated queue through the Resource Safety Gate.
    # ------------------------------------------------------------
    high_event = make_event("high-under-saturation", "HIGH")
    critical_event = make_event("critical-under-saturation", "CRITICAL")

    high_result = gate.publish(high_event)
    critical_result = gate.publish(critical_event)

    check(
        "HIGH admission decision is observable",
        isinstance(high_result, bool),
    )

    check(
        "CRITICAL admission decision is observable",
        isinstance(critical_result, bool),
    )

    # ------------------------------------------------------------
    # C. The key security invariant.
    #
    # If CRITICAL is rejected while the FIFO is full, this is a real
    # architectural gap: the gate can authorize CRITICAL, but the
    # underlying EventBus has no reserved capacity.
    # ------------------------------------------------------------
    if critical_result:
        print("INFO | CRITICAL event was admitted while queue was full")
    else:
        print(
            "INFO | CRITICAL event was rejected while queue was full; "
            "this is the suspected priority-reservation gap"
        )

    check(
        "CRITICAL event survives a LOW/MEDIUM queue-full condition",
        critical_result is True,
    )

    # ------------------------------------------------------------
    # D. Verify boundedness and non-corruption.
    # ------------------------------------------------------------
    final_stats = bus.get_stats()

    check(
        "EventBus queue remains bounded",
        final_stats.get("queue_size", -1) <= capacity,
    )

    check(
        "EventBus remains operational after saturation attack",
        bus.health_check().get("status") in {"HEALTHY", "DEGRADED"},
    )

    # ------------------------------------------------------------
    # E. Recovery: drain queue and prove admission works again.
    # ------------------------------------------------------------
    drained = 0
    while True:
        item = bus.get()
        if item is None:
            break
        drained += 1

    check(
        "Queue can be drained after saturation",
        drained == len(low_ids),
    )

    recovery_critical = gate.publish(
        make_event("critical-after-recovery", "CRITICAL")
    )

    check(
        "CRITICAL event is admitted after queue recovery",
        recovery_critical is True,
    )

    # ------------------------------------------------------------
    # Final report
    # ------------------------------------------------------------
    print()
    print("=== QUEUE-FULL ADVERSARIAL RESULT ===")
    print(f"PASS: {PASS}")
    print(f"FAIL: {FAIL}")

    if FAIL == 0:
        print("RESULT: PASS")
        print(
            "Conclusion: current EventBus passed this focused "
            "priority-preservation scenario."
        )
        return 0

    print("RESULT: FAIL")
    print(
        "Conclusion: current bounded FIFO EventBus cannot guarantee "
        "CRITICAL preservation when saturated by lower-priority traffic."
    )
    print(
        "Next engineering step: root-cause review, then EventBus v2.2 "
        "priority reservation/admission hardening — only if confirmed."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
