"""CyberDefender EventBus v2.2 priority/security-reserve adversarial test."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.bus.event_bus import EventBus

PASS = 0
FAIL = 0


def check(label: str, condition: bool) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS | {label}")
    else:
        FAIL += 1
        print(f"FAIL | {label}")


def event(event_id: str, severity: str) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": "EVENTBUS_V2_2_ADVERSARIAL",
        "severity": severity,
        "source": "eventbus_v2_2_lab",
    }


def main() -> None:
    capacity = 8
    reserve = 2
    bus = EventBus(max_size=capacity, security_reserve=reserve)
    received: list[dict[str, Any]] = []
    bus.subscribe(received.append)

    print("=" * 68)
    print(" CYBERDEFENDER EVENTBUS v2.2 ADVERSARIAL TEST")
    print(" Priority-aware admission / Security reserve / Boundedness")
    print("=" * 68)

    stats = bus.get_stats()
    check("EventBus version is v2.4", stats["version"] == "2.4")
    check("Total capacity is bounded", stats["queue_capacity"] == capacity)
    check("Security reserve is configured", stats["security_reserve"] == reserve)
    check("General capacity is reserved", stats["general_capacity"] == capacity - reserve)

    # LOW/MEDIUM may fill only the general portion.
    low_ok = sum(bus.publish(event(f"low-{i}", "LOW")) for i in range(capacity))
    check("LOW admission stops at general capacity", low_ok == capacity - reserve)
    check("LOW/MEDIUM cannot consume security reserve", bus.size() == capacity - reserve)

    # Security evidence must survive the lower-priority saturation.
    critical_ok = bus.publish(event("critical-1", "CRITICAL"))
    high_ok = bus.publish(event("high-1", "HIGH"))
    check("CRITICAL admitted after LOW general saturation", critical_ok is True)
    check("HIGH admitted after LOW general saturation", high_ok is True)
    check("Queue reaches total capacity only with protected traffic", bus.size() == capacity)
    check("Queue never exceeds total capacity", bus.size() <= capacity)

    # Further low-value traffic must not evict or consume security capacity.
    check("Additional LOW rejected while protected capacity is occupied", bus.publish(event("low-overflow", "LOW")) is False)
    check("Additional MEDIUM rejected while queue is full", bus.publish(event("medium-overflow", "MEDIUM")) is False)

    # Full queue correctly rejects only after all bounded security capacity is occupied.
    check("Additional CRITICAL rejected only at true total saturation", bus.publish(event("critical-overflow", "CRITICAL")) is False)
    check("Additional HIGH rejected only at true total saturation", bus.publish(event("high-overflow", "HIGH")) is False)

    stats = bus.get_stats()
    check("Low/medium capacity rejection telemetry exists", stats["low_medium_capacity_rejects"] >= 2)
    check("Security capacity rejection telemetry exists", stats["security_capacity_rejects"] >= 2)

    # Priority dispatch: security evidence must leave before lower priority.
    dispatch_order: list[str] = []
    while bus.dispatch_once(timeout=0):
        pass
    # The subscriber list above recorded actual event dicts in received.
    dispatch_order = [item["severity"] for item in received]
    check("All admitted events dispatched", len(received) == capacity)
    check(
        "CRITICAL/HIGH dispatch before LOW",
        dispatch_order[:2] == ["CRITICAL", "HIGH"],
    )
    check(
        "LOW events retain FIFO ordering",
        [x["event_id"] for x in received[2:]] == [f"low-{i}" for i in range(capacity - reserve)],
    )

    # Recovery after controlled drain.
    check("Queue empty after controlled dispatch", bus.is_empty() is True)
    check("Queue no longer reports full after recovery", bus.is_full() is False)
    check("CRITICAL admitted after recovery", bus.publish(event("critical-after-recovery", "CRITICAL")) is True)
    check("CRITICAL can be dispatched after recovery", bus.dispatch_once(timeout=0) is True)
    check(
        "Recovered CRITICAL reaches subscriber",
        any(x["event_id"] == "critical-after-recovery" for x in received),
    )

    # Health contract.
    health = bus.health_check()
    check("Health check remains operational", health["status"] in {"HEALTHY", "DEGRADED"})
    check("Critical security preservation is explicit", health["critical_security_preservation"] is True)
    check("Security reserve remains bounded", health["security_reserve"] == reserve)
    check("Total queue remains bounded", health["queue_size"] <= health["queue_capacity"])

    print("\n" + "=" * 68)
    print(" EVENTBUS v2.2 ADVERSARIAL RESULT")
    print("=" * 68)
    print(f"PASS: {PASS}")
    print(f"FAIL: {FAIL}")
    print(f"Queue: {health['queue_size']}/{health['queue_capacity']}")
    print(f"Security reserve: {health['security_reserve']}")
    print("RESULT: PASS — v2.2 security-reserve contract verified" if FAIL == 0 else "RESULT: FAIL — v2.2 contract violated")

    if FAIL:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
