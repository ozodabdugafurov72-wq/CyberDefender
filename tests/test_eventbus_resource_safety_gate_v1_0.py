"""
CyberDefender EventBus + Resource Safety Gate v1.0

Focused integration test.

Production EventBus/main.py are intentionally NOT modified by this test.
The gate is tested as a compatibility layer around the existing EventBus.
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
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.evidence_retention import EvidenceRetentionPolicy
from agent.core.resource_guard import ResourceGuard
from agent.core.resource_safety_plane import ResourceSafetyPlane
from agent.core.event_bus_resource_safety_gate import (
    EventBusResourceSafetyGate,
)


class SyntheticResourceProvider:
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

    def pressure(
        self,
        cpu: float,
        memory: float,
        available_mb: float,
    ) -> None:
        self.host.update(
            {
                "cpu_percent": float(cpu),
                "memory_percent": float(memory),
                "memory_available_mb": float(available_mb),
            }
        )


def check(label: str, condition: bool) -> None:
    print(
        f"{'PASS' if condition else 'FAIL'} | {label}"
    )
    if not condition:
        raise AssertionError(label)


def build_gate(
    bus: EventBus,
    provider: SyntheticResourceProvider,
) -> EventBusResourceSafetyGate:
    guard = ResourceGuard(
        host_metrics_provider=provider.host_metrics,
        agent_metrics_provider=provider.agent_metrics,
    )

    spool = BoundedDurableSpool(
        str(
            PROJECT_ROOT
            / "state"
            / "eventbus_resource_gate_test.jsonl"
        ),
        SpoolPolicy(
            max_events=32,
            max_bytes=128 * 1024,
        ),
    )

    plane = ResourceSafetyPlane(
        resource_guard=guard,
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
        evidence_retention=EvidenceRetentionPolicy(),
        bounded_spool=spool,
    )

    return EventBusResourceSafetyGate(
        event_bus=bus,
        safety_plane=plane,
    )


def main() -> None:
    print("=== EVENTBUS + RESOURCE SAFETY GATE v1.0 ===")

    provider = SyntheticResourceProvider()
    bus = EventBus(max_size=32)
    received: list[Any] = []

    bus.subscribe(received.append)

    gate = build_gate(bus, provider)

    health = gate.health_check()
    check("Gate health initially healthy", health["status"] == "HEALTHY")
    check("Gate is bounded", health["bounded"] is True)
    check(
        "Critical preservation invariant",
        health["critical_security_preservation"] is True,
    )

    # ---------------------------------------------------------
    # NORMAL
    # ---------------------------------------------------------
    check(
        "NORMAL low event admitted",
        gate.publish(
            {
                "event_type": "TEST_LOW",
                "severity": "INFO",
                "source": "IntegrationTest",
            }
        ) is True,
    )

    # ---------------------------------------------------------
    # CRITICAL RESOURCE PRESSURE
    # ResourceGuard needs sustained confirmations. Feed enough
    # samples to reach CRITICAL deterministically.
    # ---------------------------------------------------------
    provider.pressure(
        cpu=98.0,
        memory=98.0,
        available_mb=128.0,
    )

    for _ in range(5):
        gate.publish(
            {
                "event_type": "RESOURCE_PRESSURE_PROBE",
                "severity": "CRITICAL",
                "source": "IntegrationTest",
            }
        )

    # A direct critical event must remain admissible.
    critical_ok = gate.publish(
        {
            "event_type": "CRITICAL_SECURITY_TEST",
            "severity": "CRITICAL",
            "source": "IntegrationTest",
        }
    )
    check(
        "CRITICAL event survives resource pressure",
        critical_ok is True,
    )

    # LOW may be throttled once CRITICAL is established.
    low_result = gate.publish(
        {
            "event_type": "LOW_VALUE_TELEMETRY",
            "severity": "INFO",
            "source": "IntegrationTest",
        }
    )
    check(
        "LOW event is never required to survive CRITICAL",
        low_result is False,
    )

    # HIGH remains protected.
    high_result = gate.publish(
        {
            "event_type": "HIGH_SECURITY_TEST",
            "severity": "HIGH",
            "source": "IntegrationTest",
        }
    )
    check(
        "HIGH event remains protected",
        high_result is True,
    )

    # ---------------------------------------------------------
    # EVENTBUS DISPATCH
    # ---------------------------------------------------------
    dispatched = 0
    while bus.dispatch_once(timeout=0):
        dispatched += 1

    check(
        "EventBus dispatch remains functional",
        dispatched > 0,
    )

    check(
        "Critical event reached subscriber",
        any(
            isinstance(item, dict)
            and item.get("event_type") == "CRITICAL_SECURITY_TEST"
            for item in received
        ),
    )

    stats = gate.get_stats()
    check(
        "Gate recorded attempts",
        stats["attempted"] > 0,
    )
    check(
        "No gate internal failures",
        stats["failures"] == 0,
    )

    bus_health = bus.health_check()
    check(
        "EventBus remains healthy",
        bus_health["status"] == "HEALTHY",
    )

    print()
    print("EVENTBUS + RESOURCE SAFETY GATE: PASS")
    print("Production EventBus implementation: UNMODIFIED")
    print("Production main.py: UNMODIFIED")


if __name__ == "__main__":
    main()
