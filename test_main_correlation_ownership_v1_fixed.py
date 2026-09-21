"""CyberDefender — Correlation ownership compatibility diagnostic.

Aligned with the current explicit runtime ownership contract:
SecurityEvent -> SecurityEventBridge -> DETECTION -> CorrelationAdapter.handle_event().
The adapter is not an implicit EventBus subscriber and ACK ownership remains with
its caller when no ack_callback is configured.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.bus.event_bus import EventBus
from agent.correlation.adapter import CorrelationAdapter
from agent.correlation.engine import CorrelationEngine
from agent.core.event_bridge import SecurityEventBridge
from agent.event import SecurityEvent


class ProbeCorrelationEngine(CorrelationEngine):
    """Real contract plus deterministic observation of ingest calls."""

    def __init__(self) -> None:
        super().__init__()
        self.received: list[Any] = []

    def ingest(self, event: Any, **kwargs) -> Any:
        self.received.append(event)
        return super().ingest(event, **kwargs)


def main() -> int:
    passed = 0
    failed = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"[PASS] {name}")
        else:
            failed += 1
            suffix = f" :: {detail}" if detail else ""
            print(f"[FAIL] {name}{suffix}")

    bus = EventBus(max_size=32, security_reserve=8)
    engine = ProbeCorrelationEngine()
    adapter = CorrelationAdapter(engine=engine, event_bus=bus, ack_callback=None)

    subscribers = getattr(bus, "_subscribers", None)
    check(
        "CorrelationAdapter is not an implicit EventBus subscriber",
        isinstance(subscribers, list) and adapter.handle_event not in subscribers,
        f"subscribers={subscribers!r}",
    )

    event = SecurityEvent(
        event_type="RESOURCE_STATUS",
        severity="LOW",
        value={"cpu": 10.0, "memory": 20.0},
        source="diagnostic",
        message="correlation ownership compatibility diagnostic",
        host_id="diagnostic-host",
    )

    check("SecurityEvent publish accepted", bus.publish(event) is True)
    bus.dispatch_once()
    check(
        "SecurityEvent does not directly enter correlation",
        len(engine.received) == 0,
        f"received={len(engine.received)}",
    )

    detection = SecurityEventBridge.to_detection(event)
    check(
        "Bridge produced DETECTION",
        isinstance(detection, dict) and detection.get("event_type") == "DETECTION",
        f"detection={detection!r}",
    )

    before = len(engine.received)
    result = adapter.handle_event(detection)
    check("Explicit adapter consumption succeeds", result is True, f"result={result!r}")
    check(
        "Bridged DETECTION reaches correlation exactly once",
        len(engine.received) == before + 1,
        f"before={before}, after={len(engine.received)}",
    )

    received = engine.received[-1] if engine.received else None
    check(
        "event_id preserved through bridge",
        isinstance(received, dict) and received.get("event_id") == event.event_id,
        f"received={received!r}",
    )

    before = len(engine.received)
    incident_result = adapter.handle_event(
        {
            "event_type": "INCIDENT",
            "event_id": "diagnostic-incident-001",
            "severity": "HIGH",
            "data": {"reason": "ownership-test"},
        }
    )
    check("INCIDENT is rejected by correlation adapter", incident_result is False)
    check(
        "INCIDENT does not recurse into correlation",
        len(engine.received) == before,
        f"before={before}, after={len(engine.received)}",
    )

    stats = adapter.get_stats()
    check("ACK ownership remains external", stats.get("ack_enabled") is False, f"stats={stats!r}")

    bus.request_shutdown()
    check("EventBus entered shutdown state", bus.is_shutdown_requested() is True)

    print()
    print("=" * 72)
    print(f"RESULT: PASS={passed} FAIL={failed}")
    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
