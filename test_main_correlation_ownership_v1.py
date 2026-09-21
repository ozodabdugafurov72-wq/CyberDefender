"""CyberDefender — Correlation ownership diagnostic v1.5.

This diagnostic is aligned with the actual current repository implementation.

It verifies:
- EventBus accepts SecurityEvent.
- CorrelationAdapter is NOT an implicit EventBus subscriber in the current
  implementation.
- A DETECTION dictionary is therefore not consumed by the adapter unless the
  runtime explicitly calls adapter.handle_event().
- SecurityEventBridge preserves event_id.
- The main-style explicit bridge -> adapter path processes exactly once.
- INCIDENT input does not recurse into CorrelationEngine.
- ACK is disabled when no callback is supplied.

This test does not modify CyberDefender source files.
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
    """Deterministic probe aligned with the current strict ingest contract."""

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
            return

        failed += 1
        suffix = f" :: {detail}" if detail else ""
        print(f"[FAIL] {name}{suffix}")

    bus = EventBus(max_size=32, security_reserve=8)
    engine = ProbeCorrelationEngine()

    adapter = CorrelationAdapter(
        engine=engine,
        event_bus=bus,
        ack_callback=None,
    )

    # ------------------------------------------------------------------
    # 1. Verify that the adapter does not silently register itself as an
    #    EventBus subscriber.
    #
    #    This is an implementation-level ownership assertion, not a guess.
    # ------------------------------------------------------------------
    subscribers = getattr(bus, "_subscribers", None)

    check(
        "EventBus subscriber registry is accessible for diagnostic",
        isinstance(subscribers, list),
        f"type={type(subscribers).__name__}",
    )

    check(
        "CorrelationAdapter is not an implicit EventBus subscriber",
        isinstance(subscribers, list) and adapter.handle_event not in subscribers,
        f"subscriber_count={len(subscribers) if isinstance(subscribers, list) else 'unknown'}",
    )

    # ------------------------------------------------------------------
    # 2. Canonical SecurityEvent can enter EventBus, but it must not
    #    directly invoke CorrelationEngine.
    # ------------------------------------------------------------------
    event = SecurityEvent(
        event_type="RESOURCE_STATUS",
        severity="LOW",
        value={"cpu": 10.0, "memory": 20.0},
        source="diagnostic",
        message="correlation ownership diagnostic",
        host_id="diagnostic-host",
    )

    check(
        "Canonical SecurityEvent publish accepted",
        bus.publish(event) is True,
    )

    bus.dispatch_once()

    check(
        "Canonical SecurityEvent does not enter CorrelationEngine",
        len(engine.received) == 0,
        f"engine_received={len(engine.received)}",
    )

    # ------------------------------------------------------------------
    # 3. A DETECTION dictionary also does not enter CorrelationEngine
    #    automatically because the adapter is not subscribed.
    # ------------------------------------------------------------------
    detection = SecurityEventBridge.to_detection(event)

    check(
        "SecurityEventBridge produced DETECTION",
        isinstance(detection, dict)
        and detection.get("event_type") == "DETECTION",
    )

    check(
        "DETECTION publish accepted",
        bus.publish(detection) is True,
    )

    bus.dispatch_once()

    check(
        "DETECTION is not implicitly consumed by CorrelationAdapter",
        len(engine.received) == 0,
        f"engine_received={len(engine.received)}",
    )

    # ------------------------------------------------------------------
    # 4. This is the actual main.py ownership path:
    #
    #     SecurityEvent
    #         -> EventBridge.to_detection()
    #         -> correlation_adapter.handle_event()
    #
    #    Verify exactly one engine invocation.
    # ------------------------------------------------------------------
    before = len(engine.received)

    adapter.handle_event(detection)

    check(
        "Explicit main-style bridge -> adapter path processes exactly once",
        len(engine.received) == before + 1,
        f"before={before}, after={len(engine.received)}",
    )

    received = engine.received[-1] if engine.received else None

    check(
        "CorrelationEngine receives DETECTION",
        isinstance(received, dict)
        and received.get("event_type") == "DETECTION",
        f"received={received!r}",
    )

    received_event_id = (
        received.get("event_id")
        if isinstance(received, dict)
        else None
    )

    check(
        "event_id preserved through bridge",
        received_event_id == event.event_id,
        (
            f"original={event.event_id!r}, "
            f"received={received_event_id!r}"
        ),
    )

    # ------------------------------------------------------------------
    # 5. INCIDENT must not recurse into correlation.
    # ------------------------------------------------------------------
    before = len(engine.received)

    adapter.handle_event(
        {
            "event_type": "INCIDENT",
            "event_id": "diagnostic-incident-001",
            "severity": "HIGH",
            "data": {"reason": "ownership-test"},
        }
    )

    check(
        "INCIDENT does not recurse into CorrelationEngine",
        len(engine.received) == before,
        f"before={before}, after={len(engine.received)}",
    )

    # ------------------------------------------------------------------
    # 6. ACK ownership.
    # ------------------------------------------------------------------
    stats = adapter.get_stats()

    check(
        "CorrelationAdapter ACK is disabled",
        stats.get("ack_enabled") is False,
        f"stats={stats!r}",
    )

    # ------------------------------------------------------------------
    # 7. Clean EventBus lifecycle transition.
    # ------------------------------------------------------------------
    bus.request_shutdown()

    check(
        "EventBus entered shutdown state",
        bus.is_shutdown_requested() is True,
    )

    print()
    print("=" * 72)
    print(f"RESULT: PASS={passed} FAIL={failed}")
    print("=" * 72)

    if failed:
        print(
            "CONCLUSION: A current repository ownership invariant failed. "
            "Do not change main.py until the failing check is reviewed."
        )
        return 1

    print(
        "CONCLUSION: No duplicate CorrelationEngine processing path was "
        "demonstrated. In the current repository, CorrelationAdapter is "
        "not an EventBus subscriber; main.py explicitly converts trusted "
        "SecurityEvent -> DETECTION and calls adapter.handle_event() once."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
