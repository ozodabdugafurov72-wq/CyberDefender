"""
CyberDefender — Correlation Ownership Diagnostic v1.5

Purpose:
    Verify the actual current CyberDefender repository contract.

Checks:
    1. EventBus accepts SecurityEvent.
    2. CorrelationAdapter is not an implicit EventBus subscriber.
    3. Canonical SecurityEvent does not directly enter CorrelationEngine.
    4. SecurityEventBridge converts SecurityEvent -> DETECTION.
    5. DETECTION is not implicitly consumed by CorrelationAdapter.
    6. Explicit main-style bridge -> adapter path processes exactly once.
    7. event_id is preserved through the bridge.
    8. INCIDENT does not recursively enter CorrelationEngine.
    9. ACK is disabled when no callback is supplied.
   10. EventBus shuts down cleanly.

This diagnostic does NOT modify CyberDefender source code.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# REAL CYBERDEFENDER IMPORTS
# ============================================================

from agent.bus.event_bus import EventBus
from agent.correlation.adapter import CorrelationAdapter
from agent.core.event_bridge import SecurityEventBridge
from agent.event import SecurityEvent


# ============================================================
# TEST PROBE
# ============================================================

class ProbeCorrelationEngine:
    """
    Deterministic probe replacing the real CorrelationEngine.

    The probe records every event received through ingest().
    """

    def __init__(self) -> None:
        self.received: list[Any] = []

    def ingest(self, event: Any) -> Any:
        self.received.append(event)
        return None


# ============================================================
# TEST RUNNER
# ============================================================

def main() -> int:
    passed = 0
    failed = 0

    def check(
        name: str,
        condition: bool,
        detail: str = "",
    ) -> None:
        nonlocal passed, failed

        if condition:
            passed += 1
            print(f"[PASS] {name}")
            return

        failed += 1

        suffix = (
            f" :: {detail}"
            if detail
            else ""
        )

        print(
            f"[FAIL] {name}{suffix}"
        )

    # ========================================================
    # INITIALIZE REAL COMPONENTS
    # ========================================================

    bus = EventBus(
        max_size=32,
        security_reserve=8,
    )

    engine = ProbeCorrelationEngine()

    adapter = CorrelationAdapter(
        engine=engine,
        event_bus=bus,
        ack_callback=None,
    )

    # ========================================================
    # TEST 1
    # Verify EventBus subscriber ownership.
    # ========================================================

    subscribers = getattr(
        bus,
        "_subscribers",
        None,
    )

    check(
        "EventBus subscriber registry is accessible for diagnostic",
        isinstance(subscribers, list),
        (
            f"type={type(subscribers).__name__}"
        ),
    )

    # Current repository contract:
    #
    # CorrelationAdapter receives event_bus as a dependency,
    # but does NOT automatically subscribe itself.

    check(
        "CorrelationAdapter is not an implicit EventBus subscriber",
        (
            isinstance(subscribers, list)
            and adapter.handle_event not in subscribers
        ),
        (
            f"subscriber_count="
            f"{len(subscribers) if isinstance(subscribers, list) else 'unknown'}"
        ),
    )

    # ========================================================
    # TEST 2
    # Canonical SecurityEvent path.
    # ========================================================

    event = SecurityEvent(
        event_type="RESOURCE_STATUS",
        severity="LOW",
        value={
            "cpu": 10.0,
            "memory": 20.0,
        },
        source="diagnostic",
        message="correlation ownership diagnostic",
        host_id="diagnostic-host",
    )

    published = bus.publish(
        event
    )

    check(
        "Canonical SecurityEvent publish accepted",
        published is True,
    )

    # EventBus publish() admits to queue.
    # dispatch_once() performs dispatch.

    bus.dispatch_once()

    check(
        "Canonical SecurityEvent does not enter CorrelationEngine",
        len(engine.received) == 0,
        (
            f"engine_received="
            f"{len(engine.received)}"
        ),
    )

    # ========================================================
    # TEST 3
    # SecurityEvent -> DETECTION bridge.
    # ========================================================

    detection = SecurityEventBridge.to_detection(
        event
    )

    check(
        "SecurityEventBridge produced DETECTION",
        (
            isinstance(detection, dict)
            and detection.get("event_type") == "DETECTION"
        ),
        (
            f"type="
            f"{type(detection).__name__}"
        ),
    )

    # ========================================================
    # TEST 4
    # DETECTION through EventBus.
    #
    # Because CorrelationAdapter is not an implicit subscriber,
    # this MUST NOT reach the engine automatically.
    # ========================================================

    published_detection = bus.publish(
        detection
    )

    check(
        "DETECTION publish accepted",
        published_detection is True,
    )

    bus.dispatch_once()

    check(
        "DETECTION is not implicitly consumed by CorrelationAdapter",
        len(engine.received) == 0,
        (
            f"engine_received="
            f"{len(engine.received)}"
        ),
    )

    # ========================================================
    # TEST 5
    # Actual main.py ownership path.
    #
    # Current main-style flow:
    #
    # SecurityEvent
    #       |
    #       v
    # SecurityEventBridge
    #       |
    #       v
    # DETECTION
    #       |
    #       v
    # CorrelationAdapter.handle_event()
    #       |
    #       v
    # CorrelationEngine
    #
    # Exactly one invocation is required.
    # ========================================================

    before = len(
        engine.received
    )

    adapter.handle_event(
        detection
    )

    check(
        "Explicit main-style bridge -> adapter path processes exactly once",
        len(engine.received) == before + 1,
        (
            f"before={before}, "
            f"after={len(engine.received)}"
        ),
    )

    # ========================================================
    # TEST 6
    # Verify CorrelationEngine receives DETECTION.
    # ========================================================

    received = (
        engine.received[-1]
        if engine.received
        else None
    )

    check(
        "CorrelationEngine receives DETECTION",
        (
            isinstance(received, dict)
            and received.get("event_type") == "DETECTION"
        ),
        (
            f"received={received!r}"
        ),
    )

    # ========================================================
    # TEST 7
    # Verify event_id integrity.
    # ========================================================

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

    # ========================================================
    # TEST 8
    # Explicit second bridge path.
    #
    # This confirms that main.py's direct:
    #
    #     bridge.to_detection()
    #     adapter.handle_event()
    #
    # is a single processing entry.
    # ========================================================

    second_event = SecurityEvent(
        event_type="TEST_DETECTION",
        severity="HIGH",
        value={
            "probe": True,
        },
        source="diagnostic",
        message="explicit main-style bridge path",
        host_id="diagnostic-host",
    )

    second_detection = (
        SecurityEventBridge.to_detection(
            second_event
        )
    )

    before = len(
        engine.received
    )

    adapter.handle_event(
        second_detection
    )

    check(
        "Second explicit bridge -> adapter path processes exactly once",
        len(engine.received) == before + 1,
        (
            f"before={before}, "
            f"after={len(engine.received)}"
        ),
    )

    explicit_received = (
        engine.received[-1]
        if engine.received
        else None
    )

    explicit_event_id = (
        explicit_received.get("event_id")
        if isinstance(explicit_received, dict)
        else None
    )

    check(
        "Second event_id preserved",
        explicit_event_id == second_event.event_id,
        (
            f"original={second_event.event_id!r}, "
            f"received={explicit_event_id!r}"
        ),
    )

    # ========================================================
    # TEST 9
    # INCIDENT recursion protection.
    # ========================================================

    before = len(
        engine.received
    )

    incident = {
        "event_type": "INCIDENT",
        "event_id": "diagnostic-incident-001",
        "severity": "HIGH",
        "data": {
            "reason": "ownership-test",
        },
    }

    adapter.handle_event(
        incident
    )

    check(
        "INCIDENT does not recurse into CorrelationEngine",
        len(engine.received) == before,
        (
            f"before={before}, "
            f"after={len(engine.received)}"
        ),
    )

    # ========================================================
    # TEST 10
    # ACK ownership.
    # ========================================================

    stats = adapter.get_stats()

    check(
        "CorrelationAdapter ACK is disabled",
        stats.get("ack_enabled") is False,
        (
            f"ack_enabled="
            f"{stats.get('ack_enabled')!r}"
        ),
    )

    # ========================================================
    # TEST 11
    # Clean lifecycle shutdown.
    # ========================================================

    bus.request_shutdown()

    check(
        "EventBus entered shutdown state",
        bus.is_shutdown_requested() is True,
    )

    # ========================================================
    # RESULT
    # ========================================================

    print()
    print("=" * 72)
    print(
        f"RESULT: PASS={passed} FAIL={failed}"
    )
    print("=" * 72)

    if failed:
        print()
        print(
            "CONCLUSION:"
        )
        print(
            "A current repository ownership invariant failed."
        )
        print(
            "Do NOT modify main.py until the failing check "
            "has been reviewed."
        )
        return 1

    print()
    print(
        "CONCLUSION:"
    )
    print(
        "No duplicate CorrelationEngine processing path "
        "was demonstrated."
    )
    print(
        "The current repository does not implicitly subscribe "
        "CorrelationAdapter to EventBus."
    )
    print(
        "Canonical SecurityEvent traffic does not directly "
        "enter CorrelationEngine."
    )
    print(
        "DETECTION is explicitly delivered through "
        "CorrelationAdapter.handle_event()."
    )
    print(
        "event_id integrity is preserved."
    )
    print(
        "INCIDENT does not recurse."
    )
    print(
        "ACK ownership remains outside CorrelationAdapter."
    )

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    raise SystemExit(
        main()
    )