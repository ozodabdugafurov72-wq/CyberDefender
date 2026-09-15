"""
CyberDefender - Correlation Ownership Diagnostic v1.1

Run from the CyberDefender project root:

    .venv/Scripts/python.exe test_main_correlation_ownership_v1_fixed.py

Purpose:
- Verify that a real SecurityEvent published to EventBus is not consumed
  directly by CorrelationAdapter.
- Verify that the explicit SecurityEvent -> DETECTION bridge path reaches
  CorrelationAdapter exactly once.
- Verify event_id preservation.
- Verify INCIDENT events do not recursively create another DETECTION.
- Verify CorrelationAdapter ACK is disabled in this wiring, so main/runtime
  remains the ACK owner.

This is a diagnostic test only. It does not modify CyberDefender source files.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Make imports reliable when the script is launched from the project root.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.bus.event_bus import EventBus
from agent.correlation.adapter import CorrelationAdapter
from agent.core.event_bridge import SecurityEventBridge
from agent.event import SecurityEvent


class ProbeCorrelationEngine:
    """Minimal probe replacing the real correlation engine for this test."""

    def __init__(self) -> None:
        self.received: list[Any] = []

    def ingest(self, event: Any) -> Any:
        self.received.append(event)
        return None


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

    bus = EventBus(32)
    engine = ProbeCorrelationEngine()

    # CorrelationAdapter subscribes itself to EventBus.
    adapter = CorrelationAdapter(
        event_bus=bus,
        correlation_engine=engine,
    )

    # 1. Publish a canonical SecurityEvent.
    security_event = SecurityEvent(
        event_type="RESOURCE_STATUS",
        source="diagnostic",
        severity="LOW",
        payload={"cpu": 10.0, "memory": 20.0},
    )

    published = bus.publish(security_event)

    check("SecurityEvent publish accepted", published is True)

    # CorrelationAdapter currently handles dict events whose event_type is
    # DETECTION. A canonical SecurityEvent must therefore not be processed
    # directly by that subscriber.
    check(
        "Direct SecurityEvent does not reach CorrelationAdapter",
        len(engine.received) == 0,
        f"engine_received={len(engine.received)}",
    )

    # 2. Explicit bridge conversion: SecurityEvent -> DETECTION.
    detection = SecurityEventBridge.to_detection(security_event)

    check(
        "Bridge produced DETECTION",
        isinstance(detection, dict) and detection.get("event_type") == "DETECTION",
        f"detection={detection!r}",
    )

    adapter.handle_event(detection)

    check(
        "Bridged DETECTION reaches CorrelationAdapter exactly once",
        len(engine.received) == 1,
        f"engine_received={len(engine.received)}",
    )

    # 3. event_id must survive the bridge.
    received = engine.received[0] if engine.received else None
    received_event_id = (
        received.get("event_id") if isinstance(received, dict) else None
    )

    check(
        "event_id preserved through bridge",
        received_event_id == security_event.event_id,
        f"original={security_event.event_id!r}, received={received_event_id!r}",
    )

    # 4. INCIDENT must not be turned into another DETECTION by this adapter.
    before_incident = len(engine.received)

    incident = {
        "event_type": "INCIDENT",
        "event_id": "diagnostic-incident-001",
        "severity": "HIGH",
        "payload": {"reason": "ownership-test"},
    }
    adapter.handle_event(incident)

    check(
        "INCIDENT does not recursively create DETECTION",
        len(engine.received) == before_incident,
        f"before={before_incident}, after={len(engine.received)}",
    )

    # 5. ACK ownership.
    ack_enabled = bool(getattr(adapter, "ack_enabled", False))

    check(
        "CorrelationAdapter ACK is disabled",
        ack_enabled is False,
        f"ack_enabled={ack_enabled!r}",
    )

    # Cleanup.
    try:
        bus.request_shutdown("diagnostic-test-complete")
    except Exception as exc:
        print(f"[WARN] EventBus shutdown raised: {exc!r}")

    print()
    print("=" * 64)
    print(f"RESULT: PASS={passed} FAIL={failed}")
    print("=" * 64)

    if failed == 0:
        print(
            "CONCLUSION: No current duplicate-processing bug was demonstrated. "
            "The CorrelationAdapter EventBus subscription is redundant/ambiguous "
            "for canonical SecurityEvent traffic, while the explicit bridge path "
            "is the active DETECTION path. ACK ownership remains outside the adapter."
        )
        return 0

    print(
        "CONCLUSION: Diagnostic failure detected. Do not change the architecture "
        "until the failing check is inspected."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
