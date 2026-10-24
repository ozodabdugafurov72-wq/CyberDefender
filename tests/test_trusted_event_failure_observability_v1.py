from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from agent.core.event_bridge import SecurityEventBridge
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime


def main() -> int:
    event = SecurityEvent("OBSERVE_FAILURE", "HIGH", 1, "fixture", "synthetic")
    pipeline = Mock()
    pipeline.claim_trusted_delivery.return_value = event
    pipeline.consumer_failed = Mock()
    bridge = Mock()
    bridge.to_detection.side_effect = ValueError("sensitive fixture detail")
    runtime = SimpleNamespace(
        pipeline=pipeline,
        event_bridge=bridge,
        correlation_adapter=Mock(),
        events_acked=0,
        component_failures=0,
        last_error=None,
    )

    CyberDefenderRuntime._handle_trusted_event(runtime, event)
    assert runtime.component_failures == 1
    assert runtime.events_acked == 0
    assert runtime.last_error.startswith(
        "trusted_event:ValueError:BRIDGE:main.py:_handle_trusted_event:"
    ), runtime.last_error
    assert "sensitive fixture detail" not in runtime.last_error
    pipeline.ack.assert_not_called()
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
