from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from agent.bus.event_bus import EventBus
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.adapter import CorrelationAdapter
from agent.correlation.engine import CorrelationEngine
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime


def main() -> int:
    event = SecurityEvent("TENANTLESS_SCOPE", "HIGH", 1, "fixture", "synthetic")
    pipeline = Mock()
    pipeline.claim_trusted_delivery.return_value = event
    pipeline.ack = Mock(return_value=True)
    pipeline.consumer_failed = Mock()
    adapter = CorrelationAdapter(
        CorrelationEngine(), EventBus(), incident_outbox=object()
    )
    runtime = SimpleNamespace(
        pipeline=pipeline,
        event_bridge=SecurityEventBridge(),
        correlation_adapter=adapter,
        events_acked=0,
        component_failures=0,
        tenant_binding_pending=0,
        last_error=None,
    )

    CyberDefenderRuntime._handle_trusted_event(runtime, event)
    assert runtime.component_failures == 0
    assert runtime.tenant_binding_pending == 1
    assert runtime.events_acked == 0
    pipeline.ack.assert_not_called()
    pipeline.consumer_failed.assert_not_called()
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
