"""ACK propagation fixtures only: no runtime startup or installed services."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agent.main import CyberDefenderRuntime
from agent.event import SecurityEvent
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.adapter import CorrelationAdapter
from agent.correlation.engine import CorrelationEngine
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline


class ConsumerAckTests(unittest.TestCase):
    def setUp(self):
        self.event = SecurityEvent('ACK_FIXTURE', 'HIGH', 1, 'fixture', 'synthetic', host_id='fixture')
        self.engine = CorrelationEngine()
        self.bus = Mock()
        self.bus.publish.return_value = True
        self.adapter = CorrelationAdapter(self.engine, self.bus)
        self.pipeline = Mock()
        self.pipeline.ack.return_value = True
        self.runtime = SimpleNamespace(pipeline=self.pipeline, event_bridge=SecurityEventBridge(),
            correlation_adapter=self.adapter, events_acked=0, component_failures=0, last_error=None)

    def deliver(self):
        CyberDefenderRuntime._handle_trusted_event(self.runtime, self.event)

    def test_success(self):
        self.deliver()
        self.pipeline.ack.assert_called_once_with(self.event.event_id)
        self.assertEqual(self.runtime.events_acked, 1)

    def test_engine_throws(self):
        with patch.object(self.engine, 'ingest', side_effect=RuntimeError('fixture')):
            self.deliver()
        self.pipeline.ack.assert_not_called()
        self.assertEqual(self.runtime.component_failures, 1)

    def test_engine_internal_error(self):
        with patch.object(self.engine, '_create_incident', side_effect=RuntimeError('fixture')):
            self.deliver()
        self.pipeline.ack.assert_not_called()
        self.assertEqual(self.adapter.get_stats()['failed'], 1)

    def test_publication_rejected_then_retry(self):
        self.bus.publish.return_value = False
        self.deliver()
        self.pipeline.ack.assert_not_called()
        self.assertEqual(len(self.engine._recent_events), 0)
        self.bus.publish.return_value = True
        self.deliver()
        self.pipeline.ack.assert_called_once()
        self.assertEqual(self.engine._incidents_created, 1)
        self.assertEqual(self.adapter.get_stats()['published'], 1)

    def test_publication_throws(self):
        self.bus.publish.side_effect = RuntimeError('fixture')
        self.deliver()
        self.pipeline.ack.assert_not_called()
        self.assertEqual(len(self.engine._recent_events), 0)

    def test_duplicate_does_not_republish(self):
        self.deliver()
        self.deliver()
        self.bus.publish.assert_called_once()
        self.assertEqual(self.pipeline.ack.call_count, 2)  # one idempotent ACK per delivery

    def test_ack_rejection_and_retry(self):
        self.pipeline.ack.return_value = False
        self.deliver()
        self.assertEqual(self.runtime.events_acked, 0)
        self.assertEqual(self.runtime.component_failures, 1)
        self.pipeline.ack.return_value = True
        self.deliver()
        self.assertEqual(self.runtime.events_acked, 1)
        self.bus.publish.assert_called_once()

    def test_ack_exception(self):
        self.pipeline.ack.side_effect = RuntimeError('fixture')
        self.deliver()
        self.assertEqual(self.runtime.events_acked, 0)
        self.assertEqual(self.runtime.component_failures, 1)

    def test_malformed_detection(self):
        self.runtime.event_bridge = Mock()
        self.runtime.event_bridge.to_detection.return_value = {'event_type':'DETECTION','event_id':'bad','data':{}}
        self.deliver()
        self.pipeline.ack.assert_not_called()

    def test_unknown_engine_result(self):
        with patch.object(self.engine, 'ingest', return_value=False):
            self.deliver()
        self.pipeline.ack.assert_not_called()

    def test_unknown_adapter_result(self):
        with patch.object(self.adapter, 'handle_event', return_value=None):
            self.deliver()
        self.pipeline.ack.assert_not_called()

    def test_standalone_callback_failure(self):
        callback = Mock(return_value=False)
        adapter = CorrelationAdapter(self.engine, self.bus, callback)
        detection = SecurityEventBridge.to_detection(self.event)
        self.assertIs(adapter.handle_event(detection), False)
        callback.return_value = True
        self.assertIs(adapter.handle_event(detection), True)
        self.bus.publish.assert_called_once()
        self.assertEqual(adapter.get_stats()['ack_failed'], 1)

    def test_legacy_ingest_compatibility(self):
        self.assertIsNone(self.engine.ingest({'event_type':'DETECTION','data':{}}))
        self.assertIsInstance(self.engine.ingest(SecurityEventBridge.to_detection(self.event)), dict)

    def test_incident_serialization_failure_is_not_committed(self):
        with patch.object(self.engine, '_incident_event', side_effect=RuntimeError('fixture')):
            self.deliver()
        self.pipeline.ack.assert_not_called()
        self.assertEqual(len(self.engine._recent_events), 0)
        self.deliver()
        self.pipeline.ack.assert_called_once()

    def test_repeated_rejection_keeps_memory_bounded(self):
        self.bus.publish.return_value = False
        for _ in range(100):
            self.deliver()
        self.pipeline.ack.assert_not_called()
        self.assertEqual(len(self.engine._recent_events), 0)
        self.assertEqual(len(self.engine._active_incidents), 0)
        self.assertEqual(self.bus.publish.call_count, 100)  # no internal retry

    def test_real_queue_rejection_then_recovery(self):
        bus = EventBus(max_size=1)
        self.assertTrue(bus.publish({'event_type':'INCIDENT','severity':'HIGH'}))
        self.runtime.correlation_adapter = CorrelationAdapter(self.engine, bus)
        self.deliver()
        self.pipeline.ack.assert_not_called()
        bus.dispatch_all()
        self.deliver()
        self.pipeline.ack.assert_called_once()
        self.assertEqual(bus.size(), 1)

    def test_adapter_invalid_input(self):
        for value in (None, {}, {'event_type':'DETECTION','data':{}},
                      {'event_type':'INCIDENT','event_id':'wrong'}):
            self.assertIs(self.adapter.handle_event(value), False)
        self.bus.publish.assert_not_called()

    def test_durable_restart_after_rejected_publication(self):
        with tempfile.TemporaryDirectory(prefix='cd_ack_fixture_') as directory:
            bus = EventBus()
            spool = DurableEventSpool(Path(directory))
            pipeline = DurableEventPipeline(spool, bus)
            self.runtime.pipeline = pipeline
            bus.subscribe(lambda event: CyberDefenderRuntime._handle_trusted_event(self.runtime, event))
            self.bus.publish.return_value = False
            self.assertTrue(pipeline.ingest(self.event))
            bus.dispatch_all()
            self.assertEqual(self.runtime.events_acked, 0)
            # Reopen persisted spool; no process/service action is involved.
            bus2 = EventBus()
            pipeline2 = DurableEventPipeline(DurableEventSpool(Path(directory)), bus2)
            self.runtime.pipeline = pipeline2
            self.runtime.correlation_adapter = CorrelationAdapter(CorrelationEngine(), self.bus)
            self.bus.publish.return_value = True
            bus2.subscribe(lambda event: CyberDefenderRuntime._handle_trusted_event(self.runtime, event))
            self.assertGreater(pipeline2.replay_pending(), 0)
            bus2.dispatch_all()
            self.assertEqual(self.runtime.events_acked, 1)
            self.assertEqual(pipeline2.replay_pending(), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
