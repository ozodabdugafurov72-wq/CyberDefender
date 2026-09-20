"""Synthetic local admission fixtures; no service or production runtime startup."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agent.main import CyberDefenderRuntime
from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.core.event_bridge import SecurityEventBridge
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.core.crypto_replay_admission_gateway import CryptoReplayAdmissionGateway
from agent.crypto.key_manager import KeyManager
from agent.crypto.replay_guard import ReplayGuard
from agent.storage.durable_spool import DurableEventSpool
from agent.correlation.engine import CorrelationEngine
from agent.correlation.adapter import CorrelationAdapter


class AdmissionBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cd_binding_fixture_')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.storage_key = os.urandom(32)
        self.keys = KeyManager(self.root/'keys', self.storage_key)
        self.assertTrue(self.keys.generate_key())
        self.start_stack()
        self.event = SecurityEvent('BINDING_TEST', 'HIGH', 1, 'fixture', 'synthetic',
                                   tenant_id='tenant-a', host_id='host-a')

    def start_stack(self):
        self.bus = EventBus(max_size=16)
        self.spool = DurableEventSpool(self.root/'spool')
        self.pipeline = DurableEventPipeline(self.spool, self.bus, require_admission=True)
        self.gateway = CryptoReplayAdmissionGateway(self.keys, ReplayGuard(), self.pipeline,
                                                     use_detailed_transport=True)
        self.pipeline.bind_admission_verifier(self.gateway.verify_admission_receipt)
        self.engine = CorrelationEngine()
        self.adapter = CorrelationAdapter(self.engine, self.bus)
        self.runtime = SimpleNamespace(pipeline=self.pipeline, event_bridge=SecurityEventBridge(),
            correlation_adapter=self.adapter, events_acked=0, component_failures=0, last_error=None)
        self.deliveries = []
        self.bus.subscribe(lambda e: self.deliveries.append(e) if isinstance(e, SecurityEvent) else None)
        self.bus.subscribe(lambda e: CyberDefenderRuntime._handle_trusted_event(self.runtime, e))

    def admit(self):
        return self.gateway.sign_and_admit_detailed(self.event)

    def dispatch(self):
        self.bus.dispatch_all(max_events=32)

    def assert_no_correlation(self):
        self.assertEqual(self.engine.get_stats()['received'], 0)
        self.assertEqual(self.runtime.events_acked, 0)

    def test_admitted_event_and_ack_once(self):
        with patch.object(self.pipeline, 'ack', wraps=self.pipeline.ack) as ack:
            self.assertTrue(self.admit().accepted)
            self.dispatch()
            ack.assert_called_once_with(self.event.event_id)
        self.assertEqual(self.engine.get_stats()['received'], 1)
        self.assertEqual(self.spool.pending_records(), [])

    def test_unsigned_direct_publication(self):
        self.assertTrue(self.bus.publish(self.event))
        self.dispatch()
        self.assert_no_correlation()
        self.assertEqual(self.pipeline.admission_health()['delivery_rejected'], 1)

    def test_forged_payload_flags(self):
        self.event = SecurityEvent('BINDING_TEST','HIGH',{'trusted':True,'verified':True},
            'SystemObserver','forged flags',provenance={'admitted':True,'signature':'fake'})
        self.event.trusted = True
        self.bus.publish(self.event)
        self.dispatch()
        self.assert_no_correlation()

    def test_raw_dicts_and_demo_are_ignored(self):
        for name in ('DETECTION','INCIDENT','DEMO','RESOURCE_STATUS'):
            self.bus.publish({'event_type':name,'severity':'HIGH','trusted':True})
        self.dispatch()
        self.assert_no_correlation()

    def test_direct_pipeline_missing_receipt(self):
        self.assertFalse(self.pipeline.ingest(self.event))
        self.dispatch()
        self.assert_no_correlation()
        self.assertEqual(self.spool.pending_records(), [])

    def test_ordinary_signature_is_not_admission_receipt(self):
        envelope = self.gateway.sign_event(self.event)
        receipt = {k:envelope[k] for k in ('key_id','signature')}
        self.assertFalse(self.pipeline.ingest_detailed(self.event, admission=receipt).accepted)
        self.assert_no_correlation()

    def test_invalid_signature(self):
        self.assertFalse(self.gateway.admit_detailed(self.event,self.keys.active_key_id(),'0'*64).accepted)
        self.dispatch()
        self.assert_no_correlation()

    def test_tampered_before_admission(self):
        envelope = self.gateway.sign_event(self.event)
        self.event.value = 2
        self.assertFalse(self.gateway.admit_detailed(self.event,envelope['key_id'],envelope['signature']).accepted)
        self.dispatch()
        self.assert_no_correlation()

    def test_schema_invalid(self):
        self.event.severity = 'INVALID'
        self.event.integrity = self.event.compute_integrity()
        self.assertFalse(self.admit().accepted)
        self.dispatch()
        self.assert_no_correlation()

    def test_replay_gateway_rejected(self):
        self.assertTrue(self.admit().accepted)
        self.dispatch()
        self.assertFalse(self.admit().accepted)
        self.dispatch()
        self.assertEqual(self.engine.get_stats()['received'], 1)

    def test_original_object_not_bound(self):
        self.assertTrue(self.admit().accepted)
        self.bus.publish(self.event)
        self.dispatch()
        self.assertEqual(self.engine.get_stats()['received'], 1)
        self.assertEqual(self.runtime.events_acked, 1)

    def test_binding_is_one_use(self):
        self.assertTrue(self.admit().accepted)
        self.dispatch()
        self.bus.publish(self.deliveries[0])
        self.dispatch()
        self.assertEqual(self.engine.get_stats()['received'], 1)

    def test_serialized_copy_cannot_copy_binding(self):
        self.assertTrue(self.admit().accepted)
        self.bus.publish(SecurityEvent.from_dict(self.event.to_dict()))
        self.dispatch()
        self.assertEqual(self.engine.get_stats()['received'], 1)
        self.assertEqual(
            self.pipeline.admission_health()['delivery_rejected'],
            1,
        )

    def test_queued_tamper(self):
        self.assertTrue(self.admit().accepted)
        def tamper(event):
            if isinstance(event, SecurityEvent):
                event.value = 9
                event.integrity = event.compute_integrity()
        self.bus._subscribers.insert(0,tamper)
        self.dispatch()
        self.assert_no_correlation()
        self.assertEqual(len(self.spool.pending_records()), 1)

    def test_unsigned_extra_attributes_removed(self):
        self.assertTrue(self.admit().accepted)
        def tamper(event):
            if isinstance(event, SecurityEvent):
                event.process_id = 999999
        self.bus._subscribers.insert(0,tamper)
        with patch.object(self.adapter,'handle_event',wraps=self.adapter.handle_event) as handle:
            self.dispatch()
            self.assertIsNone(handle.call_args.args[0]['data']['process_id'])

    def test_restart_recovery(self):
        self.assertTrue(self.admit().accepted)
        self.keys = KeyManager(self.root/'keys', self.storage_key)
        self.start_stack()
        self.assertEqual(self.pipeline.replay_pending(), 1)
        self.dispatch()
        self.assertEqual(self.runtime.events_acked, 1)
        self.assertEqual(self.pipeline.replay_pending(), 0)

    def test_legacy_unsigned_spool_not_promoted(self):
        self.assertTrue(self.spool.append(self.event))
        self.assertEqual(self.pipeline.replay_pending(), 0)
        self.dispatch()
        self.assert_no_correlation()
        self.assertEqual(len(self.spool.pending_records()), 1)
        health = self.pipeline.health_check()
        self.assertEqual(health['status'], 'HEALTHY')
        self.assertGreater(
            health['admission_binding']['rejected'],
            0,
        )
        self.assertGreater(
            health['counters']['replay_failed'],
            0,
        )

    def test_corrupted_receipt_after_restart(self):
        self.assertTrue(self.admit().accepted)
        row = self.spool.pending_records()[0]
        row['admission']['signature'] = '0'*64
        self.spool.pending_path.write_text(json.dumps(row)+'\n')
        self.start_stack()
        self.assertEqual(self.pipeline.replay_pending(), 0)
        self.assert_no_correlation()
        self.assertEqual(len(self.spool.pending_records()), 1)
        self.assertGreater(
            self.pipeline.health_check()['counters']['replay_failed'],
            0,
        )

    def test_receipt_bound_to_tenant_and_payload(self):
        self.assertTrue(self.admit().accepted)
        row = self.spool.pending_records()[0]

        other_tenant = SecurityEvent(
            'BINDING_TEST',
            'HIGH',
            1,
            'fixture',
            'synthetic',
            tenant_id='tenant-b',
        )
        self.assertFalse(
            self.pipeline.ingest_detailed(
                other_tenant,
                admission=row['admission'],
            ).accepted
        )

        changed_payload = SecurityEvent(
            'BINDING_TEST',
            'HIGH',
            2,
            'fixture',
            'synthetic',
            event_id=self.event.event_id,
            timestamp=self.event.timestamp,
            tenant_id='tenant-a',
            host_id='host-a',
        )
        self.assertFalse(
            self.pipeline.ingest_detailed(
                changed_payload,
                admission=row['admission'],
            ).accepted
        )

    def test_downstream_failure_retries_without_ack(self):
        self.assertTrue(self.admit().accepted)
        with patch.object(self.engine,'ingest',side_effect=RuntimeError('fixture')):
            self.dispatch()
        self.assertEqual(self.runtime.events_acked, 0)
        self.assertEqual(len(self.spool.pending_records()), 1)
        self.assertEqual(self.pipeline.replay_pending(), 1)
        self.dispatch()
        self.assertEqual(self.runtime.events_acked, 1)

    def test_ack_failure_duplicate_recovery(self):
        self.assertTrue(self.admit().accepted)
        with patch.object(self.pipeline,'ack',return_value=False):
            self.dispatch()
        self.assertEqual(self.runtime.events_acked, 0)
        self.pipeline.replay_pending()
        self.dispatch()
        self.assertEqual(self.runtime.events_acked, 1)
        self.assertEqual(self.adapter.get_stats()['published'], 1)

    def test_delivery_binding_capacity_deferred(self):
        self.pipeline._max_delivery_bindings = 0
        result = self.admit()
        self.assertTrue(result.accepted)
        self.assertEqual(result.disposition,'PERSISTED_DEFERRED')
        self.assertEqual(len(self.spool.pending_records()),1)
        self.pipeline._max_delivery_bindings = 1
        self.assertEqual(self.pipeline.replay_pending(),1)
        self.dispatch()
        self.assertEqual(self.runtime.events_acked,1)

    def test_receipt_missing_verifier_fails_closed(self):
        self.pipeline._admission_verifier = None
        self.assertFalse(self.admit().accepted)
        self.dispatch()
        self.assert_no_correlation()


    def test_atomic_active_key_pair_is_used(self):
        # Neither event signing nor receipt minting should perform a split
        # active_key_id() read followed by a separate sign().
        with patch.object(
            self.keys,
            'active_key_id',
            side_effect=AssertionError('split key-id read forbidden'),
        ):
            result = self.admit()

        self.assertTrue(result.accepted)
        self.dispatch()
        self.assertEqual(self.runtime.events_acked, 1)

    def test_restart_recovery_after_key_rotation(self):
        old_key = self.keys.active_key_id()
        self.assertIsNotNone(old_key)

        self.assertTrue(self.admit().accepted)

        new_key = self.keys.rotate()
        self.assertIsNotNone(new_key)
        self.assertNotEqual(old_key, new_key)

        # Real KeyManager reload from persisted authenticated state.
        self.keys = KeyManager(
            self.root / 'keys',
            self.storage_key,
        )
        self.start_stack()

        self.assertEqual(self.pipeline.replay_pending(), 1)
        self.dispatch()

        self.assertEqual(self.runtime.events_acked, 1)
        self.assertEqual(self.pipeline.replay_pending(), 0)

    def test_revoked_receipt_key_fails_closed(self):
        old_key = self.keys.active_key_id()
        self.assertIsNotNone(old_key)

        self.assertTrue(self.admit().accepted)

        new_key = self.keys.rotate()
        self.assertIsNotNone(new_key)
        self.assertTrue(self.keys.revoke(old_key))

        self.keys = KeyManager(
            self.root / 'keys',
            self.storage_key,
        )
        self.start_stack()

        self.assertEqual(self.pipeline.replay_pending(), 0)
        self.dispatch()

        self.assert_no_correlation()
        self.assertEqual(len(self.spool.pending_records()), 1)
        self.assertGreater(
            self.pipeline.admission_health()['rejected'],
            0,
        )

    def test_legacy_unsigned_record_does_not_starve_valid_recovery(self):
        legacy = SecurityEvent(
            'LEGACY_UNSIGNED',
            'HIGH',
            1,
            'fixture',
            'legacy',
            tenant_id='tenant-a',
        )
        self.assertTrue(self.spool.append(legacy))

        # Persist a valid admitted event but defer its initial publication.
        self.pipeline._max_delivery_bindings = 0
        self.event = SecurityEvent(
            'BINDING_TEST',
            'HIGH',
            2,
            'fixture',
            'synthetic',
            tenant_id='tenant-a',
            host_id='host-a',
        )
        result = self.admit()

        self.assertTrue(result.accepted)
        self.assertEqual(
            result.disposition,
            'PERSISTED_DEFERRED',
        )

        self.pipeline._max_delivery_bindings = 1

        # Old bounded-batch behaviour would only expose the first legacy row.
        # Admission-enforced recovery must scan past it.
        first_record = self.spool.pending_records()[0]

        with patch.object(
            self.spool,
            'pending_batch',
            return_value=[first_record],
        ) as pending_batch:
            self.assertEqual(self.pipeline.replay_pending(), 1)
            pending_batch.assert_not_called()

        self.dispatch()

        self.assertEqual(self.engine.get_stats()['received'], 1)
        self.assertEqual(self.runtime.events_acked, 1)

        remaining = self.spool.pending_records()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(
            remaining[0]['event_id'],
            legacy.event_id,
        )



if __name__ == '__main__':
    unittest.main(verbosity=2)
