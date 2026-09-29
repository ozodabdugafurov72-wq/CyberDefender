import os
import tempfile
import unittest
import json

from agent.bus.event_bus import EventBus
from agent.correlation.adapter import CorrelationAdapter
from agent.correlation.engine import CorrelationEngine
from agent.storage.durable_incident_outbox import (
    DurableIncidentOutbox,
    IncidentOutboxCapacityError,
    IncidentOutboxConflict,
    IncidentOutboxPolicy,
)


KEY = b"runtime-outbox-integrity-key-32-bytes!!"


def detection(event_id="evt-1", tenant_id="tenant-a"):
    return {
        "event_type": "DETECTION",
        "event_id": event_id,
        "timestamp": 1700000000.0,
        "data": {
            "type": "PROCESS_START",
            "severity": "HIGH",
            "source": "test-sensor",
            "tenant_id": tenant_id,
            "host_id": "host-1",
            "process_id": 42,
            "message": "synthetic",
        },
    }


def build_adapter(outbox, *, ack=None, engine=None, bus=None):
    return CorrelationAdapter(
        engine or CorrelationEngine(),
        bus or EventBus(32),
        incident_outbox=outbox,
        ack_callback=ack,
    )


class RuntimeOutboxWiringTests(unittest.TestCase):
    def test_successful_commit_then_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            acks = []
            adapter = build_adapter(
                DurableIncidentOutbox(directory, KEY),
                ack=lambda event_id: acks.append(event_id) or True,
            )
            self.assertTrue(adapter.handle_event(detection()))
            self.assertEqual(["evt-1"], acks)
            self.assertEqual("PENDING", adapter.incident_outbox.scan()[0]["state"])

    def test_outbox_commit_failure_prevents_ack(self):
        class FailingOutbox:
            def put_if_absent(self, **kwargs):
                raise OSError("simulated commit failure")

        acks = []
        adapter = build_adapter(FailingOutbox(), ack=lambda event_id: acks.append(event_id) or True)
        self.assertFalse(adapter.handle_event(detection()))
        self.assertEqual([], acks)
        self.assertEqual(1, adapter.get_stats()["outbox_failures"])

    def test_duplicate_replay_reuses_existing_row(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableIncidentOutbox(directory, KEY)
            first_acks = []
            self.assertTrue(build_adapter(outbox, ack=lambda event_id: first_acks.append(event_id) or True).handle_event(detection()))
            second_acks = []
            reopened = DurableIncidentOutbox(directory, KEY)
            self.assertTrue(build_adapter(reopened, ack=lambda event_id: second_acks.append(event_id) or True).handle_event(detection()))
            self.assertEqual(["evt-1"], first_acks)
            self.assertEqual(["evt-1"], second_acks)
            self.assertEqual(1, reopened.health_snapshot()["physical_records"])
            self.assertEqual(1, len(reopened.scan()))

    def test_conflicting_existing_row_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableIncidentOutbox(directory, KEY)
            first_engine = CorrelationEngine()
            candidate = first_engine.ingest(detection(), strict=True, publish=lambda incident: True)
            outbox.put_if_absent(
                tenant_id="tenant-a",
                source_event_id="evt-1",
                incident_id=candidate["incident_id"],
                idempotency_key=candidate["idempotency_key"],
                incident_payload={"tampered": True},
            )
            acks = []
            adapter = build_adapter(outbox, ack=lambda event_id: acks.append(event_id) or True)
            self.assertFalse(adapter.handle_event(detection()))
            self.assertEqual([], acks)

    def test_capacity_exhaustion_prevents_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = IncidentOutboxPolicy(max_records=1, max_bytes=8192, max_record_bytes=4096, max_scan_records=16, max_scan_bytes=8192)
            outbox = DurableIncidentOutbox(directory, KEY, policy=policy)
            outbox.put_if_absent(tenant_id="tenant-a", source_event_id="other", incident_id="INC-OTHER", idempotency_key="INCIDENT:INC-OTHER:other", incident_payload={"x": 1})
            acks = []
            self.assertFalse(build_adapter(outbox, ack=lambda event_id: acks.append(event_id) or True).handle_event(detection()))
            self.assertEqual([], acks)

    def test_tenant_mismatch_prevents_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableIncidentOutbox(directory, KEY)
            engine = CorrelationEngine()
            candidate = engine.ingest(detection(), strict=True, publish=lambda incident: True)
            outbox.put_if_absent(
                tenant_id="tenant-b",
                source_event_id="evt-1",
                incident_id=candidate["incident_id"],
                idempotency_key=candidate["idempotency_key"],
                incident_payload=candidate,
            )
            acks = []
            self.assertFalse(build_adapter(outbox, ack=lambda event_id: acks.append(event_id) or True).handle_event(detection()))
            self.assertEqual([], acks)

    def test_tenantless_event_is_rejected_and_not_acked(self):
        with tempfile.TemporaryDirectory() as directory:
            acks = []
            adapter = build_adapter(
                DurableIncidentOutbox(directory, KEY),
                ack=lambda event_id: acks.append(event_id) or True,
            )
            self.assertFalse(adapter.handle_event(detection(tenant_id=None)))
            self.assertEqual([], acks)

    def test_event_state_preserves_tenant_for_recovery(self):
        from agent.event import SecurityEvent
        from agent.state import EventState

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "state.json")
            state = EventState(path)
            state.update(SecurityEvent(
                event_type="PROCESS_START",
                severity="HIGH",
                value=1,
                source="test",
                message="synthetic",
                tenant_id="tenant-a",
            ))
            reopened = EventState(path)
            self.assertEqual(
                reopened.get_state("PROCESS_START").get("tenant_id"),
                "tenant-a",
            )

    def test_reopen_before_ack_keeps_one_logical_row(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableIncidentOutbox(directory, KEY)
            self.assertFalse(build_adapter(outbox, ack=lambda event_id: False).handle_event(detection()))
            reopened = DurableIncidentOutbox(directory, KEY)
            self.assertFalse(build_adapter(reopened, ack=lambda event_id: False).handle_event(detection()))
            self.assertEqual(1, len(reopened.scan()))
            self.assertEqual(1, reopened.health_snapshot()["physical_records"])

    def test_no_policy_safety_or_action_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            bus = EventBus(32)
            outbox = DurableIncidentOutbox(directory, KEY)
            adapter = build_adapter(outbox, bus=bus)
            self.assertTrue(adapter.handle_event(detection()))
            self.assertFalse(hasattr(adapter, "policy_engine"))
            self.assertFalse(hasattr(adapter, "safety_core"))
            self.assertFalse(hasattr(adapter, "action_gateway"))
            self.assertEqual(1, bus.get_stats()["published"])

    def test_corrupt_existing_row_prevents_duplicate_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableIncidentOutbox(directory, KEY)
            adapter = build_adapter(outbox)
            self.assertTrue(adapter.handle_event(detection()))
            record = json.loads(outbox.journal_path.read_text(encoding="utf-8"))
            record["incident_id"] = "INC-TAMPERED"
            outbox.journal_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            acks = []
            replay = build_adapter(outbox, ack=lambda event_id: acks.append(event_id) or True)
            self.assertFalse(replay.handle_event(detection()))
            self.assertEqual([], acks)


if __name__ == "__main__":
    unittest.main(verbosity=2)
