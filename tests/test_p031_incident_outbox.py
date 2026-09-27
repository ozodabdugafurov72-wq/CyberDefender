import json
import tempfile
import unittest
from pathlib import Path

from agent.storage.durable_incident_outbox import (
    DurableIncidentOutbox,
    IncidentOutboxCapacityError,
    IncidentOutboxConflict,
    IncidentOutboxPolicy,
)


class FakeClock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class IncidentOutboxTests(unittest.TestCase):
    KEY = b"test-outbox-integrity-key-32-bytes!!"

    def make_outbox(self, root, *, policy=None, clock=None, key=None):
        return DurableIncidentOutbox(
            root,
            key or self.KEY,
            policy=policy,
            clock=clock,
        )

    @staticmethod
    def put(outbox, *, tenant="tenant-a", source="evt-1", incident="inc-1", idem="idem-1", payload=None):
        return outbox.put_if_absent(
            tenant_id=tenant,
            source_event_id=source,
            incident_id=incident,
            idempotency_key=idem,
            incident_payload=payload or {"event_type": "INCIDENT", "severity": "HIGH", "message": "synthetic"},
        )

    def test_put_if_absent_creates_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            record, reused = self.put(self.make_outbox(directory))
            self.assertFalse(reused)
            self.assertEqual("incident-outbox.v1", record["schema_version"])
            self.assertEqual("PENDING", record["state"])
            self.assertEqual(0, record["attempt_count"])

    def test_duplicate_replay_reuses_same_record(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = self.make_outbox(directory)
            first, _ = self.put(outbox)
            second, reused = self.put(outbox)
            self.assertTrue(reused)
            self.assertEqual(first["outbox_id"], second["outbox_id"])
            self.assertEqual(1, len(outbox.scan()))
            self.assertEqual(1, outbox.health_snapshot()["physical_records"])

    def test_conflicting_payload_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = self.make_outbox(directory)
            self.put(outbox)
            with self.assertRaises(IncidentOutboxConflict):
                self.put(outbox, payload={"event_type": "INCIDENT", "severity": "CRITICAL"})

    def test_tenant_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = self.make_outbox(directory)
            self.put(outbox)
            with self.assertRaises(IncidentOutboxConflict):
                self.put(outbox, tenant="tenant-b")

    def test_malformed_record_is_retained_and_observable(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = self.make_outbox(directory)
            self.put(outbox)
            with outbox.journal_path.open("ab") as handle:
                handle.write(b"{malformed-json}\n")
            trusted = outbox.scan()
            self.assertEqual(1, len(trusted))
            self.assertGreaterEqual(outbox.health_snapshot()["corrupt_records"], 1)
            self.assertIn(b"malformed-json", outbox.journal_path.read_bytes())

    def test_integrity_mac_failure_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = self.make_outbox(directory)
            self.put(outbox)
            record = json.loads(outbox.journal_path.read_text(encoding="utf-8"))
            record["incident_id"] = "tampered"
            outbox.journal_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertEqual([], outbox.scan())
            snapshot = outbox.health_snapshot()
            self.assertGreaterEqual(snapshot["integrity_rejected"], 1)
            self.assertGreaterEqual(snapshot["corrupt_records"], 1)

    def test_capacity_exhaustion_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = IncidentOutboxPolicy(max_records=1, max_bytes=4096, max_record_bytes=2048, max_scan_records=8, max_scan_bytes=4096)
            outbox = self.make_outbox(directory, policy=policy)
            self.put(outbox)
            with self.assertRaises(IncidentOutboxCapacityError):
                self.put(outbox, source="evt-2", incident="inc-2", idem="idem-2")

    def test_scan_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            write_policy = IncidentOutboxPolicy(max_scan_records=8, max_scan_bytes=8192, max_bytes=8192, max_record_bytes=2048)
            outbox = self.make_outbox(directory, policy=write_policy)
            for index in range(3):
                self.put(outbox, source=f"evt-{index}", incident=f"inc-{index}", idem=f"idem-{index}")
            with self.assertRaises(IncidentOutboxCapacityError):
                outbox.scan(max_records=2)
            self.assertGreaterEqual(outbox.health_snapshot()["scan_limit_exceeded"], 1)

    def test_lease_expiry_allows_bounded_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock()
            policy = IncidentOutboxPolicy(lease_seconds=10, max_attempts=3, max_scan_records=16, max_scan_bytes=8192, max_bytes=8192, max_record_bytes=2048)
            outbox = self.make_outbox(directory, policy=policy, clock=clock)
            original, _ = self.put(outbox)
            first = outbox.claim_due()
            self.assertEqual(1, len(first))
            self.assertEqual(1, first[0]["attempt_count"])
            self.assertEqual([], outbox.claim_due())
            clock.advance(11)
            second = outbox.claim_due()
            self.assertEqual(original["outbox_id"], second[0]["outbox_id"])
            self.assertEqual(2, second[0]["attempt_count"])

    def test_retry_attempt_limit_moves_to_review_required(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock()
            policy = IncidentOutboxPolicy(lease_seconds=1, max_attempts=1, max_scan_records=16, max_scan_bytes=8192, max_bytes=8192, max_record_bytes=2048)
            outbox = self.make_outbox(directory, policy=policy, clock=clock)
            record, _ = self.put(outbox)
            claimed = outbox.claim_due()[0]
            updated = outbox.fail_dispatch(claimed["outbox_id"], error="DOWNSTREAM_TIMEOUT")
            self.assertEqual(record["outbox_id"], updated["outbox_id"])
            self.assertEqual("REVIEW_REQUIRED", updated["state"])
            self.assertEqual("REVIEW_REQUIRED", outbox.scan()[0]["state"])

    def test_restart_reopen_preserves_state(self):
        with tempfile.TemporaryDirectory() as directory:
            clock = FakeClock()
            first = self.make_outbox(directory, clock=clock)
            record, _ = self.put(first)
            claimed = first.claim_due()[0]
            first.mark_delivered(claimed["outbox_id"])
            reopened = self.make_outbox(directory, clock=clock)
            restored = reopened.scan()[0]
            self.assertEqual(record["outbox_id"], restored["outbox_id"])
            self.assertEqual("DELIVERED", restored["state"])

    def test_no_secret_leakage_in_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = b"super-secret-test-key-1234567890"
            outbox = self.make_outbox(directory, key=secret)
            self.put(outbox)
            diagnostics = json.dumps(outbox.health_snapshot(), sort_keys=True)
            self.assertNotIn(secret.decode("ascii"), diagnostics)
            self.assertNotIn(secret.hex(), diagnostics)
            journal = outbox.journal_path.read_text(encoding="utf-8")
            self.assertNotIn(secret.decode("ascii"), journal)
            self.assertNotIn(secret.hex(), journal)
            self.assertFalse(outbox.health_snapshot()["key_material_export"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
