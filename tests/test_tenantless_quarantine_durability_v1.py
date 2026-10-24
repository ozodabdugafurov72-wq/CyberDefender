from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.bus.event_bus import EventBus
from agent.correlation.adapter import CorrelationAdapter
from agent.correlation.engine import CorrelationEngine
from agent.event import SecurityEvent
from agent.quarantine.vault import SecureQuarantineVault
from agent.storage.durable_incident_outbox import DurableIncidentOutbox
from agent.storage.durable_spool import DurableEventSpool


def event(event_id: str, tenant_id: str | None = None) -> SecurityEvent:
    return SecurityEvent(
        "PROCESS_START",
        "HIGH",
        1,
        "fixture",
        "synthetic",
        event_id=event_id,
        host_id="fixture-host",
        tenant_id=tenant_id,
    )


def detection(event_id: str, tenant_id: str) -> dict[str, object]:
    return {
        "event_type": "DETECTION",
        "event_id": event_id,
        "timestamp": 1700000000.0,
        "data": {
            "type": "PROCESS_START",
            "severity": "HIGH",
            "source": "fixture",
            "tenant_id": tenant_id,
            "host_id": "fixture-host",
            "process_id": 1,
            "message": "synthetic",
        },
    }


class TenantlessQuarantineDurabilityTests(unittest.TestCase):
    def test_partial_write_has_no_published_quarantine_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = SecureQuarantineVault(directory)
            with patch.object(
                SecureQuarantineVault,
                "_atomic_write",
                side_effect=OSError("simulated power loss"),
            ):
                with self.assertRaises(OSError):
                    vault.quarantine(
                        b'{"event_id":"legacy-1"}',
                        reason="TENANT_IDENTITY_REQUIRED",
                        source="DurableEventSpool",
                        event_id="legacy-1",
                        failure_type="TENANTLESS_LEGACY",
                    )
            self.assertEqual([], list(Path(directory, "records").glob("*")))
            self.assertEqual([], list(Path(directory, "evidence").glob("*")))

    def test_duplicate_raw_replay_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = SecureQuarantineVault(directory)
            first = vault.quarantine(
                b'{"event_id":"legacy-2"}',
                reason="TENANT_IDENTITY_REQUIRED",
                source="DurableEventSpool",
                event_id="legacy-2",
                failure_type="TENANTLESS_LEGACY",
            )
            second = vault.quarantine(
                b'{"event_id":"legacy-2"}',
                reason="TENANT_IDENTITY_REQUIRED",
                source="DurableEventSpool",
                event_id="legacy-2",
                failure_type="TENANTLESS_LEGACY",
            )
            self.assertEqual(first["quarantine_id"], second["quarantine_id"])
            self.assertEqual(1, len(list(Path(directory, "records").glob("*.json"))))
            self.assertEqual(1, len(list(Path(directory, "evidence").glob("*.raw"))))

    def test_cross_tenant_replay_is_denied_without_ack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = b"runtime-outbox-integrity-key-32-bytes!!"
            outbox = DurableIncidentOutbox(directory, key)
            engine = CorrelationEngine()
            candidate = engine.ingest(detection("cross-tenant-1", "tenant-a"), strict=True, publish=lambda _: True)
            outbox.put_if_absent(
                tenant_id="tenant-b",
                source_event_id="cross-tenant-1",
                incident_id=candidate["incident_id"],
                idempotency_key=candidate["idempotency_key"],
                incident_payload=candidate,
            )
            acks: list[str] = []
            adapter = CorrelationAdapter(
                engine,
                EventBus(32),
                incident_outbox=outbox,
                ack_callback=lambda event_id: acks.append(event_id) or True,
            )
            self.assertFalse(adapter.handle_event(detection("cross-tenant-1", "tenant-a")))
            self.assertEqual([], acks)

    def test_terminal_accounting_survives_restart_without_ack_for_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spool_root = Path(directory) / "spool"
            vault = SecureQuarantineVault(Path(directory) / "vault")
            spool = DurableEventSpool(spool_root, quarantine_vault=vault)
            first = event("legacy-3")
            second = event("valid-3", tenant_id="tenant-a")
            self.assertTrue(spool.append(first))
            self.assertTrue(spool.append(second))
            pending_before = spool.get_stats()["pending"]
            record = next(row for row in spool.pending_records() if row["event_id"] == first.event_id)
            self.assertTrue(spool._quarantine_record(record, "TENANT_IDENTITY_REQUIRED", "TENANTLESS_LEGACY"))
            self.assertTrue(spool.ack(second.event_id))
            stats = spool.get_stats()
            self.assertEqual(pending_before, stats["acked"] + stats["quarantined"] + stats["pending"])
            self.assertEqual(0, stats["pending"])
            self.assertEqual(0, stats["ack_rejected"])
            self.assertEqual(1, stats["quarantined"])
            reopened = DurableEventSpool(spool_root, quarantine_vault=SecureQuarantineVault(Path(directory) / "vault"))
            restarted = reopened.get_stats()
            self.assertEqual(1, restarted["acked"])
            self.assertEqual(1, restarted["quarantined"])
            self.assertEqual(0, restarted["pending"])
            self.assertEqual([], reopened.pending_records())

    def test_failed_terminal_reconciliation_stays_pending_and_unsafe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spool_root = Path(directory) / "spool"
            vault_root = Path(directory) / "vault"
            vault = SecureQuarantineVault(vault_root)
            spool = DurableEventSpool(spool_root, quarantine_vault=vault)
            candidate = event("legacy-4")
            self.assertTrue(spool.append(candidate))
            record = spool.pending_records()[0]
            self.assertTrue(
                vault.quarantine(
                    spool._canonical_json(record),
                    reason="TENANT_IDENTITY_REQUIRED",
                    source="DurableEventSpool",
                    event_id=candidate.event_id,
                    failure_type="TENANTLESS_LEGACY",
                )
            )
            with patch.object(DurableEventSpool, "_append_jsonl", side_effect=OSError("journal unavailable")):
                reopened = DurableEventSpool(spool_root, quarantine_vault=vault)
                stats = reopened.get_stats()
                self.assertEqual(1, stats["pending"])
                self.assertFalse(stats["terminal_state_safe"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
