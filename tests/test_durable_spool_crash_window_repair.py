from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy


def event(index: int) -> SecurityEvent:
    return SecurityEvent(
        event_type=f"CRASH_WINDOW_{index}",
        severity="HIGH",
        value=index,
        source="test",
        message="crash-window repair fixture",
    )


class DurableSpoolCrashWindowRepairTests(unittest.TestCase):
    def policy(self, terminal_limit: int) -> DurableSpoolPolicy:
        return DurableSpoolPolicy(
            max_pending_events=8,
            max_pending_bytes=64 * 1024,
            max_event_bytes=8 * 1024,
            protected_reserve_events=2,
            protected_reserve_bytes=8 * 1024,
            max_recovery_batch=2,
            max_recovery_scan_bytes=64 * 1024,
            compaction_terminal_ops=100,
            compaction_min_dead_bytes=64 * 1024,
            max_terminal_records=terminal_limit,
            max_terminal_state_bytes=4096,
        )

    def test_limit_plus_one_snapshot_repairs_pending_before_pruning(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-crash-window-") as root:
            spool_dir = Path(root) / "spool"
            initial = DurableEventSpool(spool_dir, policy=self.policy(4))
            events = [event(index) for index in range(3)]
            for item in events:
                self.assertTrue(initial.append(item))

            # Simulate a crash after ACK snapshot commit and before compact().
            (spool_dir / "acked_state.json").write_text(
                json.dumps({"schema_version": "1", "status": "ACKED", "acked_ids": [item.event_id for item in events]}),
                encoding="utf-8",
            )

            repaired = DurableEventSpool(spool_dir, policy=self.policy(2))
            health = repaired.health_check()
            self.assertEqual("HEALTHY", health["status"])
            self.assertTrue(health["terminal_state_safe"])
            self.assertLessEqual(health["acked"], 2)
            self.assertEqual([], repaired.pending_records())

            restarted = DurableEventSpool(spool_dir, policy=self.policy(2))
            self.assertTrue(restarted.health_check()["terminal_state_safe"])
            self.assertEqual([], restarted.pending_records())

    def test_more_than_limit_plus_one_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-unsafe-window-") as root:
            spool_dir = Path(root) / "spool"
            spool_dir.mkdir(parents=True)
            (spool_dir / "acked_state.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1",
                        "status": "ACKED",
                        "acked_ids": [f"event-{index}" for index in range(4)],
                    }
                ),
                encoding="utf-8",
            )
            unsafe = DurableEventSpool(spool_dir, policy=self.policy(2))
            health = unsafe.health_check()
            self.assertEqual("DEGRADED", health["status"])
            self.assertFalse(health["terminal_state_safe"])

    def test_limit_plus_one_pending_sharing_failure_is_degraded_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-sharing-window-") as root:
            spool_dir = Path(root) / "spool"
            initial = DurableEventSpool(spool_dir, policy=self.policy(4))
            events = [event(index) for index in range(4)]
            for item in events:
                self.assertTrue(initial.append(item))

            # Exact limit+1 crash window: three ACK tombstones for a limit of
            # two, with one unacknowledged event that must survive repair.
            (spool_dir / "acked_state.json").write_text(
                json.dumps({"schema_version": "1", "status": "ACKED", "acked_ids": [item.event_id for item in events[:3]]}),
                encoding="utf-8",
            )
            expected_pending = {events[3].event_id}
            original_atomic_write = DurableEventSpool._atomic_write

            def pending_sharing_violation(self, path: Path, payload: bytes) -> None:
                if path == self.pending_path:
                    raise PermissionError("simulated Windows pending-file sharing violation")
                original_atomic_write(self, path, payload)

            with mock.patch.object(
                DurableEventSpool, "_atomic_write", new=pending_sharing_violation
            ):
                blocked = DurableEventSpool(spool_dir, policy=self.policy(2))

            blocked_health = blocked.health_check()
            self.assertEqual("DEGRADED", blocked_health["status"])
            self.assertFalse(blocked_health["terminal_state_safe"])
            self.assertEqual(
                expected_pending,
                {item["event_id"] for item in blocked.pending_records()},
            )

            recovered = DurableEventSpool(spool_dir, policy=self.policy(2))
            recovered_health = recovered.health_check()
            self.assertEqual("HEALTHY", recovered_health["status"])
            self.assertTrue(recovered_health["terminal_state_safe"])
            self.assertLessEqual(recovered_health["acked"], 2)
            self.assertEqual(
                expected_pending,
                {item["event_id"] for item in recovered.pending_records()},
            )

    def test_legacy_ack_journal_lock_does_not_poison_authoritative_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-ack-journal-lock-") as root:
            spool_dir = Path(root) / "spool"
            spool = DurableEventSpool(spool_dir, policy=self.policy(2))
            events = [event(index) for index in range(3)]
            for item in events:
                self.assertTrue(spool.append(item))
            self.assertTrue(spool.ack(events[0].event_id))
            self.assertTrue(spool.ack(events[1].event_id))

            original_rewrite = spool._rewrite_jsonl

            def sharing_violation(path: Path, records: list[dict]) -> None:
                if path == spool.acked_path:
                    raise PermissionError("simulated Windows sharing violation")
                original_rewrite(path, records)

            with mock.patch.object(spool, "_rewrite_jsonl", side_effect=sharing_violation):
                self.assertTrue(spool.ack(events[2].event_id))

            health = spool.health_check()
            self.assertEqual("HEALTHY", health["status"])
            self.assertTrue(health["terminal_state_safe"])
            self.assertEqual(1, health["terminal_compatibility_failures"])
            self.assertEqual([], spool.pending_records())

            # Restart must trust the bounded atomic snapshot, not the stale
            # compatibility journal left by the simulated lock.
            restarted = DurableEventSpool(spool_dir, policy=self.policy(2))
            self.assertEqual("HEALTHY", restarted.health_check()["status"])
            self.assertEqual([], restarted.pending_records())


if __name__ == "__main__":
    unittest.main()
