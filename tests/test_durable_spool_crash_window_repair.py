from __future__ import annotations

import json
import os
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

    @staticmethod
    def write_ack_window(spool_dir: Path, ordered_ids: list[str]) -> None:
        (spool_dir / "acked_state.json").write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "status": "ACKED",
                    # Historical snapshots were sorted, so the compatibility
                    # journal is required to recover the actual ACK order.
                    "acked_ids": sorted(ordered_ids),
                }
            ),
            encoding="utf-8",
        )
        (spool_dir / "acked.jsonl").write_text(
            "".join(json.dumps({"event_id": item}) + "\n" for item in ordered_ids),
            encoding="utf-8",
        )

    def test_limit_plus_one_snapshot_repairs_pending_before_pruning(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-crash-window-") as root:
            spool_dir = Path(root) / "spool"
            initial = DurableEventSpool(spool_dir, policy=self.policy(4))
            events = [event(index) for index in range(3)]
            for item in events:
                self.assertTrue(initial.append(item))

            # Simulate a crash after ACK snapshot commit and before compact().
            self.write_ack_window(spool_dir, [item.event_id for item in events])

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
            self.write_ack_window(spool_dir, [item.event_id for item in events[:3]])
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

    def test_limit_plus_one_preserves_most_recent_ack_window(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-ack-order-") as root:
            spool_dir = Path(root) / "spool"
            spool_dir.mkdir(parents=True)
            ordered = ["z-oldest", "a-middle", "m-newest"]
            self.write_ack_window(spool_dir, ordered)

            repaired = DurableEventSpool(spool_dir, policy=self.policy(2))

            self.assertEqual("HEALTHY", repaired.health_check()["status"])
            self.assertEqual({"a-middle", "m-newest"}, repaired._acked)
            self.assertEqual(["a-middle", "m-newest"], repaired._acked_order)

    def test_limit_plus_one_fails_closed_on_untrusted_order_journal(self) -> None:
        hostile_journals = {
            "mismatch": json.dumps({"event_id": "different"}) + "\n",
            "duplicate": "".join(
                json.dumps({"event_id": item}) + "\n"
                for item in ("event-1", "event-1", "event-3")
            ),
            "corrupt": "{not-json\n",
        }
        for label, journal in hostile_journals.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix="cd-spool-ack-hostile-"
            ) as root:
                spool_dir = Path(root) / "spool"
                spool_dir.mkdir(parents=True)
                self.write_ack_window(spool_dir, ["event-1", "event-2", "event-3"])
                (spool_dir / "acked.jsonl").write_text(journal, encoding="utf-8")

                rejected = DurableEventSpool(spool_dir, policy=self.policy(2))

                health = rejected.health_check()
                self.assertEqual("DEGRADED", health["status"])
                self.assertFalse(health["terminal_state_safe"])

    def test_limit_plus_one_snapshot_write_failure_retries_idempotently(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-ack-retry-") as root:
            spool_dir = Path(root) / "spool"
            initial = DurableEventSpool(spool_dir, policy=self.policy(4))
            events = [event(index) for index in range(4)]
            for item in events:
                self.assertTrue(initial.append(item))
            self.write_ack_window(spool_dir, [item.event_id for item in events[:3]])
            expected_pending = {events[3].event_id}
            original_atomic_write = DurableEventSpool._atomic_write

            def snapshot_failure(self, path: Path, payload: bytes) -> None:
                if path == self.acked_state_path:
                    raise PermissionError("simulated ACK snapshot sharing violation")
                original_atomic_write(self, path, payload)

            with mock.patch.object(DurableEventSpool, "_atomic_write", new=snapshot_failure):
                interrupted = DurableEventSpool(spool_dir, policy=self.policy(2))

            self.assertEqual("DEGRADED", interrupted.health_check()["status"])
            self.assertEqual(
                expected_pending,
                {item["event_id"] for item in interrupted.pending_records()},
            )

            recovered = DurableEventSpool(spool_dir, policy=self.policy(2))
            self.assertEqual("HEALTHY", recovered.health_check()["status"])
            self.assertEqual({events[1].event_id, events[2].event_id}, recovered._acked)
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

    def test_duplicate_recovery_ack_is_idempotent_after_terminal_compaction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-recovery-duplicate-") as root:
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
                    raise PermissionError("simulated compatibility-journal sharing violation")
                original_rewrite(path, records)

            with mock.patch.object(spool, "_rewrite_jsonl", side_effect=sharing_violation):
                self.assertTrue(spool.ack(events[2].event_id))

            # The recovery cursor can publish the same pending record twice
            # before the first delivery's durable ACK becomes visible to its
            # next bounded sweep.  Reconfirming an already durable ACK must be
            # idempotent rather than reported as a consumer failure.
            self.assertTrue(spool.ack(events[2].event_id))
            self.assertEqual([], spool.pending_records())
            self.assertLessEqual(len(spool._acked), 2)
            self.assertEqual(1, spool.health_check()["terminal_compatibility_failures"])

    def test_full_terminal_window_acks_across_cycles_without_pending_rewrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-full-window-live-") as root:
            spool_dir = Path(root) / "spool"
            spool = DurableEventSpool(spool_dir, policy=self.policy(3))
            historical = [event(index) for index in range(3)]
            for item in historical:
                self.assertTrue(spool.append(item))
                self.assertTrue(spool.ack(item.event_id))
            self.assertTrue(spool.compact())
            self.assertEqual([], spool.pending_records())

            original_atomic_write = spool._atomic_write

            def pending_rewrite_locked(path: Path, payload: bytes) -> None:
                if path == spool.pending_path:
                    raise PermissionError("simulated transient live pending-file sharing")
                original_atomic_write(path, payload)

            # A full terminal window must not force a pending-file replacement
            # when a retired tombstone has no physical pending row.  This is
            # exercised over multiple runtime-like cycles so dead rows from a
            # prior successful ACK remain in the append journal.
            with mock.patch.object(
                spool, "_atomic_write", side_effect=pending_rewrite_locked
            ):
                for index in range(3, 6):
                    current = event(index)
                    self.assertTrue(spool.append(current))
                    self.assertTrue(spool.ack(current.event_id))

            stats = spool.get_stats()
            self.assertEqual(0, stats["ack_failures"])
            self.assertLessEqual(stats["acked"], 3)
            self.assertTrue(stats["terminal_state_safe"])
            self.assertEqual([], spool.pending_records())
            restarted = DurableEventSpool(spool_dir, policy=self.policy(3))
            self.assertEqual("HEALTHY", restarted.health_check()["status"])
            self.assertEqual([], restarted.pending_records())

    def test_full_terminal_window_malformed_pending_preserves_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-spool-full-window-corrupt-") as root:
            spool_dir = Path(root) / "spool"
            spool = DurableEventSpool(spool_dir, policy=self.policy(3))
            historical = [event(index) for index in range(3)]
            for item in historical:
                self.assertTrue(spool.append(item))
                self.assertTrue(spool.ack(item.event_id))
            self.assertTrue(spool.compact())

            current = event(3)
            self.assertTrue(spool.append(current))
            with spool.pending_path.open("ab") as handle:
                handle.write(b'{"event_id":')
                handle.flush()
                os.fsync(handle.fileno())
            pending_before = spool.pending_path.read_bytes()
            ack_before = spool.acked_state_path.read_bytes()

            self.assertFalse(spool.ack(current.event_id))
            self.assertEqual(pending_before, spool.pending_path.read_bytes())
            self.assertEqual(ack_before, spool.acked_state_path.read_bytes())
            self.assertEqual(1, spool.get_stats()["ack_failures"])


if __name__ == "__main__":
    unittest.main()
