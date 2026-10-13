from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

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
            initial._persist_ack_state({item.event_id for item in events})

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


if __name__ == "__main__":
    unittest.main()
