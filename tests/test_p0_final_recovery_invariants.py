from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from agent.event import SecurityEvent
from agent.service_crash_guard import CrashPolicy, FAILURE_CODES, fresh_record
import agent.service_crash_store as crash_store
from agent.service_lifecycle import run_guarded_service
from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy


class MemoryStore:
    def __init__(self):
        self.record = fresh_record("CyberDefenderAgent")

    def load(self):
        return copy.deepcopy(self.record)

    def write(self, record):
        assert record["revision"] == self.record["revision"]
        updated = copy.deepcopy(record)
        updated["revision"] += 1
        crash_store.validate_record(updated, updated["service"])
        self.record = updated
        return self.load()

    def close(self):
        pass


class FinalRecoveryInvariants(unittest.TestCase):
    def test_ack_writer_never_commits_above_terminal_limit(self):
        policy = DurableSpoolPolicy(
            max_pending_events=8,
            max_pending_bytes=65536,
            max_event_bytes=8192,
            protected_reserve_events=2,
            protected_reserve_bytes=8192,
            max_recovery_batch=2,
            max_recovery_scan_bytes=65536,
            compaction_terminal_ops=100,
            compaction_min_dead_bytes=65536,
            max_terminal_records=2,
            max_terminal_state_bytes=4096,
        )
        with tempfile.TemporaryDirectory(prefix="cd-ack-bound-") as raw:
            spool = DurableEventSpool(Path(raw), policy=policy)
            events = [SecurityEvent(event_type="BOUND", severity="HIGH", value=i, source="test", message="bound") for i in range(3)]
            for event in events:
                self.assertTrue(spool.append(event))
            observed = []
            original = spool._atomic_write

            def observe(path, payload):
                if path == spool.acked_state_path:
                    observed.append(len(json.loads(payload)["acked_ids"]))
                return original(path, payload)

            with mock.patch.object(spool, "_atomic_write", side_effect=observe):
                for event in events:
                    self.assertTrue(spool.ack(event.event_id))
            self.assertLessEqual(max(observed), 2)
            self.assertEqual([], spool.pending_records())

    def test_agent_failed_attempt_exits_host_without_clean_stop(self):
        calls = []
        store = MemoryStore()

        def fail(guard):
            calls.append(1)
            guard.failed("UNHANDLED_EXCEPTION")
            return False

        result = run_guarded_service(
            "CyberDefenderAgent",
            threading.Event(),
            fail,
            policy=CrashPolicy(cooldown_seconds=1.0),
            store_factory=lambda: store,
            boot_factory=lambda: "a",
            observer=lambda *_: None,
            clock=lambda: 10.0,
            stop_on_attempt_failure=True,
        )
        self.assertFalse(result)
        self.assertEqual(1, len(calls))
        self.assertFalse(store.record["clean_stop"])
        self.assertFalse(store.record["active_attempt"])

    def test_failure_codes_have_one_authoritative_set(self):
        self.assertIs(crash_store.FAILURE_CODES, FAILURE_CODES)

    def test_runtime_gate_code_is_closed_and_sanitized(self):
        from agent.main import RuntimeBootstrapError
        from agent.service_diagnostics import failure_fields

        fields = failure_fields(RuntimeBootstrapError("secret", gate_code="KEY_NOT_ACTIVE"), "STARTUP")
        self.assertEqual("KEY_NOT_ACTIVE", fields["gate_code"])
        self.assertEqual("key_manager", fields["failing_component"])
        unknown = failure_fields(RuntimeBootstrapError("secret", gate_code="SECRET_VALUE"), "STARTUP")
        self.assertEqual("BOOTSTRAP_UNCLASSIFIED", unknown["gate_code"])
        self.assertNotIn("secret", json.dumps(fields).lower())


if __name__ == "__main__":
    unittest.main()
