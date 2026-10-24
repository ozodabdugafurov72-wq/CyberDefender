from __future__ import annotations

import copy
import unittest

from agent.service_crash_guard import fresh_record
from agent.service_crash_store import CrashStoreError, authorize_probe_transition


class AuthorizeProbeTransitionTests(unittest.TestCase):
    def test_interrupted_attempt_is_debited_without_mutating_input(self) -> None:
        record = fresh_record("CyberDefenderAgent")
        record.update(
            revision=41,
            generation=7,
            cumulative_failures=2,
            attempts_since_stable=1,
            probes_used=1,
            repair_count=4,
            active_attempt=True,
            clean_stop=False,
            state="PROBE",
            boot="abc-123",
            last_progress=123.0,
        )
        before = copy.deepcopy(record)

        candidate = authorize_probe_transition(record)

        self.assertEqual(record, before)
        self.assertEqual(candidate["revision"], 41)
        self.assertEqual(candidate["cumulative_failures"], 3)
        self.assertEqual(candidate["repair_count"], 5)
        self.assertEqual(candidate["probes_used"], 0)
        self.assertEqual(candidate["state"], "LATCHED")
        self.assertFalse(candidate["active_attempt"])
        self.assertEqual(candidate["recent_failures"][-1], {
            "generation": 7,
            "boot": "abc-123",
            "code": "PREVIOUS_ATTEMPT_INTERRUPTED",
            "tick": 123.0,
        })

    def test_clean_record_preserves_failure_count_and_invalid_input_fails(self) -> None:
        record = fresh_record("CyberDefenderAgent")
        candidate = authorize_probe_transition(record)
        self.assertEqual(candidate["cumulative_failures"], 0)
        self.assertEqual(candidate["repair_count"], 1)
        with self.assertRaises(CrashStoreError):
            authorize_probe_transition({"service": "CyberDefenderAgent"})


if __name__ == "__main__":
    unittest.main()
