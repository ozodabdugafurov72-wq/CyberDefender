from __future__ import annotations

import unittest

from agent.disconnected.primary_reachability import (
    PrimaryReachabilityTracker,
)


class FakeClock:

    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


class PrimaryReachabilityTrackerTests(
    unittest.TestCase
):

    def test_initial_state_unknown(self):
        t = PrimaryReachabilityTracker()

        s = t.snapshot()

        self.assertIsNone(s.reachable)
        self.assertFalse(
            s.evidence_available
        )

    def test_success_is_true(self):
        t = PrimaryReachabilityTracker()

        t.record(
            True,
            source="heartbeat",
        )

        self.assertIs(
            t.current(),
            True,
        )

    def test_failure_is_false(self):
        t = PrimaryReachabilityTracker()

        t.record(
            False,
            source="heartbeat",
        )

        self.assertIs(
            t.current(),
            False,
        )

    def test_unknown_is_preserved(self):
        t = PrimaryReachabilityTracker()

        t.record(
            None,
            source="heartbeat",
        )

        self.assertIsNone(
            t.current()
        )

    def test_stale_evidence_becomes_unknown(self):
        clock = FakeClock()

        t = PrimaryReachabilityTracker(
            stale_after_seconds=30.0,
            clock=clock,
        )

        t.record(
            True,
            source="heartbeat",
        )

        self.assertIs(
            t.current(),
            True,
        )

        clock.advance(31.0)

        s = t.snapshot()

        self.assertTrue(s.stale)
        self.assertIsNone(
            s.reachable
        )

    def test_new_failure_replaces_old_success(self):
        t = PrimaryReachabilityTracker()

        t.record(
            True,
            source="heartbeat",
        )

        t.record(
            False,
            source="heartbeat",
        )

        self.assertIs(
            t.current(),
            False,
        )

    def test_health_never_grants_authority(self):
        t = PrimaryReachabilityTracker()

        h = t.health_snapshot()

        self.assertEqual(
            h["authority"],
            "NONE",
        )

        self.assertEqual(
            h["authorization"],
            "NOT_GRANTED",
        )

        self.assertFalse(
            h["authoritative"],
        )

        self.assertFalse(
            h["network_probe"],
        )

        self.assertFalse(
            h["os_actions"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
