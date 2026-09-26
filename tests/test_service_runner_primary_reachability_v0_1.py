from __future__ import annotations

import unittest

from agent.disconnected.primary_reachability import (
    PrimaryReachabilityTracker,
)

from agent.service_runner import (
    ServiceRunner,
)


class FakeSafety:

    def enter_safe_mode(
        self,
        reason,
    ):
        return None


class FakeRuntime:

    VERSION = "2.4"

    def __init__(
        self,
        *,
        health_failure=False,
    ):
        self.running = False
        self.shutdown_requested = False
        self.safety = FakeSafety()
        self.last_error = None
        self.health_failure = health_failure

    def begin_managed_loop(self):
        self.running = True

    def run_cycle(self):
        return None

    def health_snapshot(self):
        if self.health_failure:
            raise RuntimeError(
                "synthetic health failure"
            )

        return {
            "runtime": {
                "status":
                    "HEALTHY",
            },

            "resource_guard": {
                "state":
                    "NORMAL",
            },
        }

    def stop(
        self,
        reason,
    ):
        self.running = False

    def close(self):
        return None


class FakeClient:

    def __init__(
        self,
        *,
        register_result=True,
        heartbeat_result=True,
        heartbeat_raises=False,
    ):
        self.register_result = register_result
        self.heartbeat_result = heartbeat_result
        self.heartbeat_raises = heartbeat_raises

    def register(self, **kwargs):
        return self.register_result

    def heartbeat(self, **kwargs):
        if self.heartbeat_raises:
            raise OSError(
                "synthetic unreachable"
            )

        return self.heartbeat_result


class ServiceRunnerPrimaryEvidenceTests(
    unittest.TestCase
):

    def test_successful_heartbeat_sets_true(self):
        tracker = PrimaryReachabilityTracker()

        runner = ServiceRunner(
            lambda: FakeRuntime(),
            interval_seconds=0.1,
            telemetry_client=FakeClient(),
            primary_reachability_tracker=tracker,
        )

        runner.run(
            max_cycles=1
        )

        s = tracker.snapshot()

        self.assertIs(
            s.reachable,
            True,
        )

        self.assertEqual(
            s.source,
            "heartbeat",
        )

    def test_rejected_heartbeat_sets_false(self):
        tracker = PrimaryReachabilityTracker()

        runner = ServiceRunner(
            lambda: FakeRuntime(),
            interval_seconds=0.1,
            telemetry_client=FakeClient(
                heartbeat_result=False,
            ),
            primary_reachability_tracker=tracker,
        )

        runner.run(
            max_cycles=1
        )

        self.assertIs(
            tracker.current(),
            False,
        )

    def test_heartbeat_exception_sets_false(self):
        tracker = PrimaryReachabilityTracker()

        runner = ServiceRunner(
            lambda: FakeRuntime(),
            interval_seconds=0.1,
            telemetry_client=FakeClient(
                heartbeat_raises=True,
            ),
            primary_reachability_tracker=tracker,
        )

        runner.run(
            max_cycles=1
        )

        self.assertIs(
            tracker.current(),
            False,
        )

    def test_no_client_keeps_unknown(self):
        tracker = PrimaryReachabilityTracker()

        runner = ServiceRunner(
            lambda: FakeRuntime(),
            interval_seconds=0.1,
            telemetry_client=None,
            primary_reachability_tracker=tracker,
        )

        runner.run(
            max_cycles=1
        )

        self.assertIsNone(
            tracker.current()
        )

    def test_runtime_health_failure_does_not_invent_new_network_failure(self):
        tracker = PrimaryReachabilityTracker()

        runner = ServiceRunner(
            lambda: FakeRuntime(
                health_failure=True,
            ),
            interval_seconds=0.1,
            telemetry_client=FakeClient(
                register_result=True,
            ),
            primary_reachability_tracker=tracker,
        )

        runner.run(
            max_cycles=1
        )

        # Registration succeeded. Heartbeat was never attempted
        # because health preparation failed, so no false network
        # failure may overwrite the recent success.
        self.assertIs(
            tracker.current(),
            True,
        )

        self.assertEqual(
            tracker.snapshot().source,
            "register",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
