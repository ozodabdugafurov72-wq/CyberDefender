from __future__ import annotations

import threading
import unittest

from agent.service_runner import ServiceRunner


class Runtime:
    VERSION = "2.4"

    def __init__(self) -> None:
        self.running = False
        self.cycles = 0
        self.component_failures = 0
        self.resource_state = "NORMAL"
        self.safety = type("Safety", (), {"enter_safe_mode": lambda *_: None})()

    def begin_managed_loop(self) -> None:
        self.running = True

    def run_cycle(self) -> None:
        self.cycles += 1

    def health_snapshot(self) -> dict:
        return {
            "runtime": {
                "status": "HEALTHY",
                "running": self.running,
                "component_failures": self.component_failures,
                "cycle_count": self.cycles,
            },
            "resource_guard": {"state": self.resource_state},
        }

    def stop(self, _reason: str) -> None:
        self.running = False

    def close(self) -> None:
        pass


class Telemetry:
    def __init__(self) -> None:
        self.heartbeats: list[dict] = []

    def register(self, **_kwargs) -> bool:
        return True

    def heartbeat(self, **kwargs) -> bool:
        self.heartbeats.append(dict(kwargs))
        return True


class ProductionHealthGateTests(unittest.TestCase):
    def test_three_completed_cycles_are_required_before_healthy_running(self) -> None:
        runtime = Runtime()
        telemetry = Telemetry()
        runner = ServiceRunner(lambda: runtime, interval_seconds=0.1, telemetry_client=telemetry)
        runner.run(max_cycles=3)

        self.assertEqual([row["health_state"] for row in telemetry.heartbeats], [
            "UNKNOWN", "UNKNOWN", "HEALTHY",
        ])
        self.assertEqual([row["service_state"] for row in telemetry.heartbeats], [
            "STARTING", "STARTING", "RUNNING",
        ])
        self.assertEqual(telemetry.heartbeats[-1]["last_error"], None)

    def test_any_failed_invariant_resets_the_consecutive_streak(self) -> None:
        runner = ServiceRunner(lambda: None, stop_event=threading.Event())
        healthy = {
            "runtime": {"status": "HEALTHY", "running": True, "component_failures": 0},
            "resource_guard": {"state": "NORMAL"},
        }
        self.assertFalse(runner._observe_runtime_health_gate(healthy))
        self.assertFalse(runner._observe_runtime_health_gate(healthy))
        failed = {
            "runtime": {"status": "HEALTHY", "running": True, "component_failures": 1},
            "resource_guard": {"state": "NORMAL"},
        }
        self.assertFalse(runner._observe_runtime_health_gate(failed))
        self.assertEqual(runner._healthy_cycle_streak, 0)
        self.assertFalse(runner._observe_runtime_health_gate(healthy))
        self.assertFalse(runner._observe_runtime_health_gate(healthy))
        self.assertTrue(runner._observe_runtime_health_gate(healthy))


if __name__ == "__main__":
    unittest.main()
