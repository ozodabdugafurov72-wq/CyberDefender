import threading
import unittest
from agent.service_watchdog import ProgressWatchdog, active_time


class WatchdogTests(unittest.TestCase):
    def test_completed_work_not_process_existence(self):
        tick=[0]; w=ProgressWatchdog(deadline=10,clock=lambda:tick[0]); w.begin()
        self.assertEqual(w.snapshot()["state"],"DEGRADED")
        w.progress(True); self.assertEqual(w.snapshot()["state"],"HEALTHY")
        tick[0]=11; self.assertEqual(w.snapshot()["state"],"STALLED")
        self.assertEqual(w.snapshot()["action"],"OBSERVE_ONLY")

    def test_sleep_and_jitter_do_not_create_restart_authority(self):
        awake=[0]; w=ProgressWatchdog(deadline=10,clock=lambda:awake[0]); w.begin(); w.progress(True)
        # A sleep interval changes wall time, not the injected awake clock.
        self.assertEqual(w.snapshot()["state"],"HEALTHY")
        awake[0]=10; self.assertEqual(w.snapshot()["state"],"HEALTHY")
        awake[0]=11; self.assertEqual(w.snapshot()["authorization"],"NOT_GRANTED")
        w.progress(True); self.assertEqual(w.snapshot()["state"],"HEALTHY")

    def test_optional_failure_does_not_override_core_health(self):
        w=ProgressWatchdog(); w.begin()
        # Core health is the caller's independently assessed input; no Rust field
        # or restart actuator exists in this observer.
        w.progress(True); self.assertEqual(w.snapshot()["state"],"HEALTHY")
        w.progress(False); self.assertEqual(w.snapshot()["state"],"DEGRADED")

    def test_clock_and_observer_are_bounded(self):
        self.assertGreaterEqual(active_time(),0)
        tick=[10]; w=ProgressWatchdog(clock=lambda:tick[0]); w.begin(); w.progress(True)
        tick[0]=0; self.assertEqual(w.snapshot()["state"],"DEGRADED")
        self.assertEqual(set(w.snapshot()),{"state","completed","age_seconds","deadline_seconds","action","authorization"})

    def test_failed_probes_do_not_refresh_useful_work_deadline(self):
        tick=[0]; w=ProgressWatchdog(deadline=10,clock=lambda:tick[0]); w.begin()
        for now in range(1,12):
            tick[0]=now; w.progress(False)
        self.assertEqual(w.snapshot()["state"],"STALLED")
        self.assertEqual(w.snapshot()["completed"],0)


if __name__ == "__main__": unittest.main()
