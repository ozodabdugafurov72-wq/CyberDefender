import concurrent.futures
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from agent.sensors.native_process_supervisor import FramedSensorTransport, NativeSensorSupervisorError


class AdmissionTests(unittest.TestCase):
    def supervisor(self, fault="malformed", budget=1):
        fixture = Path(__file__).parent / "support/fake_process_sensor_ipc_v1.py"
        s = FramedSensorTransport([sys.executable, str(fixture), "--fault", fault], timeout=2, max_restarts=budget)
        self.addCleanup(s.close)
        return s

    def test_all_faults_latch_all_entry_points(self):
        for fault in ("malformed", "wrong-sequence", "wrong-epoch", "wrong-nonce"):
            for budget in (0, 1):
                with self.subTest(fault=fault, budget=budget):
                    s = self.supervisor(fault, budget)
                    for _ in range(8):
                        for call in (s.start, s.snapshot):
                            try: call()
                            except NativeSensorSupervisorError: pass
                    self.assertTrue(s.exhausted)
                    self.assertEqual(s.generation, 1 + budget)
                    self.assertEqual(s.launch_attempts, 1 + budget)
                    self.assertEqual(s.restart_count, budget)
                    self.assertFalse(s.health_check()["child_alive"])

    def test_failed_spawn_debits_before_attempt(self):
        s = self.supervisor()
        with patch("agent.sensors.native_process_supervisor.subprocess.Popen", side_effect=OSError("synthetic")) as spawn:
            for _ in range(8):
                with self.assertRaises(NativeSensorSupervisorError): s.start()
            self.assertEqual(spawn.call_count, 2)
        self.assertEqual(s.restart_count, 1)
        self.assertEqual(s.generation, 0)

    def test_close_is_terminal_under_concurrency(self):
        s = self.supervisor()
        def invoke(i):
            try: (s.start if i % 2 else s.close)()
            except NativeSensorSupervisorError: pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(invoke, range(20)))
        generation = s.generation
        with self.assertRaises(NativeSensorSupervisorError): s.snapshot()
        self.assertEqual(s.generation, generation)
        self.assertFalse(s.health_check()["child_alive"])

    def test_elapsed_time_does_not_clear_exhaustion(self):
        s = self.supervisor(budget=0)
        for _ in range(3):
            try: s.snapshot()
            except NativeSensorSupervisorError: pass
        with patch("agent.sensors.native_process_supervisor.time.monotonic", return_value=10**12):
            with self.assertRaises(NativeSensorSupervisorError): s.start()
        self.assertEqual(s.launch_attempts, 1)

    def test_only_validated_stability_restores_retry_capacity(self):
        fixture=Path(__file__).parent/"support/fake_process_sensor_ipc_v1.py"
        s=FramedSensorTransport([sys.executable,str(fixture)],timeout=2,max_restarts=1)
        self.addCleanup(s.close)
        s.start(); s.child.kill(); s.child.wait(timeout=2)
        with patch("agent.sensors.native_process_supervisor.time.monotonic",return_value=100): s.snapshot()
        self.assertEqual(s._retry_debits,1)
        with patch("agent.sensors.native_process_supervisor.time.monotonic",return_value=130): s.snapshot()
        self.assertEqual(s._retry_debits,1)
        with patch("agent.sensors.native_process_supervisor.time.monotonic",return_value=161): s.snapshot()
        self.assertEqual(s._retry_debits,0)
        self.assertEqual(s.restart_count,1)


if __name__ == "__main__": unittest.main()
