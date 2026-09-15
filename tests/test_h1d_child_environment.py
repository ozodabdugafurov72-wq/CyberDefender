import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from agent.sensors.windows_child_containment import sensor_environment, launch_contained
from agent.sensors.native_process_supervisor import NativeProcessSensorSupervisor, NativeSensorSupervisorError


class EnvironmentTests(unittest.TestCase):
    def test_allowlist(self):
        with patch.dict(os.environ, {"CYBERDEFENDER_STORAGE_KEY_B64": "SYNTHETIC_KEY", "FLEET_TOKEN": "SYNTHETIC_TOKEN", "PATH": "SYNTHETIC_PATH"}):
            env = sensor_environment("a" * 64, 123)
        self.assertEqual(set(env), {"SYSTEMROOT", "WINDIR", "CYBERDEFENDER_SENSOR_LAUNCH_NONCE", "CYBERDEFENDER_SENSOR_SUPERVISOR_PID"})
        child = launch_contained([sys._base_executable, "-c", "import json,os; print(json.dumps(dict(os.environ)))"], env)
        try:
            inherited = json.loads(child.stdout.read())
            child.wait(timeout=3)
            self.assertEqual(inherited, env)
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=3)
            child.stdin.close(); child.stdout.close(); child.release()

    def test_replacement_rejected_on_retry_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"sensor.exe"; path.write_bytes(b"trusted")
            s=NativeProcessSensorSupervisor(path, expected_sha256=hashlib.sha256(b"trusted").hexdigest(), max_restarts=1)
            with patch("agent.sensors.windows_child_containment.launch_contained", side_effect=OSError()) as create:
                with self.assertRaises(NativeSensorSupervisorError): s.start()
                path.write_bytes(b"substitution")
                with self.assertRaises(NativeSensorSupervisorError): s.start()
                self.assertEqual(create.call_count, 1)
                self.assertEqual(s.launch_attempts, 2)
            s.close()

    def test_hash_lock_denies_write_during_launch(self):
        from agent.sensors.windows_child_containment import verified_binary
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"sensor.exe"; path.write_bytes(b"trusted")
            with verified_binary(path, hashlib.sha256(b"trusted").hexdigest()):
                with self.assertRaises(OSError): path.write_bytes(b"changed")


if __name__ == "__main__": unittest.main()
