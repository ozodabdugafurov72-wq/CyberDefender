import os
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
from agent.sensors.native_process_supervisor import FramedSensorTransport, NativeSensorSupervisorError, NativeProcessSensorSupervisor


class OwnershipTests(unittest.TestCase):
    def test_failed_cleanup_retains_owner_and_blocks_launch(self):
        s = FramedSensorTransport([sys.executable])
        child = Mock(pid=123)
        child.poll.return_value = None
        child.kill.side_effect = OSError()
        child.wait.side_effect = subprocess.TimeoutExpired("test", 1)
        s.child = child; s.child_pid = 123
        with patch.object(s, "_create_child") as create:
            for operation in (s.start, s.snapshot, s.close):
                with self.assertRaises(NativeSensorSupervisorError): operation()
            self.assertEqual(create.call_count, 0)
        self.assertIs(s.child, child)
        self.assertEqual(s.child_pid, 123)
        child.poll.return_value = 1
        s.close()
        self.assertIsNone(s.child)

    @unittest.skipUnless(os.name == "nt", "Windows kernel containment")
    def test_job_close_kills_blocked_child(self):
        from agent.sensors.windows_child_containment import launch_contained
        child = launch_contained([sys.executable, "-c", "import time; time.sleep(60)"], dict(os.environ))
        try:
            self.assertIsNone(child.poll())
            child._job.Close()
            child.wait(timeout=3)
            self.assertIsNotNone(child.poll())
        finally:
            child._handle.Close()
            child.stdin.close(); child.stdout.close()

    def test_containment_failure_never_falls_back(self):
        s = NativeProcessSensorSupervisor(Path(sys.executable), expected_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(), max_restarts=0)
        with patch("agent.sensors.windows_child_containment.launch_contained", side_effect=OSError()), patch("subprocess.Popen") as spawn:
            with self.assertRaises(NativeSensorSupervisorError): s.start()
            with self.assertRaises(NativeSensorSupervisorError): s.start()
            self.assertEqual(spawn.call_count, 0)
        s.close()

    @unittest.skipUnless(os.name == "nt", "Windows parent death")
    def test_parent_death_closes_job(self):
        import psutil
        code = '''
import os,sys,time
from agent.sensors.windows_child_containment import launch_contained
p=launch_contained([sys._base_executable,'-c','import os,time; print(os.getpid(),flush=True); time.sleep(60)'],dict(os.environ))
print(p.stdout.readline().decode().strip(),flush=True)
time.sleep(.3)
os._exit(17)
'''
        parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
        try:
            pid = int(parent.stdout.readline())
            child = psutil.Process(pid)
            self.assertEqual(parent.wait(timeout=5), 17)
            child.wait(timeout=5)
        finally:
            if parent.poll() is None: parent.kill(); parent.wait(timeout=3)
            parent.stdout.close()


if __name__ == "__main__": unittest.main()
