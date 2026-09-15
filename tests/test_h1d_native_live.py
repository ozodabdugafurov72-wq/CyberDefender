"""Only the repository's local Rust binary and newly owned test children."""
import gc
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import unittest
import psutil
from agent.sensors.native_process_supervisor import NativeProcessSensorSupervisor

ROOT=Path(__file__).resolve().parents[1]
BINARY=ROOT/"native/process_sensor_v0_5_1/target/debug/cyberdefender-process-sensor.exe"


class NativeLiveTests(unittest.TestCase):
    def test_native_ipc_pin_binding_cleanup_and_handle_bound(self):
        self.assertTrue(BINARY.is_file())
        pin=hashlib.sha256(BINARY.read_bytes()).hexdigest()
        def cycle():
            s=NativeProcessSensorSupervisor(BINARY,expected_sha256=pin,max_restarts=0)
            try:
                result=s.snapshot()
                self.assertEqual(result["ipc"]["sensor_pid"],s.child_pid)
                self.assertEqual(result["ipc"]["supervisor_pid"],os.getpid())
                self.assertTrue(s.health_check()["direct_pid_verified"])
                child=psutil.Process(s.child_pid)
            finally: s.close()
            self.assertFalse(child.is_running())
        cycle(); gc.collect(); process=psutil.Process(); before=process.num_handles()
        for _ in range(10): cycle()
        gc.collect(); after=process.num_handles()
        self.assertLessEqual(after-before,4)
        print(f"RESOURCE_HANDLES before={before} after={after} cycles=10")

    def test_native_parent_death_no_persistent_child(self):
        code='''
import hashlib,os,sys,time
from pathlib import Path
from agent.sensors.native_process_supervisor import NativeProcessSensorSupervisor
p=Path(sys.argv[1])
s=NativeProcessSensorSupervisor(p,expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest())
s.snapshot()
print(s.child_pid,flush=True)
time.sleep(.5)
os._exit(19)
'''
        parent=subprocess.Popen([sys.executable,"-c",code,str(BINARY)],stdout=subprocess.PIPE)
        try:
            pid=int(parent.stdout.readline()); child=psutil.Process(pid)
            self.assertEqual(parent.wait(timeout=10),19)
            child.wait(timeout=5)
        finally:
            if parent.poll() is None: parent.kill(); parent.wait(timeout=3)
            parent.stdout.close()


if __name__ == "__main__": unittest.main()
