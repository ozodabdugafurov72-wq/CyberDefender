from __future__ import annotations

import copy
import json
import time
import unittest

from tests.support.fake_process_sensor_ipc_v1 import snapshot
from agent.sensors.rust_process_v05_contract import RustProcessV05Error, validate_v05_snapshot


class ContractTests(unittest.TestCase):
    def fixture(self):
        return snapshot(7, "epoch-1", supervisor_pid=1234, sensor_pid=5678)

    def test_canonical_ipc_snapshot(self):
        data = validate_v05_snapshot(
            self.fixture(),
            now=time.time(),
            require_ipc=True,
            expected_sequence=7,
            expected_epoch="epoch-1",
            expected_supervisor_pid=1234,
            expected_sensor_pid=5678,
        )
        self.assertEqual(data["schema"], "cd.process.v5")
        self.assertEqual(data["processes"][0]["exe"], "C:\\fake.exe")
        self.assertEqual(data["processes"][0]["integrity_level"], "MEDIUM")

    def test_schema_expansion_rejected(self):
        data = self.fixture()
        data["unexpected"] = True
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time())

    def test_status_value_consistency(self):
        data = self.fixture()
        data["processes"][0]["exe"] = None
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time())

    def test_cpu_memory_deferred_contract(self):
        data = self.fixture()
        data["processes"][0]["cpu_percent"] = 1.0
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time())

    def test_ipc_sequence_and_epoch(self):
        data = self.fixture()
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time(), expected_sequence=8)
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time(), expected_epoch="other")


    def test_ipc_pid_binding(self):
        data = self.fixture()
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time(), expected_supervisor_pid=9999)
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time(), expected_sensor_pid=9999)

    def test_duplicate_json_key_rejected(self):
        raw = b'{"schema":"cd.process.v5","schema":"cd.process.v5"}'
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(raw, now=time.time())

    def test_partial_skip_contract(self):
        data = self.fixture()
        data["partial"] = True
        data["skipped"] = 1
        data["skipped_processes"] = [
            {"pid": 0, "reason": "SYSTEM_IDLE_UNQUERYABLE", "win32_error": 87}
        ]
        validated = validate_v05_snapshot(data, now=time.time())
        self.assertTrue(validated["partial"])

        bad = copy.deepcopy(data)
        bad["skipped_processes"][0]["win32_error"] = 5
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(bad, now=time.time())

    def test_utf8_and_command_line_bounds(self):
        data = self.fixture()
        data["processes"][0]["cmdline"] = ["x" * 32769]
        with self.assertRaises(RustProcessV05Error):
            validate_v05_snapshot(data, now=time.time())

    def test_raw_json_roundtrip(self):
        raw = json.dumps(self.fixture(), separators=(",", ":")).encode()
        data = validate_v05_snapshot(raw, now=time.time())
        self.assertEqual(data["process_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
