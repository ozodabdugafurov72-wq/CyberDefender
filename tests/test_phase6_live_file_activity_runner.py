from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class Phase6LiveFileActivityRunnerTests(unittest.TestCase):
    def test_default_mode_is_read_only_and_does_not_inject_events(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        runner = repository / "scripts" / "run_phase6_live_file_activity_test.py"
        completed = subprocess.run(
            [sys.executable, "-B", str(runner)],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual("NOT_EXECUTED", report["status"])
        self.assertFalse(report["simulator_event_injection"])
        self.assertEqual("NOT_GRANTED", report["production_authorization"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
