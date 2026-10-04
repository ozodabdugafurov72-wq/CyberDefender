from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class Phase61InstalledDetectionRunnerTests(unittest.TestCase):
    def test_runner_executes_real_chain_and_negative_control(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        runner = repository / "scripts" / "run_phase6_installed_detection_test.py"
        completed = subprocess.run(
            [sys.executable, "-B", str(runner)],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual("VERIFIED_QUARANTINED", report["status"])
        self.assertIn("RANSOMWARE_BEHAVIOR", report["detection_types_produced"])
        self.assertFalse(report["negative_control_ransomware_behavior"])
        self.assertEqual("CRITICAL", report["final_risk_level"])
        self.assertEqual("REQUIRE_VERIFICATION", report["policy_outcome"])
        self.assertEqual("VERIFIED", report["independent_verification"])
        self.assertEqual("REQUIRE_VERIFICATION", report["quarantine_policy_outcome"])
        self.assertEqual("VERIFIED", report["quarantine_verification_outcome"])
        self.assertEqual("NOT_GRANTED", report["production_authorization"])
        self.assertEqual("QUARANTINE_CAPABILITY_CONSUMED", report["lab_authorization"])
        self.assertFalse(report["network_activity"])
        self.assertFalse(report["user_files_touched"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
