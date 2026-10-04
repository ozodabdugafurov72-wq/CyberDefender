from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class QuarantineV2LabIntegrationTests(unittest.TestCase):
    def test_real_policy_verifier_safety_and_lab_runner(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        runner = repository_root / "scripts" / "run_quarantine_canary_v2.py"
        completed = subprocess.run(
            [sys.executable, "-B", str(runner)],
            cwd=repository_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "VERIFIED_QUARANTINED")
        self.assertFalse(report["original_present"])
        self.assertTrue(report["vault_object_verified"])
        self.assertTrue(report["evidence_verified"])
        self.assertTrue(report["receipt_verified"])
        self.assertEqual(report["verification_outcome"], "QUARANTINED_VERIFIED")
        self.assertEqual(report["production_authorization"], "NOT_GRANTED")
        self.assertEqual(report["production_safety_decision"], "DENY")
        self.assertEqual(report["lab_authorization"], "QUARANTINE_CAPABILITY_CONSUMED")
        self.assertEqual(len(report["target_sha256"]), 64)
        self.assertEqual(len(report["object_sha256"]), 64)
        self.assertNotIn("token_mac", completed.stdout)


if __name__ == "__main__":
    unittest.main()
