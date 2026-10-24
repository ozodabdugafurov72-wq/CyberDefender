from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_distribution_package import build


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe",
    "tests/test_runtime_tenant_binding_health_gate_v1.py",
    "tests/test_tenantless_quarantine_durability_v1.py",
}


class DistributionPackageContentTests(unittest.TestCase):
    def test_distribution_contains_runtime_gate_tests_rust_and_provenance(self):
        names = {
            row.strip()
            for row in (ROOT / "distribution-files.txt").read_text(encoding="utf-8").splitlines()
            if row.strip() and not row.lstrip().startswith("#")
        }
        self.assertTrue(REQUIRED.issubset(names))

        with tempfile.TemporaryDirectory(prefix="cd-package-content-") as td:
            package = build(Path(td) / "candidate.zip")
            with zipfile.ZipFile(package) as archive:
                archive_names = set(archive.namelist())
                self.assertTrue(REQUIRED.issubset(archive_names))
                manifest = json.loads(archive.read("release-manifest.json"))

        expected_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        expected_tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
        ).strip()
        self.assertEqual(manifest["commit"], expected_commit)
        self.assertEqual(manifest["tree"], expected_tree)
        self.assertEqual(manifest["schema"], "cyberdefender.distribution-manifest.v1")
        self.assertEqual(manifest["file_count"], len(names))


if __name__ == "__main__":
    unittest.main()
