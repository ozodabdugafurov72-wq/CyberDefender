from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "phase6_dependency_manifest", ROOT / "scripts" / "phase6_dependency_manifest.py"
)
assert SPEC and SPEC.loader
manifest_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manifest_module)


class Phase6DependencyManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = manifest_module.build_manifest(ROOT)

    def test_dependency_closure_is_complete(self) -> None:
        manifest_module.validate_manifest(self.manifest, ROOT)
        self.assertTrue(self.manifest["closure_complete"])
        paths = {row["relative_path"] for row in self.manifest["files"]}
        self.assertIn("agent/__init__.py", paths)
        self.assertIn("agent/service_crash_store.py", paths)
        self.assertIn("agent/service_lifecycle.py", paths)
        self.assertGreaterEqual(len(paths), 80)

    def test_service_lifecycle_transitively_reaches_crash_store(self) -> None:
        row = next(item for item in self.manifest["files"] if item["relative_path"] == "agent/service_lifecycle.py")
        self.assertIn("agent/service_crash_store.py", row["direct_local_dependencies"])

    def test_omitted_local_dependency_fails_closed(self) -> None:
        candidate = copy.deepcopy(self.manifest)
        candidate["files"] = [
            row for row in candidate["files"] if row["relative_path"] != "agent/service_crash_store.py"
        ]
        with self.assertRaises(manifest_module.DependencyManifestError):
            manifest_module.validate_manifest(candidate, ROOT)

    def test_manifest_records_dynamic_imports_without_treating_time_as_local(self) -> None:
        dynamic = self.manifest["dynamic_imports"]
        self.assertTrue(any(row.get("import") == "time" for row in dynamic))
        self.assertFalse(any(row.get("local") for row in dynamic))


if __name__ == "__main__":
    unittest.main(verbosity=2)
