from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from agent.sensors.file_activity_collector import (
    FILE_ACTIVITY_CANARY_MARKER,
    FILE_ACTIVITY_CANARY_MARKER_FILENAME,
    FileActivityCollector,
    FileActivityCollectorError,
)


class FileActivityCollectorV1Tests(unittest.TestCase):
    def _root(self, base: Path) -> Path:
        root = base / "LiveRansomwareTest"
        root.mkdir()
        (root / FILE_ACTIVITY_CANARY_MARKER_FILENAME).write_text(
            FILE_ACTIVITY_CANARY_MARKER,
            encoding="utf-8",
        )
        return root

    def test_bounded_normalized_create_modify_rename_delete_events(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-file-collector-") as directory:
            root = self._root(Path(directory))
            collector = FileActivityCollector(
                root,
                endpoint_id="endpoint-lab",
                tenant_id="tenant-lab",
                max_events_per_poll=16,
                max_events_per_window=32,
            )
            self.assertEqual([], collector.poll())

            target = root / "sample.txt"
            target.write_text("one", encoding="utf-8")
            created = collector.poll()
            self.assertEqual({"CREATE"}, {row["data"]["operation"] for row in created})
            self.assertTrue(all(row["data"]["path"].startswith(str(root)) for row in created))
            self.assertTrue(all(row["data"]["endpoint_id"] == "endpoint-lab" for row in created))

            time.sleep(0.002)
            target.write_text("two", encoding="utf-8")
            modified = collector.poll()
            self.assertIn("MODIFY", {row["data"]["operation"] for row in modified})

            renamed = root / "sample.locked"
            target.rename(renamed)
            rename_events = collector.poll()
            rename = next(row for row in rename_events if row["data"]["operation"] == "RENAME")
            self.assertTrue(rename["data"]["extension_changed"])
            self.assertEqual(str(target), rename["data"]["old_path"])
            self.assertEqual(str(renamed), rename["data"]["new_path"])

            renamed.unlink()
            deleted = collector.poll()
            self.assertIn("DELETE", {row["data"]["operation"] for row in deleted})

            health = collector.health_check()
            self.assertEqual("HEALTHY", health["status"])
            self.assertTrue(health["bounded"])
            self.assertEqual("NONE", health["authority"])
            self.assertEqual("NOT_GRANTED", health["authorization"])
            self.assertFalse(health["response_actions"])

    def test_marker_and_reparse_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-file-collector-marker-") as directory:
            base = Path(directory)
            root = base / "missing-marker"
            root.mkdir()
            collector = FileActivityCollector(root, endpoint_id="endpoint-lab")
            self.assertEqual([], collector.poll())
            self.assertEqual("DEGRADED", collector.health_check()["status"])
            self.assertEqual("COLLECTOR_FAIL_CLOSED", collector.health_check()["last_error"])

    def test_rate_limit_is_bounded_and_drops_events(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-file-collector-rate-") as directory:
            root = self._root(Path(directory))
            collector = FileActivityCollector(
                root,
                endpoint_id="endpoint-lab",
                max_events_per_poll=64,
                max_events_per_window=2,
            )
            collector.poll()
            for index in range(6):
                (root / f"bounded-{index}.txt").write_text("x", encoding="utf-8")
            events = collector.poll()
            self.assertLessEqual(len(events), 2)
            self.assertGreaterEqual(collector.health_check()["events_dropped"], 1)

    def test_symlinked_approved_root_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-file-collector-link-") as directory:
            base = Path(directory)
            real_root = self._root(base)
            linked_root = base / "linked-root"
            try:
                linked_root.symlink_to(real_root, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable on this host")
            with self.assertRaises(FileActivityCollectorError):
                FileActivityCollector(linked_root, endpoint_id="endpoint-lab")


if __name__ == "__main__":
    unittest.main(verbosity=2)
