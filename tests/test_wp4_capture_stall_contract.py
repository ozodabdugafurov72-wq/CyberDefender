from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_PATH = ROOT / "scripts" / "capture_agent_startup_once.ps1"
CLONE_HELPER_PATH = ROOT / "scripts" / "agent_release" / "capture_state_clone.py"
LAUNCHER = LAUNCHER_PATH.read_text(encoding="utf-8")


def _load_clone_helper():
    spec = importlib.util.spec_from_file_location("capture_state_clone", CLONE_HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WP4CaptureStallContractTests(unittest.TestCase):
    def test_closed_summary_schema_is_bounded_and_string_only(self) -> None:
        required = {
            "run",
            "last_stage",
            "stage_utc",
            "stage_seconds",
            "terminal_code",
            "task_last_result",
            "clone_files",
            "clone_mb",
            "top_files",
            "clone_exists",
            "tasks",
            "agent_state",
        }
        for field in required:
            self.assertIn(f"{field}=", LAUNCHER)
        self.assertIn("CAPTURE_SUMMARY_BOUND_EXCEEDED", LAUNCHER)
        self.assertIn("[string]$_", LAUNCHER)
        self.assertNotIn("stage_codes=$stageCodes", LAUNCHER)

    def test_worker_has_progress_deadline_and_terminal_marker(self) -> None:
        for token in (
            "[int]$StageTimeoutSeconds=90",
            "[switch]$CoreWorker",
            "STAGE_TIMEOUT:",
            "worker_finished:",
            "$workerTotalBudgetSeconds=210",
            "clone_begin",
            "clone_item:",
            "clone_done",
        ):
            self.assertIn(token, LAUNCHER)
        self.assertLess(LAUNCHER.index("Read-CaptureStages $stageFile"), LAUNCHER.index("Unregister-ScheduledTask"))
        self.assertIn("New-TimeSpan -Minutes 4", LAUNCHER)

    def test_clone_allowlist_size_cap_and_lock_failure(self) -> None:
        helper = _load_clone_helper()
        relpaths = {spec.relative_path for spec in helper.COPY_SPECS}
        self.assertIn("keys/key_state.json", relpaths)
        self.assertIn("spool/acked_state.json", relpaths)
        self.assertIn("incident_outbox/incident_outbox.jsonl", relpaths)
        self.assertIn("state.json", relpaths)
        self.assertFalse(any(path.startswith("logs/") for path in relpaths))
        self.assertFalse(any(path.startswith("data/") for path in relpaths))
        self.assertEqual(helper.MAX_TOTAL_BYTES, 64 * 1024 * 1024)
        self.assertIn("remaining_budget", CLONE_HELPER_PATH.read_text(encoding="utf-8"))
        self.assertIn("_reject_reparse_chain", CLONE_HELPER_PATH.read_text(encoding="utf-8"))
        self.assertIn("verify_unchanged", CLONE_HELPER_PATH.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live = root / "live"
            clone = root / "clone"
            stage = root / "stages.log"
            result = root / "result.json"
            stage.touch()
            target_spec = helper.COPY_SPECS[0]
            for spec_item in helper.COPY_SPECS:
                if spec_item.required:
                    required_source = live / Path(spec_item.relative_path)
                    required_source.parent.mkdir(parents=True, exist_ok=True)
                    required_source.write_bytes(b"x")
            source = live / Path(target_spec.relative_path)
            source.write_bytes(b"x" * 32)
            with self.assertRaises(helper.CloneFailure) as raised:
                helper.clone_state(live, clone, stage, result, max_total_bytes=16)
            self.assertEqual(raised.exception.code, "CLONE_TOO_LARGE")

            attempts: list[int] = []

            def locked_reader(_path: Path):
                attempts.append(1)
                error = PermissionError("locked")
                error.winerror = 32
                raise error

            with self.assertRaises(helper.CloneFailure) as raised:
                helper.clone_state(
                    live,
                    clone,
                    stage,
                    result,
                    open_reader=locked_reader,
                    sleep=lambda _seconds: None,
                )
            self.assertEqual(raised.exception.code, f"CLONE_FILE_LOCKED:{target_spec.file_class}")
            self.assertEqual(len(attempts), 3)
            self.assertLess(len(json.dumps({"code": raised.exception.code})), 256)


if __name__ == "__main__":
    unittest.main()
