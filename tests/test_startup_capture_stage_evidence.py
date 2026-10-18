from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = (ROOT / "scripts" / "capture_agent_startup_once.ps1").read_text(encoding="utf-8")
WORKER_PATH = ROOT / "scripts" / "agent_release" / "startup_capture_once.py"


class StartupCaptureStageEvidenceTests(unittest.TestCase):
    def test_launcher_persists_bounded_stages_and_task_result_on_failure(self) -> None:
        for stage in (
            "worker_started",
            "key_ready",
            "clone_ready",
            "runtime_imported",
            "gate_result",
            "acl_cleanup",
        ):
            self.assertIn(stage, LAUNCHER)
        for token in (
            "Flush($true)",
            "capture-task-result.json",
            "last_task_result",
            "last_stage",
            "stage_utc",
        ):
            self.assertIn(token, LAUNCHER)
        worker_tail = LAUNCHER[LAUNCHER.index("CAPTURE_SYSTEM_REQUIRED") :]
        self.assertIn("Restrict-Path $stageFile $false", worker_tail)
        self.assertLess(worker_tail.index("Write-CaptureStage $stageFile 'worker_started'"), worker_tail.index("Restrict-Path $stageFile $false"))
        self.assertLess(worker_tail.index("try{"), worker_tail.index("New-Item -ItemType Directory -Path $candidate,$clone,$evidence"))
        self.assertNotIn("Tree-Digest $liveState", worker_tail)
        self.assertIn("capture_state_clone", (ROOT / "scripts" / "agent_release" / "capture_state_clone.py").stem)
        self.assertLess(worker_tail.index("finally {"), worker_tail.index("CAPTURE_CLONE_DELETE_FAILED"))

    def test_python_stage_writer_is_closed_vocabulary_and_durable(self) -> None:
        spec = importlib.util.spec_from_file_location("startup_capture_once", WORKER_PATH)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stages.log"
            path.touch()
            module._append_stage(path, "runtime_imported")
            line = path.read_text(encoding="ascii").strip()
            self.assertEqual(line.split("|", 1)[1], "runtime_imported")
            with self.assertRaises(ValueError):
                module._append_stage(path, "not_allowed")


if __name__ == "__main__":
    unittest.main()
