from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts" / "capture_agent_startup_once.ps1").read_text(encoding="utf-8")


class StartupCaptureTaskLifecycleTests(unittest.TestCase):
    def test_launcher_waits_for_observed_task_start_and_terminal_evidence(self) -> None:
        self.assertNotIn("while($state -eq 'Running'", SOURCE)
        self.assertNotIn("if(Test-Path -LiteralPath $sanitized -PathType Leaf){break}", SOURCE)
        for token in (
            "$observedStart=$false",
            "Get-ScheduledTaskInfo",
            "CAPTURE_SYSTEM_TASK_NOT_STARTED",
            "CAPTURE_SYSTEM_TASK_FAILED",
            "Test-Path -LiteralPath $sanitized",
        ):
            self.assertIn(token, SOURCE)
        self.assertLess(SOURCE.index("Start-ScheduledTask"), SOURCE.index("$observedStart=$false"))
        self.assertLess(SOURCE.index("$observedStart=$false"), SOURCE.index("Unregister-ScheduledTask"))


if __name__ == "__main__":
    unittest.main()
