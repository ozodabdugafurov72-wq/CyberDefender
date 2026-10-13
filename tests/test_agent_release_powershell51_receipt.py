"""Static regression guards for the Windows PowerShell 5.1 Agent-only installer.

These tests are source-level assertions. They do NOT simulate Windows SCM,
CrashGuard, runtime health, or a physical installed Agent.
"""
from __future__ import annotations

import re
from pathlib import Path
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "scripts" / "install_agent_release.ps1"


class AgentInstallerPS51ReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")

    def test_never_assign_to_read_only_pid_automatic_variable(self) -> None:
        # PowerShell variable names are case-insensitive: $pid == $PID.
        self.assertIsNone(re.search(r"\$pid\b", self.source, flags=re.IGNORECASE))
        self.assertIn("$agentProcessId=Verify-AgentProcess $newBin $NewRoot", self.source)
        self.assertIn("agent_pid=$AgentProcessId", self.source)

    def test_receipt_does_not_use_powershell_7_only_encoding(self) -> None:
        self.assertNotIn("utf8NoBOM", self.source)
        self.assertIn("[System.Text.UTF8Encoding]::new($false)", self.source)
        self.assertIn("[System.IO.File]::WriteAllText($temporary", self.source)

    def test_powershell_receipt_is_written_before_commit_marker(self) -> None:
        source = self.source
        self.assertLess(source.index("[System.IO.File]::WriteAllText($temporary"),
                        source.index("Move-Item -LiteralPath $temporary -Destination $target -Force"))
        self.assertIn("status='COMMITTED'", source)
        self.assertIn("AGENT_RELEASE_PASS:", source)

    def test_plan_is_explicitly_non_mutating(self) -> None:
        self.assertIn("if(-not $Apply) {", self.source)
        self.assertIn("PLAN_ONLY: no release files or service settings changed.", self.source)
        self.assertIn("PLAN_PASS_READ_ONLY:", self.source)
        self.assertIn("APPLY_PRECHECK_PASS:", self.source)
        self.assertNotIn("Write-Host 'PLAN_PASS:", self.source)
        self.assertIn("HostAcknowledgement -eq 'AGENT_ONLY_AUTHORIZED'", self.source)
        self.assertIn("Require-Administrator", self.source)

    def test_companion_isolation_and_rollback_invariants_remain(self) -> None:
        source = self.source
        for required in (
            "Verify-Others $otherBaseline",
            "Set-AgentBinary $agentBaseline.PathName",
            "ROLLBACK_BINPATH_MISMATCH",
            "ROLLBACK_RECOVERY_MISMATCH",
            "RUNTIME_HEALTH_GATE_TIMEOUT",
            "RUNTIME_CYCLE_NOT_ADVANCING",
            "UNACKNOWLEDGED_OUTBOX_GROWTH",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
