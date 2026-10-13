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

    def test_acl_gate_uses_only_mutating_rights(self) -> None:
        source = self.source
        gate = source.split("function Inspect-ProtectedPath", 1)[1].split(
            "function Require-Administrator", 1
        )[0]
        self.assertNotIn("FileSystemRights]::Write -bor", gate)
        self.assertNotIn("FileSystemRights]::Modify -bor", gate)
        self.assertNotIn("FileSystemRights]::FullControl", gate)
        for flag in (
            "WriteData", "AppendData", "WriteExtendedAttributes",
            "WriteAttributes", "DeleteSubdirectoriesAndFiles", "Delete",
            "ChangePermissions", "TakeOwnership",
        ):
            with self.subTest(flag=flag):
                self.assertIn("FileSystemRights]::" + flag, gate)
        self.assertIn("0x50000000", gate)
        self.assertIn("BROAD_WRITE_ACCESS:", gate)

    def test_acl_mask_read_only_is_not_write(self) -> None:
        # FileSystemRights values are defined by Windows ACCESS_MASK constants.
        # A read/execute ACE must not trigger; modification, delete and
        # ownership/permission changes must trigger.
        read = 0x00020089
        read_execute = 0x000200A9
        specific_write = 0x00000002 | 0x00000004 | 0x00000010 | 0x00000100
        mutate = specific_write | 0x00000040 | 0x00010000 | 0x00040000 | 0x00080000
        mask = mutate | 0x50000000
        self.assertEqual(read & mask, 0)
        self.assertEqual(read_execute & mask, 0)
        for allowed in (
            specific_write, 0x00000040, 0x00010000,
            0x00040000, 0x00080000, 0x40000000, 0x10000000,
        ):
            with self.subTest(allowed=allowed):
                self.assertNotEqual(allowed & mask, 0)

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
