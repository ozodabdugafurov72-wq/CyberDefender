from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "scripts" / "agent_release"
INSTALLER = ROOT / "scripts" / "install_agent_release.ps1"
COMMIT = "1c5970e41877af4283cfe534b9441f0289b4e0e9"
SPEC = importlib.util.spec_from_file_location(
    "agent_release_manager", TOOLS / "release_manager.py"
)
assert SPEC and SPEC.loader
release_manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_manager)


def make_release(path: Path, files: dict[str, bytes] | None = None) -> str:
    if files is None:
        files = {name: b"VALUE=1\n" for name in release_manager.REQUIRED}
    manifest = {
        "schema": release_manager.SCHEMA,
        "commit": COMMIT,
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "length": len(data),
            }
            for name, data in files.items()
        ],
        "file_count": len(files),
        "total_bytes": sum(len(data) for data in files.values()),
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr("release/" + name, data)
        archive.writestr("PINNED_MANIFEST.json", json.dumps(manifest))
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseManagerTests(unittest.TestCase):
    def test_verified_release_extracts_to_exact_immutable_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            package = base / "release.zip"
            digest = make_release(package)
            releases = base / "agent-releases"
            releases.mkdir()
            destination = releases / COMMIT
            bootstrap = base / "agent_service_bootstrap.py"
            bootstrap.write_text("pass\n", encoding="utf-8")
            report = release_manager.unpack(package, destination, digest, COMMIT, bootstrap)
            self.assertEqual(report["status"], "RELEASE_EXTRACTED_NO_SERVICE_CHANGE")
            self.assertTrue((destination / "agent" / "main.py").is_file())
            with self.assertRaises(FileExistsError):
                release_manager.unpack(package, destination, digest, COMMIT, bootstrap)

    def test_archive_boundary_rejects_windows_and_escape_names(self) -> None:
        unsafe = (
            "../escape.py",
            "agent/CON.txt",
            "agent/NUL.json",
            "agent/COM1.bin",
            "agent/name:stream",
            "agent/trailing.",
            "secrets/token.txt",
            ".env",
        )
        for name in unsafe:
            self.assertFalse(release_manager.safe_path(name), name)

    def test_tampered_package_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "release.zip"
            digest = make_release(package)
            with package.open("ab") as stream:
                stream.write(b"tamper")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                release_manager.verify(package, digest, COMMIT)


class InstallerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER.read_text(encoding="utf-8")

    def test_only_agent_has_mutating_service_operations(self) -> None:
        for forbidden in (
            "Stop-Service -Name CyberDefenderControlPlane",
            "Stop-Service -Name CyberDefenderOwnerUI",
            "New-Service",
            "Remove-Service",
            "sc.exe delete",
            "app.previous",
            "ExecutionPolicy Bypass",
        ):
            self.assertNotIn(forbidden, self.source)
        self.assertIn("& sc.exe config $AgentName 'binPath=' $Value", self.source)
        self.assertIn("Stop-Service -Name $AgentName", self.source)

    def test_stopped_recovery_and_probe_are_explicit(self) -> None:
        for required in (
            "$RecoverStoppedAgent.IsPresent",
            "$AuthorizeRecoveryProbe",
            "$Revision=$ApprovedCommit.ToLowerInvariant()",
            "'agent.service_crash_store','authorize-probe','--service',$AgentName",
            "HostAcknowledgement -eq 'AGENT_ONLY_AUTHORIZED'",
        ):
            self.assertIn(required, self.source)

    def test_runtime_gate_is_real_and_strict(self) -> None:
        for required in (
            "runtime.status -eq 'HEALTHY'",
            "runtime.running -eq $true",
            "runtime.component_failures -eq 0",
            "resource.state -eq 'NORMAL'",
            "RUNTIME_CYCLE_NOT_ADVANCING",
            "UNACKNOWLEDGED_OUTBOX_GROWTH",
            "$observations.Count -ge 3",
        ):
            self.assertIn(required, self.source)

    def test_rollback_restores_exact_service_contract(self) -> None:
        for required in (
            "Set-AgentBinary $agentBaseline.PathName",
            "ROLLBACK_BINPATH_MISMATCH",
            "ROLLBACK_STARTMODE_MISMATCH",
            "ROLLBACK_IDENTITY_MISMATCH",
            "ROLLBACK_RECOVERY_MISMATCH",
            "ROLLBACK_START_STATE_MISMATCH",
        ):
            self.assertIn(required, self.source)

    def test_remote_secret_is_never_read_or_written(self) -> None:
        self.assertNotIn("Get-Content -LiteralPath $RemoteToken", self.source)
        self.assertNotIn("Set-Content -LiteralPath $RemoteToken", self.source)
        self.assertNotIn("Get-Clipboard", self.source)


if __name__ == "__main__":
    unittest.main()
