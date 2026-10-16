from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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
RUNTIME_SPEC = importlib.util.spec_from_file_location(
    "agent_runtime_manager", TOOLS / "runtime_manager.py"
)
assert RUNTIME_SPEC and RUNTIME_SPEC.loader
runtime_manager = importlib.util.module_from_spec(RUNTIME_SPEC)
RUNTIME_SPEC.loader.exec_module(runtime_manager)


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


class RuntimeManagerTests(unittest.TestCase):
    def _runtime_zip(self, path: Path, extra: dict[str, bytes] | None = None) -> str:
        files = {name: b"runtime" for name in runtime_manager.REQUIRED}
        files.update(extra or {})
        records = [
            {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(files.items())
        ]
        manifest = {
            "schema": runtime_manager.SCHEMA,
            "python": runtime_manager.PYTHON_INPUT,
            "wheels": [
                {"name": name, "sha256": digest}
                for name, digest in sorted(runtime_manager.WHEEL_INPUTS.items())
            ],
            "file_count": len(records),
            "total_bytes": sum(item["length"] for item in records),
            "files": records,
        }
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
            archive.writestr("RUNTIME_MANIFEST.json", json.dumps(manifest))
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_pinned_runtime_verifies_and_extracts_once(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            package = base / "runtime.zip"
            digest = self._runtime_zip(package)
            destination = base / "release" / "runtime"
            destination.parent.mkdir()
            self.assertEqual(runtime_manager.verify(package, digest)["status"], "PINNED_RUNTIME_VERIFIED")
            result = runtime_manager.extract(package, destination, digest)
            self.assertEqual(result["status"], "PINNED_RUNTIME_EXTRACTED")
            self.assertTrue((destination / "python.exe").is_file())
            with self.assertRaisesRegex(ValueError, "already exists"):
                runtime_manager.extract(package, destination, digest)

    def test_runtime_archive_rejects_escape_and_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            package = base / "runtime.zip"
            digest = self._runtime_zip(package, {"../escape.dll": b"x"})
            with self.assertRaisesRegex(ValueError, "unsafe"):
                runtime_manager.verify(package, digest)
            package.write_bytes(package.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                runtime_manager.verify(package, digest)


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
        self.assertIn("Invoke-CimMethod", self.source)
        self.assertIn("Stop-Service -Name $AgentName", self.source)

    def test_scm_binary_update_uses_typed_cim_pathname(self) -> None:
        start = self.source.index("function Set-AgentBinary")
        end = self.source.index("function Authorize-AgentProbe", start)
        function = self.source[start:end]
        self.assertNotIn("sc.exe", function)
        self.assertIn("-MethodName Change", function)
        self.assertIn("@{PathName=$Value}", function)
        self.assertIn("SCM_BINARY_UPDATE_FAILED:", function)
        self.assertIn("SCM_BINARY_READBACK_MISMATCH", function)

    def test_agent_identity_rechecks_stale_pid_until_fresh_process(self) -> None:
        start = self.source.index("function Verify-AgentProcess")
        end = self.source.index("function Write-Receipt", start)
        function = self.source[start:end]
        with tempfile.TemporaryDirectory() as raw:
            script = Path(raw) / "identity_race.ps1"
            expected_bin = '"C:\\Python\\python.exe" "C:\\release\\agent_service_bootstrap.py" --service-run'
            body = rf"""
$ErrorActionPreference='Stop'
$AgentName='CyberDefenderAgent'
$Python='C:\Python\python.exe'
$script:ExpectedBin='{expected_bin}'
$script:Started=(Get-Date).ToUniversalTime()
$script:ProcessCalls=0
function Require([bool]$Condition,[string]$Message) {{ if(-not $Condition){{ throw $Message }} }}
function Service-Info([string]$Name) {{
    return [pscustomobject]@{{State='Running';PathName=$script:ExpectedBin;ProcessId=4242}}
}}
function Get-CimInstance {{
    param([string]$ClassName,[string]$Filter,[object]$ErrorAction)
    if($Filter -eq "Name='services.exe'") {{ return [pscustomobject]@{{ProcessId=888}} }}
    if($Filter -eq 'ProcessId=4242') {{
        $script:ProcessCalls++
        if($script:ProcessCalls -eq 1) {{
            return [pscustomobject]@{{ProcessId=4242;ParentProcessId=777;ExecutablePath='C:\stale\python.exe';CommandLine='stale';CreationDate=$script:Started.AddSeconds(-5)}}
        }}
        return [pscustomobject]@{{ProcessId=4242;ParentProcessId=888;ExecutablePath=$Python;CommandLine='C:\release\agent_service_bootstrap.py --service-run';CreationDate=$script:Started.AddMilliseconds(1)}}
    }}
    return $null
}}
function Start-Sleep {{ param([int]$Milliseconds) }}
{function}
$pidResult=Verify-AgentProcess $script:ExpectedBin 'C:\release' $script:Started 1000
if($pidResult -ne 4242 -or $script:ProcessCalls -ne 2) {{ throw 'STALE_TO_FRESH_RECHECK_FAILED' }}
'PASS'
"""
            script.write_text(body, encoding="utf-8")
            completed = subprocess.run(
                [
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-File",
                    str(script),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("PASS", completed.stdout)

    def test_agent_identity_mismatch_writes_sanitized_forensic_evidence(self) -> None:
        start = self.source.index("function Get-PathIdentityEvidence")
        end = self.source.index("function Write-Receipt", start)
        functions = self.source[start:end]
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            expected = base / "expected-python.exe"
            observed = base / "observed-python.exe"
            expected.write_bytes(b"expected")
            observed.write_bytes(b"observed")
            expected_bin = f'"{expected}" "C:\\release\\agent_service_bootstrap.py" --service-run'
            script = base / "identity_evidence.ps1"
            body = rf"""
$ErrorActionPreference='Stop'
$AgentName='CyberDefenderAgent'
$Revision='a' * 40
$Python='{expected}'
$IdentityEvidenceDirectory='{base}'
$script:ExpectedBin='{expected_bin}'
$script:Started=(Get-Date).ToUniversalTime()
function Require([bool]$Condition,[string]$Message) {{ if(-not $Condition){{ throw $Message }} }}
function Service-Info([string]$Name) {{ return [pscustomobject]@{{State='Running';PathName=$script:ExpectedBin;ProcessId=4242}} }}
function Get-CimInstance {{
 param([string]$ClassName,[string]$Filter,[object]$ErrorAction)
 if($Filter -eq "Name='services.exe'") {{ return [pscustomobject]@{{ProcessId=888;Name='services.exe'}} }}
 if($Filter -eq 'ProcessId=4242') {{ return [pscustomobject]@{{ProcessId=4242;ParentProcessId=999;ExecutablePath='{observed}';CommandLine='C:\release\agent_service_bootstrap.py --service-run';CreationDate=$script:Started.AddMilliseconds(1)}} }}
 if($Filter -eq 'ProcessId=999') {{ return [pscustomobject]@{{ProcessId=999;Name='foreign.exe'}} }}
 return $null
}}
{functions}
try {{ [void](Verify-AgentProcess $script:ExpectedBin 'C:\release' $script:Started 1000); throw 'EXPECTED_IDENTITY_FAILURE' }} catch {{ if($_.Exception.Message -ne 'AGENT_PROCESS_EXECUTABLE_UNEXPECTED'){{throw}} }}
$evidence=Get-Content -LiteralPath $script:IdentityEvidencePath -Raw|ConvertFrom-Json
if($evidence.reason -ne 'EXECUTABLE_MISMATCH' -or $evidence.process_id -ne 4242 -or $evidence.parent.pid -ne 999 -or $evidence.parent.name -ne 'foreign.exe'){{throw 'IDENTITY_FIELDS_MISSING'}}
if($evidence.expected.basename -ne 'expected-python.exe' -or $evidence.observed.basename -ne 'observed-python.exe'){{throw 'PATH_FIELDS_MISSING'}}
if($evidence.expected.path_sha256 -notmatch '^[0-9a-f]{{64}}$' -or $evidence.observed.path_sha256 -notmatch '^[0-9a-f]{{64}}$' -or $evidence.expected.path_sha256 -eq $evidence.observed.path_sha256){{throw 'PATH_HASH_INVALID'}}
if($null -ne $evidence.expected.raw_path -or $null -ne $evidence.observed.full_path){{throw 'RAW_PATH_LEAK'}}
if($evidence.expected.sha256 -notmatch '^[0-9a-f]{{64}}$' -or $evidence.observed.sha256 -notmatch '^[0-9a-f]{{64}}$' -or $evidence.expected.sha256 -eq $evidence.observed.sha256){{throw 'FILE_HASH_INVALID'}}
'PASS'
"""
            script.write_text(body, encoding="utf-8")
            completed = subprocess.run(
                [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", str(script)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("PASS", completed.stdout)

    def test_apply_success_path_avoids_reserved_pid_variable_in_windows_powershell_51(self) -> None:
        assignment = next(line.strip() for line in self.source.splitlines() if "=Verify-AgentProcess $newBin" in line)
        receipt = next(line.strip() for line in self.source.splitlines() if "=Write-Receipt $agentBaseline" in line)
        self.assertEqual(assignment, "$agentPid=Verify-AgentProcess $newBin $NewRoot $startedAt 5000 $newPython")
        self.assertIn("$agentPid $newBin", receipt)
        self.assertNotRegex(assignment + receipt, r"(?i)\$pid\b")
        body = f"""
$ErrorActionPreference='Stop'
function Verify-AgentProcess {{ return 4321 }}
function Write-Receipt {{ param($Original,$Others,$RuntimeEvidence,[int]$AgentPid,[string]$NewBin); if($AgentPid -ne 4321){{throw 'PID_NOT_FORWARDED'}}; return 'receipt' }}
$newBin='approved-bin';$newPython='approved-python';$NewRoot='release';$startedAt=(Get-Date).ToUniversalTime();$agentBaseline=@{{}};$otherBaseline=@();$runtimeEvidence=@()
{assignment}
{receipt}
if($agentPid -ne 4321 -or $receipt -ne 'receipt'){{throw 'SUCCESS_PATH_FAILED'}}
'PASS'
"""
        completed = subprocess.run(
            [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile", "-NonInteractive", "-Command", body],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("PASS", completed.stdout)

    def test_stopped_recovery_and_probe_are_explicit(self) -> None:
        for required in (
            "$RecoverStoppedAgent.IsPresent",
            "$AuthorizeRecoveryProbe",
            "$Revision=$ApprovedCommit.ToLowerInvariant()",
            "Run-Checked $newPython @('-I',$newBootstrap,'--authorize-probe')",
            "HostAcknowledgement -eq 'AGENT_ONLY_AUTHORIZED'",
        ):
            self.assertIn(required, self.source)

    def test_pinned_protected_runtime_is_verified_before_scm_switch(self) -> None:
        for required in (
            "[Parameter(Mandatory=$true)][string]$RuntimeZip",
            "[Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ApprovedRuntimeZipSHA256",
            "$runtimePackage=Read-PinnedRuntimePackage $RuntimeZip $ApprovedRuntimeZipSHA256",
            "Expand-PinnedRuntimePackage $runtimePackage $newRuntime",
            "PINNED_RUNTIME_SIGNATURE_INVALID",
            "PINNED_RUNTIME_SIGNER_INVALID",
            "Run-Checked $newPython @('-I',$newBootstrap,'--dependency-probe')",
            "$newBin='\"' + $newPython + '\" -I \"' + $newBootstrap + '\" --service-run'",
        ):
            self.assertIn(required, self.source)
        self.assertNotIn("$RuntimeManager", self.source)
        after_runtime_extract = self.source.split("Expand-PinnedRuntimePackage $runtimePackage $newRuntime", 1)[1]
        self.assertNotIn("Run-Checked $Python", after_runtime_extract)
        self.assertNotIn("& $Python", after_runtime_extract)
        self.assertNotIn("Inspect-ProtectedPath $newRuntime", after_runtime_extract)
        self.assertIn("Inspect-ProtectedPathNative $newRuntime", after_runtime_extract)
        self.assertIn("Verify-ExtractedRuntime $runtimePackage $newRuntime", after_runtime_extract)
        self.assertIn("$privileged -notcontains $sid", self.source)
        self.assertIn("sys.argv = [\"service_crash_store\", \"authorize-probe\", \"--service\", \"CyberDefenderAgent\"]", (TOOLS / "agent_service_bootstrap.py").read_text(encoding="utf-8"))
        self.assertLess(
            self.source.index("Run-Checked $newPython @('-I',$newBootstrap,'--dependency-probe')"),
            self.source.index("Set-AgentBinary $newBin"),
        )

    def test_powershell_51_runtime_snapshot_verifies_and_extracts_without_old_python(self) -> None:
        start = self.source.index("function Require")
        end = self.source.index("function Service-Info", start)
        functions = self.source[start:end]
        self.assertNotIn("Run-Checked $Python", functions)
        with tempfile.TemporaryDirectory(prefix="cd-runtime-ps51-") as raw:
            base = Path(raw)
            package = base / "runtime.zip"
            digest = RuntimeManagerTests()._runtime_zip(package)
            new_root = base / "release"
            escaped_package = str(package).replace("'", "''")
            escaped_root = str(new_root).replace("'", "''")
            body = f"""
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
$NewRoot='{escaped_root}'
{functions}
$package=Read-PinnedRuntimePackage '{escaped_package}' '{digest}'
$runtime=Join-Path $NewRoot 'runtime'
[void](New-Item -ItemType Directory -Path $runtime -Force)
Expand-PinnedRuntimePackage $package $runtime $runtime
if(-not (Test-Path -LiteralPath (Join-Path $NewRoot 'runtime\\python.exe') -PathType Leaf)){{throw 'RUNTIME_NOT_EXTRACTED'}}
'PASS'
"""
            completed = subprocess.run(
                [
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-Command",
                    body,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            self.assertIn("PASS", completed.stdout)

    def test_native_acl_rejects_unprivileged_delete_child_right(self) -> None:
        start = self.source.index("function Inspect-ProtectedPathNative")
        end = self.source.index("function Verify-ExtractedRuntime", start)
        function = self.source[start:end]
        body = f"""
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){{if(-not $Condition){{throw $Message}}}}
function Get-Acl{{
    $rule=[pscustomobject]@{{
        IdentityReference=[pscustomobject]@{{Value='S-1-5-21-1-2-3-1001'}}
        AccessControlType=[Security.AccessControl.AccessControlType]::Allow
        FileSystemRights=[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    }}
    $acl=[pscustomobject]@{{Rule=$rule}}
    $acl|Add-Member ScriptMethod GetOwner {{param($type)[pscustomobject]@{{Value='S-1-5-18'}}}}
    $acl|Add-Member ScriptMethod GetAccessRules {{param($explicit,$inherited,$type)@($this.Rule)}}
    return $acl
}}
{function}
try{{Inspect-ProtectedPathNative 'C:\\protected';throw 'EXPECTED_ACL_FAILURE'}}catch{{if($_.Exception.Message -ne 'ACL_BROAD_WRITE_OR_CONTROL'){{throw}}}}
'PASS'
"""
        completed = subprocess.run(
            [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", body],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("PASS", completed.stdout)

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

    def test_receipt_is_transactional_bom_free_utf8_in_windows_powershell_51(self) -> None:
        start = self.source.index("function Write-Receipt")
        end = self.source.index("# Consolidated read-only precheck.", start)
        write_receipt = self.source[start:end]
        powershell = (
            Path(os.environ["SystemRoot"])
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )

        with tempfile.TemporaryDirectory(prefix="cd-receipt-ps51-") as raw:
            root = Path(raw)
            escaped_root = str(root).replace("'", "''")
            harness = f"""
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion.Major -ne 5){{ throw 'POWERSHELL_51_REQUIRED' }}
function Inspect-NoReparse([string]$Path) {{ }}
$Revision='{'b' * 40}'
$NewRoot='C:\\approved-release'
$ApprovedZipSHA256='{'a' * 64}'
$ApprovedRuntimeZipSHA256='{'c' * 64}'
$AcknowledgeCompanionDegraded=$false
$OtherServices=@()
{write_receipt}
$Original=[pscustomobject]@{{State='Stopped';PathName='original-bin'}}
$Others=@()
$RuntimeEvidence=@([pscustomobject]@{{status='HEALTHY';running=$true;component_failures=0}})
$ReceiptDir=Join-Path '{escaped_root}' 'receipts'
$committed=Write-Receipt $Original $Others $RuntimeEvidence 4321 'approved-bin'
$bytes=[System.IO.File]::ReadAllBytes($committed)
$hasBom=($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)
$parsed=[System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
$failureRoot=Join-Path '{escaped_root}' 'blocked-parent'
[System.IO.File]::WriteAllText($failureRoot,'not-a-directory')
$ReceiptDir=$failureRoot
$failurePropagated=$false
try {{ [void](Write-Receipt $Original $Others $RuntimeEvidence 4321 'approved-bin') }} catch {{ $failurePropagated=$true }}
$failureTarget=Join-Path $failureRoot ('agent-release-' + $Revision.Substring(0,8) + '.json')
[pscustomobject]@{{
    ps_major=$PSVersionTable.PSVersion.Major
    json_valid=($null -ne $parsed)
    has_bom=$hasBom
    schema=$parsed.schema
    status=$parsed.status
    commit=$parsed.commit
    zip_sha256=$parsed.zip_sha256
    agent_pid=$parsed.agent_pid
    committed_path=$committed
    committed_exists=(Test-Path -LiteralPath $committed -PathType Leaf)
    pending_exists=(Test-Path -LiteralPath ($committed + '.pending'))
    failure_propagated=$failurePropagated
    failure_target_exists=(Test-Path -LiteralPath $failureTarget)
    failure_pending_exists=(Test-Path -LiteralPath ($failureTarget + '.pending'))
}} | ConvertTo-Json -Compress
"""
            harness_path = root / "receipt_harness.ps1"
            harness_path.write_text(harness, encoding="utf-8")
            completed = subprocess.run(
                [
                    str(powershell),
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-File",
                    str(harness_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(completed.stdout.strip())

            self.assertEqual(5, result["ps_major"])
            self.assertTrue(result["json_valid"])
            self.assertFalse(result["has_bom"])
            self.assertEqual("cyberdefender.agent-release-receipt.v1", result["schema"])
            self.assertEqual("COMMITTED", result["status"])
            self.assertEqual("b" * 40, result["commit"])
            self.assertEqual("a" * 64, result["zip_sha256"])
            self.assertEqual(4321, result["agent_pid"])
            self.assertTrue(result["committed_exists"])
            self.assertFalse(result["pending_exists"])
            self.assertTrue(result["failure_propagated"])
            self.assertFalse(result["failure_target_exists"])
            self.assertFalse(result["failure_pending_exists"])


if __name__ == "__main__":
    unittest.main()
