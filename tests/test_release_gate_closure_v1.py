from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseGateClosureTests(unittest.TestCase):
    def test_guard_initialization_failure_is_fatal_for_scm_hosts(self):
        from agent.service_lifecycle import run_guarded_service

        observed: list[tuple[str, str]] = []

        def missing_store():
            raise RuntimeError("STORE_UNAVAILABLE")

        result = run_guarded_service(
            "CyberDefenderAgent",
            threading.Event(),
            lambda _guard: True,
            store_factory=missing_store,
            observer=lambda service, state: observed.append((service, state)),
            stop_on_attempt_failure=True,
        )
        self.assertIs(result, False)
        self.assertIn(("CyberDefenderAgent", "UNAVAILABLE"), observed)

    def test_installer_preflight_never_executes_legacy_python(self):
        source = (ROOT / "scripts/install_agent_release.ps1").read_text(encoding="utf-8")
        self.assertIn("$LegacyPython=Join-Path $OldApp", source)
        self.assertIn("$PreflightPython=Join-Path $PreflightRoot 'python.exe'", source)
        self.assertIn("New-ProtectedDirectory $PreflightRoot", source)
        self.assertNotIn("Run-Checked $LegacyPython", source)
        self.assertNotIn("& $LegacyPython", source)
        self.assertIn("PRECHECK_RUNTIME_CLEANUP_FAILED", source)

    def test_apply_acceptance_requires_real_stability_window(self):
        source = (ROOT / "scripts/install_agent_release.ps1").read_text(encoding="utf-8")
        self.assertIn("[int]$MinimumSnapshotSpacingSeconds=60", source)
        self.assertIn("[int]$StableSeconds=900", source)
        self.assertIn("AGENT_PID_CHANGED_DURING_STABILITY", source)
        self.assertIn("RUNTIME_SNAPSHOT_SPACING_INVALID", source)

    def test_health_gate_ignores_early_healthy_snapshots_and_rejects_degraded_stability(self):
        source = (ROOT / "scripts/install_agent_release.ps1").read_text(encoding="utf-8")
        start = source.index("function Runtime-IsHealthy")
        end = source.index("function Get-PathIdentityEvidence", start)
        functions = source[start:end]
        body = rf'''
$ErrorActionPreference='Stop'
$AgentName='CyberDefenderAgent';$RuntimeFile='C:\fake\runtime.json'
$script:Now=[datetime]'2026-01-01T00:00:00Z';$script:Cycle=0;$script:Mode='healthy'
function Require([bool]$Condition,[string]$Message){{if(-not $Condition){{throw $Message}}}}
function Service-Info([string]$Name){{[pscustomobject]@{{State='Running';ProcessId=42}}}}
function Test-Path{{param($LiteralPath,$PathType)[bool]$true}}
function Get-Date{{$script:Now}}
function Get-Item{{param($LiteralPath,$ErrorAction)[pscustomobject]@{{LastWriteTimeUtc=$script:Now}}}}
function Start-Sleep{{param([int]$Seconds)$script:Now=$script:Now.AddSeconds($Seconds)}}
function Read-RuntimeSnapshot{{
  $script:Cycle++
  $healthy=($script:Mode -eq 'healthy' -or $script:Cycle -le 3)
  [pscustomobject]@{{runtime=[pscustomobject]@{{status=$(if($healthy){{'HEALTHY'}}else{{'DEGRADED'}});running=$healthy;component_failures=$(if($healthy){{0}}else{{1}});cycle_count=$script:Cycle;events_acked=0;events_persisted_deferred=0;resource_snapshot=[pscustomobject]@{{state=$(if($healthy){{'NORMAL'}}else{{'DEGRADED'}})}}}}}}
}}
{functions}
$ok=Await-HealthyRuntime $script:Now 300 60 0
if($ok.observations.Count -ne 3){{throw 'EARLY_HEALTHY_SNAPSHOT_HANDLING_FAILED'}}
$script:Now=[datetime]'2026-01-01T00:00:00Z';$script:Cycle=0;$script:Mode='degrade'
try{{[void](Await-HealthyRuntime $script:Now 60 1 10);throw 'EXPECTED_STABILITY_FAILURE'}}catch{{if($_.Exception.Message -ne 'RUNTIME_SUSTAINED_HEALTH_FAILED'){{throw}}}}
'PASS'
'''
        with tempfile.TemporaryDirectory() as raw:
            script = Path(raw) / "health_gate.ps1"
            script.write_text(body, encoding="utf-8")
            completed = subprocess.run(
                [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", str(script)],
                capture_output=True, text=True, timeout=30, check=False,
            )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("PASS", completed.stdout)


if __name__ == "__main__":
    unittest.main()
