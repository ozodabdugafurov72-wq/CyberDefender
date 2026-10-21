from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)


class InstallerHealthSchemaIdentityTests(unittest.TestCase):
    def test_health_schema_and_runtime_boot_identity_fail_closed(self) -> None:
        source = (ROOT / "scripts/install_agent_release.ps1").read_text(
            encoding="utf-8"
        )
        start = source.index("function Test-JsonProperty")
        end = source.index("function Await-HealthyRuntime", start)
        functions = source[start:end]
        self.assertIn("Get-CimInstance Win32_Process", source)
        self.assertIn("Assert-RuntimeBootIdentity", source)

        body = rf"""
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Message){{if(-not $Condition){{throw $Message}}}}
{functions}
function Snapshot($StartedAt=1767225600.0) {{
  [pscustomobject]@{{runtime=[pscustomobject]@{{
    status='HEALTHY';running=$true;component_failures=0;cycle_count=7;
    events_acked=4;events_persisted_deferred=0;started_at=$StartedAt;
    resource_snapshot=[pscustomobject]@{{state='NORMAL'}}
  }}}}
}}
function Expect-False($Value,[string]$Code){{if($Value){{throw $Code}}}}
function Expect-Code([scriptblock]$Action,[string]$Code){{
  try{{& $Action;throw ('EXPECTED_' + $Code)}}catch{{if($_.Exception.Message -ne $Code){{throw}}}}
}}
$good=Snapshot
if(-not (Runtime-IsHealthy $good)){{throw 'VALID_SNAPSHOT_REJECTED'}}
$missing=Snapshot;$missing.runtime.PSObject.Properties.Remove('component_failures')
Expect-False (Runtime-IsHealthy $missing) 'MISSING_COMPONENT_ACCEPTED'
$wrong=Snapshot;$wrong.runtime.component_failures='0'
Expect-False (Runtime-IsHealthy $wrong) 'STRING_COMPONENT_ACCEPTED'
$wrong=Snapshot;$wrong.runtime.running='true'
Expect-False (Runtime-IsHealthy $wrong) 'STRING_RUNNING_ACCEPTED'
$missing=Snapshot;$missing.runtime.PSObject.Properties.Remove('cycle_count')
Expect-False (Runtime-IsHealthy $missing) 'MISSING_CYCLE_ACCEPTED'
$wrong=Snapshot;$wrong.runtime.events_acked=0.0
Expect-False (Runtime-IsHealthy $wrong) 'FLOAT_COUNTER_ACCEPTED'
$missing=Snapshot;$missing.runtime.PSObject.Properties.Remove('started_at')
Expect-False (Runtime-IsHealthy $missing) 'MISSING_START_ACCEPTED'
$processStart=[datetime]'2026-01-01T00:00:00Z'
$observed=[datetime]'2026-01-01T00:00:05Z'
$identity=Assert-RuntimeBootIdentity $good $processStart $observed $null
if([Math]::Abs($identity-1767225600.0) -gt 0.0001){{throw 'IDENTITY_VALUE_CHANGED'}}
Expect-Code {{Assert-RuntimeBootIdentity (Snapshot 1767225590.0) $processStart $observed $null}} 'RUNTIME_BOOT_IDENTITY_STALE'
Expect-Code {{Assert-RuntimeBootIdentity (Snapshot 1767225630.0) $processStart $observed $null}} 'RUNTIME_BOOT_IDENTITY_FUTURE'
Expect-Code {{$s=Snapshot;$s.runtime.PSObject.Properties.Remove('started_at');Assert-RuntimeBootIdentity $s $processStart $observed $null}} 'RUNTIME_STARTED_AT_MISSING'
Expect-Code {{Assert-RuntimeBootIdentity (Snapshot '1767225600') $processStart $observed $null}} 'RUNTIME_STARTED_AT_TYPE_INVALID'
Expect-Code {{Assert-RuntimeBootIdentity $good $processStart $observed 1767225601.0}} 'RUNTIME_BOOT_IDENTITY_CHANGED'
'PASS'
"""
        with tempfile.TemporaryDirectory(prefix="cd-health-schema-") as raw:
            script = Path(raw) / "health_schema.ps1"
            script.write_text(body, encoding="utf-8")
            completed = subprocess.run(
                [
                    str(POWERSHELL),
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-File",
                    str(script),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("PASS", completed.stdout)


if __name__ == "__main__":
    unittest.main()
