from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def test_finite_definition_compiles_without_service_mutation(self):
        source=(ROOT/"scripts/service_recovery_policy.ps1").read_text()
        definition=source.split("@'\n",1)[1].split("\n'@",1)[0]
        # Compile the C# definition directly. Do not execute the installer or
        # change the machine's PowerShell execution policy.
        command="Add-Type -TypeDefinition @'\n"+definition+"\n'@\n[CyberDefenderRecoveryPolicy]::ExpectedActions() -join ','"
        p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",command],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.strip(),"1,5000,1,15000,1,60000")

    def test_recovery_definition_supports_read_only_existing_service_verify(self):
        source=(ROOT/"scripts/service_recovery_policy.ps1").read_text()
        self.assertIn("public static void Verify(string name)",source)
        self.assertIn("OpenService(manager,name,1)",source)
        self.assertIn("VerifyHandle(service)",source)

    def test_installer_provisions_separate_protected_store(self):
        text=(ROOT/"scripts/install_machine.ps1").read_text()
        for token in ("CyberDefenderCrashGuard","SetAccessRuleProtection($true,$false)","CrashGuard existing owner rejected",
                      "CrashGuard reparse path rejected","agent.service_crash_store","authorize-probe"):
            self.assertIn(token,text)
        self.assertNotIn("restart/5000/restart/15000/restart/60000",text)
        self.assertLess(text.index("'provision'"),text.index("Start-Service 'CyberDefenderControlPlane'"))

    def test_upgrade_preserves_registration_and_rolls_back_previous_app(self):
        text=(ROOT/"scripts/install_machine.ps1").read_text()
        stop_banner="Existing services safely stopped; registrations preserved for rollback"
        self.assertIn(stop_banner,text)
        self.assertIn("$PreexistingServices",text)
        self.assertIn("$PreviouslyRunningServices",text)
        self.assertIn("$ApplicationSnapshotCreated",text)
        self.assertIn("Move-Item -Force $PreviousRoot $InstallRoot",text)
        self.assertIn("Rollback restored previous application and service state",text)
        self.assertLess(text.index(stop_banner),text.index("Move-Item -Force $InstallRoot $PreviousRoot"))
        self.assertLess(text.index("Move-Item -Force $PreviousRoot $InstallRoot"),text.index("throw $InstallError"))
        self.assertIn("[CyberDefenderRecoveryPolicy]::Verify($name)",text)
        self.assertIn("Set-Location $env:TEMP",text)

    def test_remote_fleet_credential_is_isolated_from_local_control_plane(self):
        text=(ROOT/"scripts/install_machine.ps1").read_text()
        self.assertIn('remote_fleet_token.txt',text)
        self.assertIn('$AgentFleetToken = if($IsLoopback){$FleetToken}else{$RemoteFleetToken}',text)
        self.assertIn('local control-plane token is never reused',text)
        agent_preflight=text.index("@('-m','agent.windows_service','--preflight')")
        local_reset=text.index('$env:CYBERDEFENDER_FLEET_TOKEN_FILE=$FleetToken',agent_preflight)
        control_preflight=text.index("@('-m','control_plane.windows_service','--preflight')")
        self.assertLess(agent_preflight,local_reset)
        self.assertLess(local_reset,control_preflight)


if __name__ == "__main__": unittest.main()
