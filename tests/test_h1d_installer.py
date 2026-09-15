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
        self.assertEqual(p.stdout.strip(),"1,5000,1,15000,1,60000,0,0")

    def test_installer_provisions_separate_protected_store(self):
        text=(ROOT/"scripts/install_machine.ps1").read_text()
        for token in ("CyberDefenderCrashGuard","SetAccessRuleProtection($true,$false)","CrashGuard existing owner rejected",
                      "CrashGuard reparse path rejected","agent.service_crash_store","authorize-probe"):
            self.assertIn(token,text)
        self.assertNotIn("restart/5000/restart/15000/restart/60000",text)
        self.assertLess(text.index("'provision'"),text.index("Start-Service 'CyberDefenderControlPlane'"))


if __name__ == "__main__": unittest.main()
