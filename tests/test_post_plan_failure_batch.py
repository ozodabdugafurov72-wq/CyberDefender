from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def extracted_svc_do_run(relative: str, class_name: str, service_name: str):
    source = (ROOT / relative).read_text(encoding="utf-8")
    tree = ast.parse(source)
    service_class = next(
        child
        for node in tree.body
        if isinstance(node, ast.If)
        for child in node.body
        if isinstance(child, ast.ClassDef) and child.name == class_name
    )
    method = next(
        node
        for node in service_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "SvcDoRun"
    )
    method.name = "svc_do_run"
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {"SERVICE_NAME": service_name}
    exec(compile(module, relative, "exec"), namespace)
    return namespace["svc_do_run"]


class PostPlanFailureBatchTests(unittest.TestCase):
    def test_all_scm_hosts_exit_when_runtime_attempt_dies(self):
        import agent.service_diagnostics as diagnostics
        import agent.service_lifecycle as lifecycle

        cases = (
            ("agent/windows_service.py", "CyberDefenderWindowsService", "CyberDefenderAgent", "AGENT_RUNTIME_FATAL"),
            ("control_plane/windows_service.py", "CyberDefenderControlPlaneService", "CyberDefenderControlPlane", "CONTROL_PLANE_RUNTIME_FATAL"),
            ("dashboard_owner/windows_service.py", "CyberDefenderOwnerUIService", "CyberDefenderOwnerUI", "OWNER_UI_RUNTIME_FATAL"),
        )
        for relative, class_name, service_name, fatal_code in cases:
            with self.subTest(service=service_name):
                svc_do_run = extracted_svc_do_run(relative, class_name, service_name)
                service = type("FakeService", (), {})()
                service._stop_event = threading.Event()
                service._run_attempt = lambda _guard: False
                observed = []
                with mock.patch.object(lifecycle, "run_guarded_service", return_value=False) as guarded, \
                     mock.patch.object(diagnostics, "write_service_log", side_effect=lambda *a, **kw: observed.append((a, kw))):
                    with self.assertRaisesRegex(RuntimeError, f"^{fatal_code}$"):
                        svc_do_run(service)
                self.assertIs(guarded.call_args.args[2], service._run_attempt)
                self.assertTrue(guarded.call_args.kwargs["stop_on_attempt_failure"])
                self.assertIn(((service_name, "STOPPED"), {"exit_reason": "UNHANDLED_EXCEPTION"}), observed)

    def test_installer_companion_snapshot_and_ack_contract(self):
        source = (ROOT / "scripts/install_agent_release.ps1").read_text(encoding="utf-8")
        required = (
            "[switch]$AcknowledgeCompanionDegraded",
            "COMPANION_CONTROLPLANE_UNREACHABLE",
            "COMPANION_OWNERUI_UNREACHABLE",
            "$OtherServices=@('CyberDefenderControlPlane','CyberDefenderOwnerUI')",
            "$entry.Name -eq 'CyberDefenderOwnerUI'",
            "ListenerPresent",
            "COMPANION_LISTENER_CHANGED",
            "companion_degraded_acknowledged",
            "companion_baseline",
        )
        for marker in required:
            self.assertIn(marker, source)
        self.assertNotIn("Stop-Service -Name CyberDefenderOwnerUI", source)
        self.assertNotIn("Start-Service -Name CyberDefenderOwnerUI", source)
        self.assertNotIn("function Verify-LocalCompanions", source)
        self.assertRegex(source, r"catch\s*\{\s*return\s+\[pscustomobject\]")

    def test_plan_wrapper_always_writes_closed_result_and_pins_every_input(self):
        wrapper = ROOT / "scripts/agent_release/run_installer_plan.ps1"
        source = wrapper.read_text(encoding="utf-8")
        for marker in (
            "ApprovedInstallerSHA256",
            "ApprovedZipSHA256",
            "ApprovedRuntimeZipSHA256",
            "Get-FileHash",
            "RedirectStandardOutput",
            "RedirectStandardError",
            "RecoverStoppedAgent",
            "PLAN_FAIL:",
            "PLAN_PASS",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("-Verb RunAs", source)
        with tempfile.TemporaryDirectory(prefix="cd-plan-wrapper-") as raw:
            result = Path(raw) / "result.txt"
            completed = subprocess.run(
                [
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", str(wrapper),
                    "-InstallerPath", str(Path(raw) / "missing-installer.ps1"),
                    "-ApprovedInstallerSHA256", "0" * 64,
                    "-ReleaseZip", str(Path(raw) / "missing-release.zip"),
                    "-ApprovedZipSHA256", "0" * 64,
                    "-ApprovedCommit", "0" * 40,
                    "-RuntimeZip", str(Path(raw) / "missing-runtime.zip"),
                    "-ApprovedRuntimeZipSHA256", "0" * 64,
                    "-ResultPath", str(result),
                ],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(1, completed.returncode)
            self.assertTrue(result.is_file())
            self.assertRegex(result.read_text(encoding="utf-8"), r"^PLAN_FAIL:[A-Z0-9_]+\nINSTALLER_EXIT=1\n$")


if __name__ == "__main__":
    unittest.main()
