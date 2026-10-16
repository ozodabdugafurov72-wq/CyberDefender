from __future__ import annotations

from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
