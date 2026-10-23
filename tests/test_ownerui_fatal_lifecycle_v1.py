import ast
import pathlib
import threading
import unittest
from unittest.mock import patch

from agent.service_lifecycle import run_guarded_service


class _Store:
    def close(self):
        pass


class _Watchdog:
    def monitor(self, *_args):
        return None


class _Guard:
    _failure_marked = False

    def __init__(self):
        self.failed_calls = 0

    def admit(self):
        return True

    def failed(self, *_args):
        self.failed_calls += 1
        self._failure_marked = True

    def snapshot(self):
        return {"state": "LATCHED"}


class OwnerUiFatalLifecycleTests(unittest.TestCase):
    def test_attempt_failure_returns_false_without_waiting_for_scm_stop(self):
        guard = _Guard()
        observed = []
        with patch("agent.service_lifecycle.CrashGuard", return_value=guard), \
             patch("agent.service_lifecycle.ProgressWatchdog", return_value=_Watchdog()):
            result = run_guarded_service(
                "CyberDefenderOwnerUI",
                threading.Event(),
                lambda _guard: (_ for _ in ()).throw(RuntimeError("synthetic")),
                store_factory=_Store,
                boot_factory=lambda: "boot",
                observer=lambda _service, state: observed.append(state),
                stop_on_attempt_failure=True,
            )
        self.assertIs(result, False)
        self.assertEqual(guard.failed_calls, 1)
        self.assertIn("LATCHED", observed)

    def test_owner_ui_host_opts_into_fail_closed_stop(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "dashboard_owner" / "windows_service.py").read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertTrue(any(
            any(isinstance(keyword, ast.keyword) and keyword.arg == "stop_on_attempt_failure"
                and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in call.keywords)
            for call in calls
        ))


if __name__ == "__main__":
    unittest.main()
