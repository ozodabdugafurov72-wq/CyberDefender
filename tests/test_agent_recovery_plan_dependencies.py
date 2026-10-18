from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts.agent_release import agent_service_bootstrap as bootstrap


class RecoveryPlanDependencyTests(unittest.TestCase):
    def test_detached_verified_runtime_initializes_pywin32_before_recovery_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            release = base / "release"
            runtime = base / "preflight-runtime"
            dependencies = runtime / "Lib" / "site-packages"
            release.mkdir()
            runtime.mkdir()
            executable = runtime / "python.exe"
            executable.write_bytes(b"pinned-test-interpreter")
            for relative in ("win32", "win32/lib", "Pythonwin"):
                (dependencies / relative).mkdir(parents=True, exist_ok=True)
            bootstrap_file = dependencies / "pywin32_bootstrap.py"
            bootstrap_file.write_text("# test bootstrap\n", encoding="utf-8")
            origins: dict[str, Path] = {}
            for name in (
                "cryptography", "psutil", "pywintypes", "servicemanager",
                "win32file", "win32security", "win32service", "win32serviceutil",
            ):
                origin = dependencies / f"{name}.py"
                origin.write_text("# test module\n", encoding="utf-8")
                origins[name] = origin

            def import_module(name: str):
                module = types.ModuleType(name)
                module.__file__ = str(bootstrap_file if name == "pywin32_bootstrap" else origins[name])
                return module

            original_path = list(sys.path)
            try:
                with (
                    mock.patch.object(bootstrap.sys, "executable", str(executable)),
                    mock.patch.object(
                        bootstrap.importlib.util,
                        "find_spec",
                        return_value=types.SimpleNamespace(origin=str(bootstrap_file)),
                    ),
                    mock.patch.object(bootstrap.importlib, "import_module", side_effect=import_module),
                ):
                    bootstrap._verify_pinned_dependencies(
                        release,
                        required=True,
                        allow_detached_runtime=True,
                    )
                    with self.assertRaisesRegex(RuntimeError, "pinned runtime"):
                        bootstrap._verify_pinned_dependencies(
                            release,
                            required=True,
                            allow_detached_runtime=False,
                        )
            finally:
                sys.path[:] = original_path


if __name__ == "__main__":
    unittest.main()
