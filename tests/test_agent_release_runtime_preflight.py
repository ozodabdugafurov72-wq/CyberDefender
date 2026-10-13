from __future__ import annotations

import base64
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.main import build_managed_runtime
from agent.windows_service import configure_machine_environment


class AgentReleaseRuntimePreflightTests(unittest.TestCase):
    def test_remote_release_builds_healthy_runtime_in_installed_python(self):
        """Exercise the full release without touching SCM or machine state."""
        with tempfile.TemporaryDirectory(prefix="cd-release-preflight-") as raw:
            program_data = Path(raw)
            base = program_data / "CyberDefender"
            secrets_dir = base / "secrets"
            identity_dir = base / "identity"
            state_dir = base / "state"
            control_dir = base / "control-plane"
            for path in (secrets_dir, identity_dir, state_dir, control_dir):
                path.mkdir(parents=True, exist_ok=True)

            (secrets_dir / "storage_key.b64").write_text(
                base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                encoding="ascii",
            )
            (secrets_dir / "fleet_token.txt").write_text("L" * 64, encoding="ascii")
            (secrets_dir / "remote_fleet_token.txt").write_text("R" * 64, encoding="ascii")
            (identity_dir / "endpoint_id.txt").write_text(
                "release-preflight-endpoint", encoding="ascii"
            )
            (identity_dir / "distribution_url.txt").write_text(
                "https://cyberdefender-staging.up.railway.app", encoding="ascii"
            )

            with patch.dict(os.environ, {"PROGRAMDATA": str(program_data)}, clear=False):
                configure_machine_environment()
                self.assertEqual(
                    Path(os.environ["CYBERDEFENDER_FLEET_TOKEN_FILE"]),
                    secrets_dir / "remote_fleet_token.txt",
                )
                runtime = build_managed_runtime(allow_optional_sensors=False)
                try:
                    health = runtime.health_snapshot()
                    self.assertEqual(health["runtime"]["status"], "HEALTHY")
                    for component in (
                        "key_manager",
                        "runtime_pipeline",
                        "admission_gateway",
                        "spool",
                        "pipeline",
                    ):
                        self.assertEqual(health[component]["status"], "HEALTHY")
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
