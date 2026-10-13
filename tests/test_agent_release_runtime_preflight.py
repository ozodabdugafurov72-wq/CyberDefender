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

                    # Installed endpoints begin in LOCAL_STANDALONE scope. A
                    # normal tenantless observation must still complete the
                    # durable correlation/outbox/ACK path without claiming
                    # tenant membership.
                    self.assertTrue(runtime.resource_delivery_gate.bind_cycle(0))
                    self.assertTrue(
                        runtime.resource_safety_plane.commit_resource_snapshot(
                            {"state": "NORMAL"}, cycle_id=0
                        )
                    )
                    event = runtime._build_event(
                        {
                            "type": "RELEASE_PREFLIGHT_OBSERVATION",
                            "severity": "INFO",
                            "value": 1,
                            "message": "standalone durable pipeline preflight",
                            "host_id": "release-preflight-endpoint",
                        },
                        "ReleasePreflight",
                    )
                    self.assertIsNone(event.tenant_id)
                    admitted = runtime.admit_event(event)
                    self.assertTrue(admitted.accepted)
                    self.assertGreaterEqual(runtime.event_bus.dispatch_all(), 1)
                    self.assertEqual(1, runtime.events_acked)
                    self.assertEqual(0, runtime.component_failures)
                    outbox_record = runtime.incident_outbox.scan()[0]
                    self.assertEqual(
                        "local-endpoint:release-preflight-endpoint",
                        outbox_record["tenant_id"],
                    )
                    self.assertIsNone(outbox_record["incident_payload"]["tenant_id"])
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
