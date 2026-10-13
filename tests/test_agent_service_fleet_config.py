from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent.main  # Ensure the package exposes agent.main for legacy mock targets.
import agent.windows_service as host


class AgentServiceFleetConfigTests(unittest.TestCase):
    def test_persisted_distribution_url_is_loaded_for_service_process(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {
                "base": root,
                "state": root / "state",
                "secrets": root / "secrets",
                "key": root / "secrets" / "storage_key.b64",
                "fleet_token": root / "secrets" / "fleet_token.txt",
                "remote_fleet_token": root / "secrets" / "remote_fleet_token.txt",
                "endpoint_id": root / "identity" / "endpoint_id.txt",
                "distribution_url": root / "identity" / "distribution_url.txt",
                "distribution_db": root / "control-plane" / "distribution.db",
            }
            paths["key"].parent.mkdir(parents=True)
            paths["endpoint_id"].parent.mkdir(parents=True)
            paths["key"].write_text("A" * 44, encoding="ascii")
            paths["endpoint_id"].write_text("endpoint-1", encoding="ascii")
            paths["remote_fleet_token"].write_text("R" * 64, encoding="ascii")
            paths["distribution_url"].write_text(
                "https://cyberdefender-staging.up.railway.app", encoding="ascii"
            )
            with patch.object(host, "_machine_paths", return_value=paths):
                old = os.environ.get("CYBERDEFENDER_DISTRIBUTION_URL")
                try:
                    host.configure_machine_environment()
                    self.assertEqual(
                        os.environ["CYBERDEFENDER_DISTRIBUTION_URL"],
                        "https://cyberdefender-staging.up.railway.app",
                    )
                    self.assertEqual(
                        os.environ["CYBERDEFENDER_FLEET_TOKEN_FILE"],
                        str(paths["remote_fleet_token"]),
                    )
                finally:
                    if old is None:
                        os.environ.pop("CYBERDEFENDER_DISTRIBUTION_URL", None)
                    else:
                        os.environ["CYBERDEFENDER_DISTRIBUTION_URL"] = old

    def test_invalid_persisted_distribution_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {
                "base": root,
                "state": root / "state",
                "secrets": root / "secrets",
                "key": root / "secrets" / "storage_key.b64",
                "fleet_token": root / "secrets" / "fleet_token.txt",
                "remote_fleet_token": root / "secrets" / "remote_fleet_token.txt",
                "endpoint_id": root / "identity" / "endpoint_id.txt",
                "distribution_url": root / "identity" / "distribution_url.txt",
                "distribution_db": root / "control-plane" / "distribution.db",
            }
            paths["key"].parent.mkdir(parents=True)
            paths["endpoint_id"].parent.mkdir(parents=True)
            paths["key"].write_text("A" * 44, encoding="ascii")
            paths["endpoint_id"].write_text("endpoint-1", encoding="ascii")
            paths["distribution_url"].write_text(" ", encoding="ascii")
            with patch.object(host, "_machine_paths", return_value=paths):
                with self.assertRaisesRegex(ValueError, "invalid persisted distribution URL"):
                    host.configure_machine_environment()

    def test_remote_origin_requires_separate_remote_token(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {
                "base": root,
                "state": root / "state",
                "secrets": root / "secrets",
                "key": root / "secrets" / "storage_key.b64",
                "fleet_token": root / "secrets" / "fleet_token.txt",
                "remote_fleet_token": root / "secrets" / "remote_fleet_token.txt",
                "endpoint_id": root / "identity" / "endpoint_id.txt",
                "distribution_url": root / "identity" / "distribution_url.txt",
                "distribution_db": root / "control-plane" / "distribution.db",
            }
            paths["key"].parent.mkdir(parents=True)
            paths["endpoint_id"].parent.mkdir(parents=True)
            paths["key"].write_text("A" * 44, encoding="ascii")
            paths["fleet_token"].write_text("L" * 64, encoding="ascii")
            paths["endpoint_id"].write_text("endpoint-1", encoding="ascii")
            paths["distribution_url"].write_text(
                "https://cyberdefender-staging.up.railway.app", encoding="ascii"
            )
            with patch.object(host, "_machine_paths", return_value=paths):
                with self.assertRaisesRegex(ValueError, "remote fleet token missing"):
                    host.configure_machine_environment()

    def test_loopback_origin_keeps_local_control_plane_token(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {
                "base": root,
                "state": root / "state",
                "secrets": root / "secrets",
                "key": root / "secrets" / "storage_key.b64",
                "fleet_token": root / "secrets" / "fleet_token.txt",
                "remote_fleet_token": root / "secrets" / "remote_fleet_token.txt",
                "endpoint_id": root / "identity" / "endpoint_id.txt",
                "distribution_url": root / "identity" / "distribution_url.txt",
                "distribution_db": root / "control-plane" / "distribution.db",
            }
            paths["key"].parent.mkdir(parents=True)
            paths["endpoint_id"].parent.mkdir(parents=True)
            paths["key"].write_text("A" * 44, encoding="ascii")
            paths["fleet_token"].write_text("L" * 64, encoding="ascii")
            paths["endpoint_id"].write_text("endpoint-1", encoding="ascii")
            paths["distribution_url"].write_text("http://127.0.0.1:8785", encoding="ascii")
            with patch.object(host, "_machine_paths", return_value=paths):
                host.configure_machine_environment()
                self.assertEqual(
                    os.environ["CYBERDEFENDER_FLEET_TOKEN_FILE"],
                    str(paths["fleet_token"]),
                )


if __name__ == "__main__":
    unittest.main()
