from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import control_plane.distribution_server as server
from control_plane.distribution_repository import DistributionRepository


class DistributionSecurityContractTests(unittest.TestCase):
    def test_manifest_matches_artifact_and_cache_invalidates(self):
        test_root = Path(".test-tmp").resolve()
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cd-manifest-", dir=test_root) as directory:
            artifact = Path(directory) / "CyberDefenderPackage.zip"
            artifact.write_bytes(b"first-artifact")
            with patch.object(server, "ARTIFACT", artifact), patch.object(server, "_MANIFEST_CACHE", None):
                first = server._artifact_manifest()
                self.assertEqual(first["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
                self.assertEqual(first["size"], artifact.stat().st_size)
                artifact.write_bytes(b"second-artifact-content")
                second = server._artifact_manifest()
                self.assertNotEqual(first["sha256"], second["sha256"])

    def test_private_read_token_is_distinct_and_fail_closed(self):
        with patch.dict(
            os.environ,
            {
                "CYBERDEFENDER_FLEET_TOKEN": "fleet-token",
                "CYBERDEFENDER_DISTRIBUTION_READ_TOKEN": "read-token",
            },
            clear=False,
        ):
            self.assertTrue(server._authorized("Bearer fleet-token"))
            self.assertFalse(server._authorized("Bearer read-token"))
            self.assertTrue(server._authorized("Bearer read-token", server._read_token()))
            self.assertFalse(server._authorized("Bearer fleet-token", server._read_token()))
            self.assertFalse(server._authorized(None, server._read_token()))

    def test_owner_read_endpoint_requires_private_host(self):
        with patch.dict(os.environ, {"RAILWAY_PRIVATE_DOMAIN": "cyberdefender.railway.internal"}, clear=False):
            self.assertTrue(server._private_network_host("cyberdefender.railway.internal:8080"))
            self.assertFalse(server._private_network_host("cyberdefender-production.up.railway.app"))
            self.assertFalse(server._private_network_host(None))

    def test_owner_snapshot_reads_existing_database_without_migration(self):
        test_root = Path(".test-tmp").resolve()
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cd-owner-snapshot-", dir=test_root) as directory:
            db = Path(directory) / "distribution.db"
            repository = DistributionRepository(db)
            repository.register_endpoint(
                endpoint_id="endpoint-1",
                hostname="host-a",
                runtime_version="1",
                health_state="HEALTHY",
                service_state="RUNNING",
            )
            repository.close()
            snapshot = server._owner_snapshot(db)
            self.assertTrue(snapshot["read_only"])
            self.assertEqual(snapshot["summary"]["endpoints_total"], 1)
            self.assertEqual(snapshot["endpoints"][0]["endpoint_id"], "endpoint-1")
            self.assertNotIn("last_error", snapshot["endpoints"][0])

    def test_startup_initializes_empty_persistent_database(self):
        test_root = Path(".test-tmp").resolve()
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cd-startup-db-", dir=test_root) as directory:
            db = Path(directory) / "distribution.db"
            self.assertFalse(db.exists())
            server._initialize_database(db)
            snapshot = server._owner_snapshot(db)
            self.assertEqual(snapshot["status"], "HEALTHY")
            self.assertEqual(snapshot["summary"]["downloads_total"], 0)
            self.assertEqual(snapshot["summary"]["endpoints_total"], 0)


if __name__ == "__main__":
    unittest.main()
