from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import control_plane.distribution_server as server
from control_plane.cloud_soc_v2 import CloudSocRepository, CloudSocService, signature_headers


READ_TOKEN = "read-token-for-cloud-soc-v2-tests-0123456789"


def public_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def encoded(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CloudSocV2HttpTests(unittest.TestCase):
    def setUp(self):
        root = Path(".test-tmp").resolve()
        root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="cd-cloud-v2-http-", dir=root)
        self.db = Path(self.temp.name) / "distribution.db"
        self.artifact = Path(self.temp.name) / "package.zip"
        self.artifact.write_bytes(b"test")
        self.token_file = Path(self.temp.name) / "v1-token.txt"
        self.token_file.write_text("x" * 48, encoding="ascii")
        self.environment = patch.dict(os.environ, {
            "CYBERDEFENDER_CLOUD_SOC_V2": "1",
            "CYBERDEFENDER_DISTRIBUTION_READ_TOKEN": READ_TOKEN,
            "CYBERDEFENDER_CLOUD_SOC_READ_TOKENS_JSON": json.dumps({
                "tenant-a": READ_TOKEN,
                "tenant-b": "tenant-b-read-token-for-tests-0123456789",
            }),
            "RAILWAY_PRIVATE_DOMAIN": "distribution.railway.internal",
        }, clear=False)
        self.environment.start()
        self.objects = patch.multiple(server, DB=self.db, ARTIFACT=self.artifact,
                                      TOKEN_FILE=self.token_file, _MANIFEST_CACHE=None)
        self.objects.start()
        server._initialize_database(self.db)
        self.repository = CloudSocRepository(self.db)
        self.key = Ed25519PrivateKey.generate()
        self.code = self.repository.issue_enrollment_code("tenant-a", now=time.time())
        self.repository.close()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.objects.stop()
        self.environment.stop()
        self.temp.cleanup()

    def request(self, method: str, path: str, *, body: bytes | None = None,
                headers: dict[str, str] | None = None):
        request = urllib.request.Request(self.base + path, data=body, headers=headers or {}, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        try:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
        finally:
            response.close()

    def test_enrollment_authenticated_ingest_replay_and_tenant_read_boundary(self):
        enroll = {
            "schema": "cyberdefender.enrollment.v2",
            "one_time_code": self.code,
            "agent_instance_id": str(uuid.uuid4()),
            "device_public_key": public_text(self.key),
            "hostname": "http-endpoint.example",
            "runtime_version": "2.4",
            "capabilities": ["endpoint-health", "event-batches"],
        }
        status, identity = self.request(
            "POST", "/api/v2/enrollment", body=encoded(enroll),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(identity["tenant_id"], "tenant-a")
        self.assertFalse(identity["private_key_returned"])

        endpoint_id = identity["endpoint_id"]
        path = f"/api/v2/endpoints/{endpoint_id}/heartbeat"
        heartbeat = {
            "schema": "cyberdefender.heartbeat.v2", "heartbeat_id": "http-heartbeat-1",
            "endpoint_id": endpoint_id, "boot_id": str(uuid.uuid4()), "seq": 1,
            "observed_at": time.time(), "health_state": "HEALTHY", "service_state": "RUNNING",
            "resource_state": "NORMAL", "runtime_version": "2.4", "component_failures": 0,
            "cycle": 1, "cpu_percent": 10.0, "memory_percent": 20.0,
            "spool": {"pending": 0, "bytes": 0, "status": "HEALTHY"},
        }
        raw = encoded(heartbeat)
        self.assertEqual(self.request("POST", path, body=raw,
                                     headers={"Content-Type": "application/json"})[0], 401)
        signed = {"Content-Type": "application/json"}
        signed.update(signature_headers(self.key, credential_id=identity["credential_id"],
                                        path=path, body=raw, sequence=1))
        self.assertEqual(self.request("POST", path, body=raw, headers=signed)[0], 200)
        self.assertEqual(self.request("POST", path, body=raw, headers=signed)[0], 409)

        private = {"Host": "distribution.railway.internal", "Authorization": "Bearer " + READ_TOKEN}
        status, fleet = self.request("GET", "/api/v2/owner/tenants/tenant-a/fleet", headers=private)
        self.assertEqual(status, 200)
        self.assertEqual(fleet["summary"]["online"], 1)
        self.assertEqual(fleet["tenant_id"], "tenant-a")
        self.assertEqual(self.request("GET", "/api/v2/owner/tenants/tenant-b/fleet", headers=private)[0], 403)

        key_b = Ed25519PrivateKey.generate()
        repository = CloudSocRepository(self.db)
        code_b = repository.issue_enrollment_code("tenant-b", now=time.time())
        identity_b = repository.enroll({"schema": "cyberdefender.enrollment.v2", "one_time_code": code_b,
            "agent_instance_id": str(uuid.uuid4()), "device_public_key": public_text(key_b),
            "hostname": "tenant-b-endpoint.example", "runtime_version": "2.4",
            "capabilities": ["endpoint-health", "event-batches"]}, now=time.time())
        service_b = CloudSocService(repository)
        endpoint_b = identity_b["endpoint_id"]
        heartbeat_b = dict(heartbeat, heartbeat_id="tenant-b-heartbeat", endpoint_id=endpoint_b,
                           boot_id=str(uuid.uuid4()))
        heartbeat_b_raw = encoded(heartbeat_b)
        heartbeat_b_path = f"/api/v2/endpoints/{endpoint_b}/heartbeat"
        service_b.ingest_heartbeat(endpoint_b, heartbeat_b_raw, signature_headers(
            key_b, credential_id=identity_b["credential_id"], path=heartbeat_b_path,
            body=heartbeat_b_raw, sequence=1))
        event_b = {"schema": "cyberdefender.event-batch.v2", "batch_id": "tenant-b-batch",
            "endpoint_id": endpoint_b, "boot_id": heartbeat_b["boot_id"], "first_seq": 2, "last_seq": 2,
            "events": [{"event_id": "tenant-b-event", "seq": 2, "observed_at": time.time(),
                        "type": "DETECTION", "priority": "HIGH", "payload": {"rule": "tenant-b-only"}}]}
        event_b_raw = encoded(event_b)
        event_b_path = f"/api/v2/endpoints/{endpoint_b}/event-batches"
        service_b.ingest_events(endpoint_b, event_b_raw, signature_headers(
            key_b, credential_id=identity_b["credential_id"], path=event_b_path,
            body=event_b_raw, sequence=2))
        repository.close()

        self.assertEqual(self.request("GET", "/api/v2/owner/tenants/tenant-b/fleet", headers=private)[0], 403)
        tenant_b = {"Host": "distribution.railway.internal",
                    "Authorization": "Bearer tenant-b-read-token-for-tests-0123456789"}
        tenant_b_fleet = self.request("GET", "/api/v2/owner/tenants/tenant-b/fleet", headers=tenant_b)[1]
        self.assertEqual(tenant_b_fleet["summary"]["total"], 1)
        self.assertEqual(tenant_b_fleet["event_summary"][0]["count"], 1)

        with patch.dict(os.environ, {"CYBERDEFENDER_CLOUD_SOC_READ_TOKENS_JSON": json.dumps({
                "tenant-a": READ_TOKEN, "tenant-b": READ_TOKEN})}, clear=False):
            self.assertEqual(self.request("GET", "/api/v2/owner/tenants/tenant-a/fleet", headers=private)[0], 403)
        self.assertEqual(self.request("GET", "/api/v2/owner/tenants/tenant-a/fleet")[0], 404)

    def test_v2_routes_are_hidden_when_feature_is_disabled(self):
        with patch.dict(os.environ, {"CYBERDEFENDER_CLOUD_SOC_V2": "0"}, clear=False):
            private = {"Host": "distribution.railway.internal", "Authorization": "Bearer " + READ_TOKEN}
            self.assertEqual(self.request("GET", "/api/v2/owner/tenants/tenant-a/fleet", headers=private)[0], 404)
            self.assertEqual(self.request("POST", "/api/v2/enrollment", body=b"{}",
                                          headers={"Content-Type": "application/json"})[0], 404)


if __name__ == "__main__":
    unittest.main()
