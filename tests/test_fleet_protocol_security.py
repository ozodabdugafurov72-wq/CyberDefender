from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from agent.fleet.client import FleetTelemetryClient
from control_plane import distribution_server as server
from control_plane.distribution_repository import DistributionRepository
from control_plane.fleet_protocol import FleetProtocolError, SlidingWindowLimiter, signature_headers, verify_request
from control_plane.xdr_compat import (
    CAPABILITY_DEVICE_INVENTORY,
    CAPABILITY_ENDPOINT_HEALTH,
    OCSF_DEVICE_INVENTORY_CLASS_UID,
    OCSF_INCIDENT_FINDING_CLASS_UID,
    OCSF_SCHEMA_NAME,
    OCSF_SCHEMA_VERSION,
    device_inventory_event,
    incident_finding_event,
    validate_device_inventory_event,
    validate_incident_finding_event,
)


TOKEN = "fleet-test-token-0123456789-abcdef-0123456789"
READ_TOKEN = "owner-read-token-0123456789-abcdef-0123456789"


def payload(endpoint_id: str = "endpoint-1", **updates):
    value = {
        "protocol_version": "cyberdefender.fleet.v1",
        "observed_at": int(time.time() * 1000),
        "telemetry_schema": OCSF_SCHEMA_NAME,
        "telemetry_schema_version": OCSF_SCHEMA_VERSION,
        "xdr_event_class_uids": [OCSF_DEVICE_INVENTORY_CLASS_UID],
        "capabilities": [CAPABILITY_ENDPOINT_HEALTH, CAPABILITY_DEVICE_INVENTORY],
        "endpoint_id": endpoint_id,
        "hostname": "host-a",
        "runtime_version": "2.4",
        "install_state": "INSTALLED",
        "health_state": "HEALTHY",
        "service_state": "RUNNING",
    }
    value.update(updates)
    return value


class FleetProtocolUnitTests(unittest.TestCase):
    def test_rate_limiter_recovers_after_window(self):
        now = [1000.0]
        limiter = SlidingWindowLimiter(limit=2, window_seconds=60, clock=lambda: now[0])
        self.assertTrue(limiter.allow("endpoint"))
        self.assertTrue(limiter.allow("endpoint"))
        self.assertFalse(limiter.allow("endpoint"))
        self.assertTrue(limiter.allow("other-endpoint"))
        now[0] += 61
        self.assertTrue(limiter.allow("endpoint"))

    def test_signature_binds_method_path_body_and_time(self):
        raw = json.dumps(payload(), sort_keys=True, separators=(",", ":")).encode()
        headers = signature_headers(
            TOKEN,
            method="POST",
            path="/api/v1/enrollment/register",
            body=raw,
            timestamp=2_000_000_000,
            nonce="a" * 32,
        )
        verified = verify_request(
            TOKEN,
            method="POST",
            path="/api/v1/enrollment/register",
            body=raw,
            headers=headers,
            now=2_000_000_000,
        )
        self.assertEqual(verified.nonce, "a" * 32)
        with self.assertRaises(FleetProtocolError):
            verify_request(
                TOKEN,
                method="POST",
                path="/api/v1/endpoints/heartbeat",
                body=raw,
                headers=headers,
                now=2_000_000_000,
            )
        with self.assertRaises(FleetProtocolError):
            verify_request(
                TOKEN,
                method="POST",
                path="/api/v1/enrollment/register",
                body=raw + b" ",
                headers=headers,
                now=2_000_000_000,
            )
        with self.assertRaises(FleetProtocolError):
            verify_request(
                TOKEN,
                method="POST",
                path="/api/v1/enrollment/register",
                body=raw,
                headers=headers,
                now=2_000_000_301,
            )

    def test_repository_rejects_identity_and_state_poisoning(self):
        root = Path(".test-tmp")
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cd-xdr-repo-", dir=root) as directory:
            repository = DistributionRepository(Path(directory) / "distribution.db")
            invalid = [
                {"endpoint_id": "", "hostname": "host", "health_state": "HEALTHY", "service_state": "RUNNING"},
                {"endpoint_id": "../escape", "hostname": "host", "health_state": "HEALTHY", "service_state": "RUNNING"},
                {"endpoint_id": "endpoint", "hostname": "host\nforged", "health_state": "HEALTHY", "service_state": "RUNNING"},
                {"endpoint_id": "endpoint", "hostname": "host", "health_state": "BENIGN", "service_state": "RUNNING"},
                {"endpoint_id": "endpoint", "hostname": "host", "health_state": "HEALTHY", "service_state": "PWNED"},
            ]
            for item in invalid:
                with self.subTest(item=item), self.assertRaises(ValueError):
                    repository.heartbeat(runtime_version="2.4", resource_state="NORMAL", **item)
            self.assertTrue(
                repository.accept_request_nonce(nonce="b" * 32, endpoint_id="endpoint", observed_at=time.time())
            )
            self.assertFalse(
                repository.accept_request_nonce(nonce="b" * 32, endpoint_id="endpoint", observed_at=time.time())
            )
            repository.close()

    def test_schema_v1_migrates_without_losing_endpoint_rows(self):
        root = Path(".test-tmp")
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cd-xdr-migration-", dir=root) as directory:
            db = Path(directory) / "distribution.db"
            conn = sqlite3.connect(db)
            conn.executescript(
                """
                CREATE TABLE distribution_schema(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL);
                INSERT INTO distribution_schema(version,applied_at) VALUES(1,1);
                CREATE TABLE downloads(
                    download_id TEXT PRIMARY KEY, requested_at REAL NOT NULL, completed_at REAL,
                    status TEXT NOT NULL, artifact_name TEXT NOT NULL, version TEXT,
                    channel TEXT NOT NULL, bytes_sent INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE fleet_endpoints(
                    endpoint_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, download_id TEXT,
                    install_state TEXT NOT NULL, health_state TEXT NOT NULL,
                    service_state TEXT NOT NULL, runtime_version TEXT, resource_state TEXT,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL, last_error TEXT
                );
                INSERT INTO fleet_endpoints(
                    endpoint_id,hostname,install_state,health_state,service_state,
                    runtime_version,resource_state,first_seen,last_seen
                ) VALUES('legacy-1','legacy-host','INSTALLED','HEALTHY','RUNNING','2.3','NORMAL',1,2);
                """
            )
            conn.commit()
            conn.close()

            repository = DistributionRepository(db)
            row = repository.recent_endpoints()[0]
            versions = repository._conn.execute(
                "SELECT version FROM distribution_schema ORDER BY version"
            ).fetchall()
            self.assertEqual([item["version"] for item in versions], [1, 2])
            self.assertEqual(row["endpoint_id"], "legacy-1")
            self.assertEqual(row["telemetry_schema"], "legacy")
            self.assertEqual(row["capabilities_json"], "[]")
            repository.close()

    def test_ocsf_device_inventory_mapping_has_required_classification(self):
        event = device_inventory_event(
            {
                "endpoint_id": "endpoint-1",
                "hostname": "host-a",
                "runtime_version": "2.4",
                "first_seen": 1_900_000_000.0,
                "last_seen": 1_900_000_100.0,
                "install_state": "INSTALLED",
                "health_state": "HEALTHY",
                "service_state": "RUNNING",
                "resource_state": "NORMAL",
            }
        )
        self.assertEqual(event["category_uid"], 5)
        self.assertEqual(event["class_uid"], 5001)
        self.assertEqual(event["activity_id"], 2)
        self.assertEqual(event["type_uid"], 500102)
        self.assertEqual(event["metadata"]["version"], OCSF_SCHEMA_VERSION)
        self.assertEqual(event["device"]["uid"], "endpoint-1")
        self.assertTrue(event["device"]["is_managed"])
        validate_device_inventory_event(event)
        event["type_uid"] = 500199
        with self.assertRaises(ValueError):
            validate_device_inventory_event(event)

    def test_internal_incident_maps_to_valid_ocsf_incident_lifecycle(self):
        incident = {
            "event_type": "INCIDENT",
            "tenant_id": "tenant-a",
            "incident_id": "INC-001",
            "severity": "HIGH",
            "risk_score": 82.0,
            "event_count": 2,
            "correlation_key": "endpoint:host-a:process",
            "incident_family": "suspicious process chain",
            "detections": [
                {
                    "source_event_id": "evt-001",
                    "type": "PROCESS_ANOMALY",
                    "timestamp": 1_900_000_010.0,
                },
                {
                    "type": "NETWORK_ANOMALY",
                    "timestamp": 1_900_000_020.0,
                },
            ],
            "created_at": 1_900_000_000.0,
            "updated_at": 1_900_000_030.0,
            "current_state": "ACTIVE",
            "active_now": True,
        }
        event = incident_finding_event(incident, product_version="2.4")
        self.assertEqual(event["class_uid"], OCSF_INCIDENT_FINDING_CLASS_UID)
        self.assertEqual(event["activity_id"], 2)
        self.assertEqual(event["type_uid"], 200502)
        self.assertEqual(event["status_id"], 2)
        self.assertEqual(event["severity_id"], 4)
        self.assertEqual(event["metadata"]["tenant_uid"], "tenant-a")
        self.assertEqual(len(event["finding_info_list"]), 2)
        self.assertEqual(event["finding_info_list"][0]["uid"], "evt-001")
        self.assertIn(":sha256:", event["finding_info_list"][1]["uid"])
        validate_incident_finding_event(event)

        incident["active_now"] = False
        incident["current_state"] = "RECOVERED"
        closed = incident_finding_event(incident, product_version="2.4")
        self.assertEqual(closed["activity_id"], 3)
        self.assertEqual(closed["type_uid"], 200503)
        self.assertEqual(closed["status"], "Resolved")

        incident["risk_score"] = 101
        with self.assertRaises(ValueError):
            incident_finding_event(incident, product_version="2.4")


class FleetProtocolHttpTests(unittest.TestCase):
    def setUp(self):
        root = Path(".test-tmp")
        root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="cd-xdr-http-", dir=root)
        self.root = Path(self.temp.name)
        self.db = self.root / "distribution.db"
        self.artifact = self.root / "CyberDefenderPackage.zip"
        self.artifact.write_bytes(b"artifact")
        self.token_file = self.root / "fleet-token.txt"
        self.token_file.write_text(TOKEN, encoding="ascii")
        self.endpoint_file = self.root / "endpoint-id.txt"
        self.endpoint_file.write_text("endpoint-http", encoding="ascii")
        self.environment = patch.dict(
            os.environ,
            {
                "CYBERDEFENDER_DISTRIBUTION_READ_TOKEN": READ_TOKEN,
                "RAILWAY_PRIVATE_DOMAIN": "distribution.railway.internal",
            },
            clear=False,
        )
        self.environment.start()
        self.objects = patch.multiple(
            server,
            DB=self.db,
            ARTIFACT=self.artifact,
            TOKEN_FILE=self.token_file,
            _MANIFEST_CACHE=None,
        )
        self.objects.start()
        server._initialize_database(self.db)
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

    def post(self, path: str, value: dict, *, signed: bool = True, raw: bytes | None = None):
        body = raw if raw is not None else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + TOKEN}
        if signed:
            headers.update(signature_headers(TOKEN, method="POST", path=path, body=body))
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        return response.status, response.headers, response.read(), headers, body

    def get(self, path: str, *, private: bool = False):
        headers = {}
        if private:
            headers.update(
                {
                    "Host": "distribution.railway.internal",
                    "Authorization": "Bearer " + READ_TOKEN,
                }
            )
        request = urllib.request.Request(self.base + path, headers=headers, method="GET")
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        return response.status, response.headers, response.read()

    def test_signed_client_and_private_ocsf_export(self):
        client = FleetTelemetryClient(self.base, self.token_file, self.endpoint_file)
        self.assertTrue(client.register(runtime_version="2.4", health_state="HEALTHY", service_state="RUNNING"))
        self.assertTrue(
            client.heartbeat(
                runtime_version="2.4",
                health_state="HEALTHY",
                service_state="RUNNING",
                resource_state="NORMAL",
            )
        )
        status, _, body = self.get("/api/v1/owner/summary", private=True)
        self.assertEqual(status, 200)
        summary = json.loads(body)
        self.assertTrue(summary["xdr"]["signed_ingest"])
        self.assertTrue(summary["xdr"]["replay_protection"])
        self.assertEqual(summary["endpoints"][0]["telemetry_schema"], "ocsf")
        status, _, body = self.get("/api/v1/owner/xdr/ocsf/device-inventory", private=True)
        self.assertEqual(status, 200)
        export = json.loads(body)
        self.assertEqual(export["schema_version"], OCSF_SCHEMA_VERSION)
        self.assertEqual(export["events"][0]["class_uid"], 5001)
        self.assertEqual(export["events"][0]["device"]["uid"], "endpoint-http")
        self.assertEqual(self.get("/api/v1/owner/xdr/ocsf/device-inventory")[0], 404)

    def test_tamper_replay_unsigned_and_invalid_identity_are_rejected(self):
        path = "/api/v1/enrollment/register"
        value = payload("endpoint-replay")
        status, _, _, headers, body = self.post(path, value)
        self.assertEqual(status, 200)
        replay = urllib.request.Request(self.base + path, data=body, headers=headers, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as replay_error:
            urllib.request.urlopen(replay, timeout=3)
        self.assertEqual(replay_error.exception.code, 409)

        tampered = body.replace(b"host-a", b"host-b")
        request = urllib.request.Request(self.base + path, data=tampered, headers=headers, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as tamper_error:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(tamper_error.exception.code, 401)

        self.assertEqual(self.post(path, payload("endpoint-unsigned"), signed=False)[0], 401)
        self.assertEqual(self.post(path, payload(""))[0], 400)
        self.assertEqual(self.post(path, payload("endpoint-state", service_state="PWNED"))[0], 400)

    def test_security_headers_and_oversized_body(self):
        status, headers, _ = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("max-age=31536000", headers.get("Strict-Transport-Security", ""))
        oversized = b"{" + b"a" * (server.MAX_BODY + 1) + b"}"
        self.assertEqual(self.post("/api/v1/endpoints/heartbeat", {}, raw=oversized)[0], 413)


if __name__ == "__main__":
    unittest.main()
