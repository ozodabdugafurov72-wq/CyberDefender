from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from owner_cloud.distribution_client import DistributionClient


def valid_state():
    return {
        "status": "HEALTHY",
        "read_only": True,
        "summary": {
            "downloads_total": 3,
            "downloads_completed": 3,
            "downloads_failed": 0,
            "endpoints_total": 1,
            "installed": 1,
            "pending": 0,
            "install_failed": 0,
            "revoked": 0,
            "online": 1,
            "offline": 0,
            "degraded": 0,
            "critical": 0,
            "responses_total": 1,
            "responses_quarantined": 1,
            "responses_restored": 0,
            "response_latency_ms_max": 90.363,
        },
        "endpoints": [],
        "responses": [{
            "schema": "cyberdefender.response-evidence.v1",
            "evidence_id": "qv2-response-001",
            "endpoint_id": "endpoint-1",
            "incident_id": "INC-RESPONSE-001",
            "event_id": "event-response-001",
            "observed_at": 1_900_000_000.0,
            "received_at": 1_900_000_001.0,
            "target_name": "harmless-canary.txt",
            "target_sha256": "a" * 64,
            "detection_types": ["HIGH_MEMORY_USAGE"],
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "policy_outcome": "REQUIRE_VERIFICATION",
            "policy_reason": "critical risk requires independent verification",
            "verifier_outcome": "VERIFIED",
            "action_state": "QUARANTINED",
            "verification_outcome": "QUARANTINED_VERIFIED",
            "response_latency_ms": 90.363,
            "execution_latency_ms": 65.681,
            "detection_to_response_ms": 90.255,
            "restore_latency_ms": None,
            "evidence_ref": "evidence://INC-RESPONSE-001",
            "production_authorization": "NOT_GRANTED",
            "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED",
            "receipt_integrity": True,
            "post_action_verification": True,
        }],
        "xdr": {
            "status": "READY",
            "schema": "OCSF",
            "schema_version": "1.9.0",
            "ingest_protocol": "cyberdefender.fleet.v1",
            "signed_ingest": True,
            "replay_protection": True,
            "runtime_contract_validation": True,
            "event_classes": [
                {
                    "class_uid": 5001,
                    "class_name": "Device Inventory Info",
                    "activity_id": 2,
                }
            ],
        },
    }


def valid_v2_state():
    return {
        "schema": "cyberdefender.fleet-read-model.v2",
        "tenant_id": "tenant-a",
        "generated_at": 1_900_000_001.0,
        "online_after_seconds": 90.0,
        "summary": {"total": 1, "online": 1, "offline": 0, "degraded": 0, "critical": 0},
        "endpoints": [{
            "endpoint_id": "11111111-1111-4111-8111-111111111111",
            "hostname": "endpoint.example",
            "status": "ONLINE",
            "health_state": "HEALTHY",
            "service_state": "RUNNING",
            "resource_state": "NORMAL",
            "runtime_version": "2.4",
            "last_verified_heartbeat": 1_900_000_001.0,
            "last_observed_at": 1_900_000_000.0,
            "component_failures": 0,
            "cycle": 7,
            "cpu_percent": 12.5,
            "memory_percent": 42.0,
            "telemetry_status": "HEALTHY",
        }],
        "event_summary": [{"event_type": "DETECTION", "priority": "HIGH", "count": 1}],
        "read_only": True,
        "privileged_actions": "DISABLED",
    }


class SinkHandler(BaseHTTPRequestHandler):
    hits = 0
    authorization = None

    def log_message(self, format, *args):
        return

    def do_GET(self):
        type(self).hits += 1
        type(self).authorization = self.headers.get("Authorization")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


class UpstreamHandler(BaseHTTPRequestHandler):
    mode = "valid"
    redirect_url = ""

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if type(self).mode == "redirect":
            self.send_response(307)
            self.send_header("Location", type(self).redirect_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        value = valid_v2_state() if type(self).mode.startswith("v2") else valid_state()
        if type(self).mode == "v2-cross-tenant":
            value["tenant_id"] = "tenant-b"
        if type(self).mode == "v2-false-online":
            value["endpoints"][0]["status"] = "OFFLINE"
        if type(self).mode == "invalid-xdr":
            value["xdr"]["signed_ingest"] = False
        if type(self).mode == "invalid-class":
            value["xdr"]["event_classes"] = [{"class_uid": 2005}]
        if type(self).mode == "invalid-response":
            value["responses"][0]["production_authorization"] = "GRANTED"
        if type(self).mode == "invalid-endpoint":
            value["endpoints"] = [{
                "endpoint_id": "../cross-tenant",
                "hostname": "host-a",
                "install_state": "INSTALLED",
                "health_state": "HEALTHY",
                "service_state": "RUNNING",
                "runtime_version": "2.4",
                "resource_state": "NORMAL",
                "first_seen": 1_900_000_000.0,
                "last_seen": 1_900_000_001.0,
                "telemetry_schema": "ocsf",
                "telemetry_schema_version": "1.9.0",
                "capabilities": ["endpoint-health"],
                "last_observed_at": 1_900_000_001.0,
            }]
        raw = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class OwnerDistributionClientSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SinkHandler.hits = 0
        SinkHandler.authorization = None
        cls.sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
        cls.sink_thread = threading.Thread(target=cls.sink.serve_forever, daemon=True)
        cls.sink_thread.start()
        UpstreamHandler.redirect_url = f"http://127.0.0.1:{cls.sink.server_address[1]}/capture"
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        cls.upstream_thread = threading.Thread(target=cls.upstream.serve_forever, daemon=True)
        cls.upstream_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.upstream.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()
        cls.upstream.server_close()
        cls.upstream_thread.join(timeout=2)
        cls.sink.shutdown()
        cls.sink.server_close()
        cls.sink_thread.join(timeout=2)

    def setUp(self):
        UpstreamHandler.mode = "valid"
        SinkHandler.hits = 0
        SinkHandler.authorization = None
        self.client = DistributionClient(self.base_url, "read-token-0123456789-abcdef-0123456789")

    def test_accepts_only_bounded_read_only_xdr_state(self):
        state = self.client.state()
        self.assertEqual(state["status"], "HEALTHY")
        self.assertTrue(state["read_only"])
        self.assertEqual(state["xdr"]["schema_version"], "1.9.0")
        self.assertEqual(state["responses"][0]["verification_outcome"], "QUARANTINED_VERIFIED")
        self.assertEqual(state["transport"], "RAILWAY_PRIVATE_AUTHENTICATED")

        UpstreamHandler.mode = "invalid-xdr"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})

        UpstreamHandler.mode = "invalid-class"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})

        UpstreamHandler.mode = "invalid-response"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})

        UpstreamHandler.mode = "invalid-endpoint"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})

    def test_redirect_is_not_followed_and_read_token_is_not_forwarded(self):
        UpstreamHandler.mode = "redirect"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})
        self.assertEqual(SinkHandler.hits, 0)
        self.assertIsNone(SinkHandler.authorization)

    def test_v2_read_model_is_tenant_scoped_and_rejects_false_online_data(self):
        UpstreamHandler.mode = "v2"
        client = DistributionClient(
            self.base_url,
            "read-token-0123456789-abcdef-0123456789",
            tenant_id="tenant-a",
        )
        state = client.state()
        self.assertEqual(state["tenant_id"], "tenant-a")
        self.assertEqual(state["summary"]["online"], 1)
        self.assertEqual(state["event_summary"][0]["event_type"], "DETECTION")
        self.assertEqual(state["responses"], [])

        UpstreamHandler.mode = "v2-cross-tenant"
        self.assertEqual(client.state(), {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})

        UpstreamHandler.mode = "v2-false-online"
        self.assertEqual(client.state(), {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})


if __name__ == "__main__":
    unittest.main()
