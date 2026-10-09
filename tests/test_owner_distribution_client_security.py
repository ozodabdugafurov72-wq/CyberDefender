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
        },
        "endpoints": [],
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
        value = valid_state()
        if type(self).mode == "invalid-xdr":
            value["xdr"]["signed_ingest"] = False
        if type(self).mode == "invalid-class":
            value["xdr"]["event_classes"] = [{"class_uid": 2005}]
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
        self.assertEqual(state["transport"], "RAILWAY_PRIVATE_AUTHENTICATED")

        UpstreamHandler.mode = "invalid-xdr"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})

        UpstreamHandler.mode = "invalid-class"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})

    def test_redirect_is_not_followed_and_read_token_is_not_forwarded(self):
        UpstreamHandler.mode = "redirect"
        rejected = self.client.state()
        self.assertEqual(rejected, {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"})
        self.assertEqual(SinkHandler.hits, 0)
        self.assertIsNone(SinkHandler.authorization)


if __name__ == "__main__":
    unittest.main()
