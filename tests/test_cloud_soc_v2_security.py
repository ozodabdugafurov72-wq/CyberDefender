from __future__ import annotations

import base64
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from control_plane.cloud_soc_v2 import (
    CloudSocError,
    CloudSocRepository,
    CloudSocService,
    signature_headers,
)


def public_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def encoded(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CloudSocV2SecurityTests(unittest.TestCase):
    def setUp(self):
        root = Path(".test-tmp").resolve()
        root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="cd-cloud-soc-v2-", dir=root)
        self.db = Path(self.temp.name) / "soc.db"
        self.now = [1_900_000_000.0]
        self.repo = CloudSocRepository(self.db)
        self.service = CloudSocService(self.repo, clock=lambda: self.now[0])
        self.key_a = Ed25519PrivateKey.generate()
        self.enrolled_a = self.enroll("tenant-a", self.key_a)

    def tearDown(self):
        self.repo.close()
        self.temp.cleanup()

    def enroll(self, tenant: str, key: Ed25519PrivateKey) -> dict:
        code = self.repo.issue_enrollment_code(tenant, now=self.now[0])
        request = {
            "schema": "cyberdefender.enrollment.v2",
            "one_time_code": code,
            "agent_instance_id": str(uuid.uuid4()),
            "device_public_key": public_text(key),
            "hostname": "endpoint.example",
            "runtime_version": "2.4",
            "capabilities": ["endpoint-health", "event-batches"],
        }
        result = self.repo.enroll(request, now=self.now[0])
        result["code"] = code
        result["request"] = request
        return result

    def heartbeat(self, enrollment: dict, key: Ed25519PrivateKey, sequence: int,
                  *, heartbeat_id: str | None = None, health: str = "HEALTHY"):
        endpoint_id = enrollment["endpoint_id"]
        path = f"/api/v2/endpoints/{endpoint_id}/heartbeat"
        payload = {
            "schema": "cyberdefender.heartbeat.v2",
            "heartbeat_id": heartbeat_id or f"heartbeat-{sequence}",
            "endpoint_id": endpoint_id,
            "boot_id": "11111111-1111-4111-8111-111111111111",
            "seq": sequence,
            "observed_at": self.now[0],
            "health_state": health,
            "service_state": "RUNNING",
            "resource_state": "NORMAL",
            "runtime_version": "2.4",
            "component_failures": 0,
            "cycle": sequence,
            "cpu_percent": 12.5,
            "memory_percent": 42.0,
            "spool": {"pending": 0, "bytes": 0, "status": "HEALTHY"},
        }
        raw = encoded(payload)
        headers = signature_headers(
            key,
            credential_id=enrollment["credential_id"],
            path=path,
            body=raw,
            sequence=sequence,
            timestamp=int(self.now[0]),
        )
        return self.service.ingest_heartbeat(endpoint_id, raw, headers), raw, headers

    def test_one_time_enrollment_and_no_private_key_return(self):
        self.assertEqual(self.enrolled_a["tenant_id"], "tenant-a")
        self.assertFalse(self.enrolled_a["private_key_returned"])
        with self.assertRaisesRegex(CloudSocError, "ENROLLMENT_CODE_REJECTED"):
            self.repo.enroll(self.enrolled_a["request"], now=self.now[0])

    def test_valid_heartbeat_replay_duplicate_and_stale_controls(self):
        ack, raw, headers = self.heartbeat(self.enrolled_a, self.key_a, 1)
        self.assertEqual((ack["status"], ack["accepted_through"]), ("ACK", 1))

        with self.assertRaisesRegex(CloudSocError, "REPLAY_DETECTED"):
            self.service.ingest_heartbeat(self.enrolled_a["endpoint_id"], raw, headers)

        path = f"/api/v2/endpoints/{self.enrolled_a['endpoint_id']}/heartbeat"
        retry = signature_headers(
            self.key_a,
            credential_id=self.enrolled_a["credential_id"],
            path=path,
            body=raw,
            sequence=1,
            timestamp=int(self.now[0]),
        )
        duplicate = self.service.ingest_heartbeat(self.enrolled_a["endpoint_id"], raw, retry)
        self.assertEqual(duplicate, {"status": "DUPLICATE_ACK", "accepted_through": 1})

        stale = signature_headers(
            self.key_a,
            credential_id=self.enrolled_a["credential_id"],
            path=path,
            body=raw,
            sequence=1,
            timestamp=int(self.now[0] - 301),
        )
        with self.assertRaisesRegex(CloudSocError, "STALE_REQUEST"):
            self.service.ingest_heartbeat(self.enrolled_a["endpoint_id"], raw, stale)

    def test_invalid_signature_and_cross_endpoint_binding_are_denied(self):
        raw_result, raw, _ = self.heartbeat(self.enrolled_a, self.key_a, 1)
        self.assertEqual(raw_result["status"], "ACK")
        other_key = Ed25519PrivateKey.generate()
        other = self.enroll("tenant-b", other_key)

        path_a = f"/api/v2/endpoints/{self.enrolled_a['endpoint_id']}/heartbeat"
        forged = signature_headers(
            other_key,
            credential_id=self.enrolled_a["credential_id"],
            path=path_a,
            body=raw,
            sequence=1,
            timestamp=int(self.now[0]),
        )
        with self.assertRaisesRegex(CloudSocError, "SIGNATURE_INVALID"):
            self.service.ingest_heartbeat(self.enrolled_a["endpoint_id"], raw, forged)

        payload = json.loads(raw)
        payload["endpoint_id"] = other["endpoint_id"]
        payload["heartbeat_id"] = "cross-tenant"
        payload["seq"] = 2
        cross_raw = encoded(payload)
        cross_path = f"/api/v2/endpoints/{other['endpoint_id']}/heartbeat"
        cross_headers = signature_headers(
            self.key_a,
            credential_id=self.enrolled_a["credential_id"],
            path=cross_path,
            body=cross_raw,
            sequence=2,
            timestamp=int(self.now[0]),
        )
        with self.assertRaisesRegex(CloudSocError, "ENDPOINT_BINDING_MISMATCH"):
            self.service.ingest_heartbeat(other["endpoint_id"], cross_raw, cross_headers)

    def test_event_batch_is_bounded_ordered_durable_and_tenant_scoped(self):
        self.heartbeat(self.enrolled_a, self.key_a, 1)
        endpoint_id = self.enrolled_a["endpoint_id"]
        path = f"/api/v2/endpoints/{endpoint_id}/event-batches"
        batch = {
            "schema": "cyberdefender.event-batch.v2",
            "batch_id": "batch-2-3",
            "endpoint_id": endpoint_id,
            "boot_id": "11111111-1111-4111-8111-111111111111",
            "first_seq": 2,
            "last_seq": 3,
            "events": [
                {"event_id": "event-2", "seq": 2, "observed_at": self.now[0],
                 "type": "DETECTION", "priority": "HIGH", "payload": {"rule": "canary"}},
                {"event_id": "event-3", "seq": 3, "observed_at": self.now[0],
                 "type": "INCIDENT", "priority": "CRITICAL", "payload": {"risk": 90}},
            ],
        }
        raw = encoded(batch)
        headers = signature_headers(self.key_a, credential_id=self.enrolled_a["credential_id"],
                                    path=path, body=raw, sequence=3, timestamp=int(self.now[0]))
        ack = self.service.ingest_events(endpoint_id, raw, headers)
        self.assertEqual(ack["accepted_through"], 3)
        tenant_a = self.repo.tenant_snapshot("tenant-a", now=self.now[0])
        tenant_b = self.repo.tenant_snapshot("tenant-b", now=self.now[0])
        self.assertEqual(tenant_a["summary"]["online"], 1)
        self.assertEqual(sum(row["count"] for row in tenant_a["event_summary"]), 2)
        self.assertEqual(tenant_b["summary"]["total"], 0)
        self.assertEqual(tenant_b["event_summary"], [])

        self.repo.close()
        self.repo = CloudSocRepository(self.db)
        self.service = CloudSocService(self.repo, clock=lambda: self.now[0])
        reopened = self.repo.tenant_snapshot("tenant-a", now=self.now[0])
        self.assertEqual(reopened["summary"]["online"], 1)
        self.assertEqual(sum(row["count"] for row in reopened["event_summary"]), 2)

    def test_evicted_local_ack_replay_is_idempotent_by_event_id(self):
        self.heartbeat(self.enrolled_a, self.key_a, 1)
        endpoint_id = self.enrolled_a["endpoint_id"]
        path = f"/api/v2/endpoints/{endpoint_id}/event-batches"

        def send(sequence: int, batch_id: str, payload: dict) -> dict:
            batch = {
                "schema": "cyberdefender.event-batch.v2",
                "batch_id": batch_id,
                "endpoint_id": endpoint_id,
                "boot_id": "11111111-1111-4111-8111-111111111111",
                "first_seq": sequence,
                "last_seq": sequence,
                "events": [
                    {
                        "event_id": "stable-event-id",
                        "seq": sequence,
                        "observed_at": self.now[0],
                        "type": "DETECTION",
                        "priority": "HIGH",
                        "payload": payload,
                    }
                ],
            }
            raw = encoded(batch)
            headers = signature_headers(
                self.key_a,
                credential_id=self.enrolled_a["credential_id"],
                path=path,
                body=raw,
                sequence=sequence,
                timestamp=int(self.now[0]),
            )
            return self.service.ingest_events(endpoint_id, raw, headers)

        self.assertEqual("ACK", send(2, "batch-original", {"rule": "canary"})["status"])
        duplicate = send(3, "batch-replay", {"rule": "canary"})

        self.assertEqual(
            {"status": "DUPLICATE_ACK", "accepted_through": 3, "duplicates": 1},
            duplicate,
        )
        rows = self.repo._conn.execute(
            "SELECT event_id FROM cloud_events WHERE tenant_id=? AND endpoint_id=?",
            ("tenant-a", endpoint_id),
        ).fetchall()
        self.assertEqual(["stable-event-id"], [row["event_id"] for row in rows])
        conflict_batch = {
            "schema": "cyberdefender.event-batch.v2",
            "batch_id": "batch-conflict-and-new",
            "endpoint_id": endpoint_id,
            "boot_id": "11111111-1111-4111-8111-111111111111",
            "first_seq": 4,
            "last_seq": 5,
            "events": [
                {
                    "event_id": "stable-event-id",
                    "seq": 4,
                    "observed_at": self.now[0],
                    "type": "DETECTION",
                    "priority": "HIGH",
                    "payload": {"rule": "changed"},
                },
                {
                    "event_id": "new-event-id",
                    "seq": 5,
                    "observed_at": self.now[0],
                    "type": "INCIDENT",
                    "priority": "CRITICAL",
                    "payload": {"risk": 80},
                },
            ],
        }
        conflict_raw = encoded(conflict_batch)
        conflict_headers = signature_headers(
            self.key_a,
            credential_id=self.enrolled_a["credential_id"],
            path=path,
            body=conflict_raw,
            sequence=5,
            timestamp=int(self.now[0]),
        )
        mixed = self.service.ingest_events(endpoint_id, conflict_raw, conflict_headers)
        self.assertEqual(
            {
                "status": "ACK_WITH_REJECTIONS",
                "accepted_through": 5,
                "duplicates": 0,
                "rejected": [{"seq": 4, "code": "EVENT_ID_CONFLICT"}],
            },
            mixed,
        )
        rows = self.repo._conn.execute(
            "SELECT event_id FROM cloud_events WHERE tenant_id=? AND endpoint_id=? ORDER BY event_id",
            ("tenant-a", endpoint_id),
        ).fetchall()
        self.assertEqual(["new-event-id", "stable-event-id"], [row["event_id"] for row in rows])
        endpoint = self.repo._conn.execute(
            "SELECT last_sequence FROM cloud_endpoints WHERE tenant_id=? AND endpoint_id=?",
            ("tenant-a", endpoint_id),
        ).fetchone()
        self.assertEqual(5, endpoint["last_sequence"])

    def test_stale_heartbeat_cannot_report_online(self):
        self.heartbeat(self.enrolled_a, self.key_a, 1)
        self.assertEqual(self.repo.tenant_snapshot("tenant-a", now=self.now[0])["summary"]["online"], 1)
        stale = self.repo.tenant_snapshot("tenant-a", now=self.now[0] + 91)
        self.assertEqual(stale["summary"]["online"], 0)
        self.assertEqual(stale["endpoints"][0]["health_state"], "OFFLINE")
        self.assertIsNone(stale["endpoints"][0]["cpu_percent"])

    def test_rotation_overlap_and_revocation(self):
        self.heartbeat(self.enrolled_a, self.key_a, 1)
        key_new = Ed25519PrivateKey.generate()
        rotated = self.repo.rotate_credential(
            tenant_id="tenant-a",
            endpoint_id=self.enrolled_a["endpoint_id"],
            current_credential_id=self.enrolled_a["credential_id"],
            new_public_key=public_text(key_new),
            now=self.now[0],
            overlap_seconds=60,
        )
        updated = dict(self.enrolled_a, credential_id=rotated["credential_id"])
        self.heartbeat(updated, key_new, 2)
        self.now[0] += 61
        with self.assertRaisesRegex(CloudSocError, "CREDENTIAL_REJECTED"):
            self.heartbeat(self.enrolled_a, self.key_a, 3)
        self.repo.revoke_endpoint("tenant-a", self.enrolled_a["endpoint_id"], now=self.now[0])
        with self.assertRaisesRegex(CloudSocError, "CREDENTIAL_REJECTED"):
            self.heartbeat(updated, key_new, 3)

    def test_duplicate_nonce_window_is_bounded_and_secret_fields_fail_closed(self):
        _, raw, _ = self.heartbeat(self.enrolled_a, self.key_a, 1)
        path = f"/api/v2/endpoints/{self.enrolled_a['endpoint_id']}/heartbeat"
        with patch("control_plane.cloud_soc_v2.MAX_NONCES_PER_ENDPOINT", 2):
            duplicate = signature_headers(self.key_a, credential_id=self.enrolled_a["credential_id"],
                                          path=path, body=raw, sequence=1,
                                          timestamp=int(self.now[0]), nonce="1" * 32)
            self.assertEqual(self.service.ingest_heartbeat(self.enrolled_a["endpoint_id"], raw, duplicate)["status"],
                             "DUPLICATE_ACK")
            saturated = signature_headers(self.key_a, credential_id=self.enrolled_a["credential_id"],
                                          path=path, body=raw, sequence=1,
                                          timestamp=int(self.now[0]), nonce="2" * 32)
            with self.assertRaisesRegex(CloudSocError, "NONCE_WINDOW_SATURATED"):
                self.service.ingest_heartbeat(self.enrolled_a["endpoint_id"], raw, saturated)
        count = self.repo._conn.execute("SELECT COUNT(*) FROM cloud_request_nonces").fetchone()[0]
        self.assertEqual(count, 2)

        endpoint_id = self.enrolled_a["endpoint_id"]
        event_path = f"/api/v2/endpoints/{endpoint_id}/event-batches"
        batch = {"schema": "cyberdefender.event-batch.v2", "batch_id": "secret-batch",
                 "endpoint_id": endpoint_id, "boot_id": "11111111-1111-4111-8111-111111111111",
                 "first_seq": 2, "last_seq": 2,
                 "events": [{"event_id": "secret-event", "seq": 2, "observed_at": self.now[0],
                             "type": "AUDIT", "priority": "HIGH",
                             "payload": {"accessToken": "must-never-persist"}}]}
        event_raw = encoded(batch)
        event_headers = signature_headers(self.key_a, credential_id=self.enrolled_a["credential_id"],
                                          path=event_path, body=event_raw, sequence=2,
                                          timestamp=int(self.now[0]))
        with self.assertRaisesRegex(CloudSocError, "EVENT_FIELD_INVALID"):
            self.service.ingest_events(endpoint_id, event_raw, event_headers)
        stored = " ".join(row[0] for row in self.repo._conn.execute(
            "SELECT payload_json FROM cloud_ingest_records").fetchall())
        self.assertNotIn("must-never-persist", stored)


if __name__ == "__main__":
    unittest.main()
