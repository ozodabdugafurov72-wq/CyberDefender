from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.quarantine import (
    AutonomousQuarantinePipeline,
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    PRODUCTION_AUTONOMOUS_EXECUTION,
    ProductionCapabilityIssuer,
    QuarantineContractError,
    QuarantineRequest,
)
from agent.service_runner import ServiceRunner
from control_plane.xdr_compat import validate_response_evidence


class ProductionQuarantineGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cd-production-quarantine-")
        self.addCleanup(self.temp.cleanup)
        self.clock = [2_000_000_000.0]
        self.root = Path(self.temp.name) / "approved"
        self.root.mkdir()
        self.target = self.root / "harmless-suspicious.exe"
        self.target.write_bytes(b"MZ harmless production pipeline fixture")
        self.private_key = Ed25519PrivateKey.generate()
        self.issuer = ProductionCapabilityIssuer(
            self.private_key.public_key().public_bytes_raw(), clock=lambda: self.clock[0]
        )
        self.vault = BoundedQuarantineVault(
            Path(self.temp.name) / "vault", max_records=8, max_bytes=1024 * 1024,
            max_target_bytes=64 * 1024,
        )
        self.executor = BoundedQuarantineExecutor(
            self.vault, self.issuer, approved_root=self.root,
            mode=PRODUCTION_AUTONOMOUS_EXECUTION,
        )

    def signed_policy(self, **updates) -> dict:
        payload = {
            "schema": "cd.production-quarantine-policy.v1",
            "policy_id": "prod-policy-2026-10",
            "issued_at": self.clock[0] - 60,
            "expires_at": self.clock[0] + 3600,
            "allowed_roots": [str(self.root)],
            "endpoint_ids": ["endpoint-prod-001"],
            "min_risk_score": 90,
            "min_detection_count": 2,
            "min_detection_confidence": 0.95,
            "allow_executable_targets": True,
        }
        payload.update(updates)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return {
            "payload": payload,
            "signature": base64.b64encode(self.private_key.sign(canonical)).decode("ascii"),
        }

    def request(self, **updates) -> QuarantineRequest:
        value = {
            "incident_id": "INC-PROD-001",
            "idempotency_key": "prod-idem-001",
            "target": str(self.target),
            "approved_root": str(self.root),
            "target_sha256": hashlib.sha256(self.target.read_bytes()).hexdigest(),
            "requester": "trusted-runtime",
            "evidence_ref": "evidence://INC-PROD-001",
            "decision_digest": hashlib.sha256(b"prod-decision").hexdigest(),
            "mode": PRODUCTION_AUTONOMOUS_EXECUTION,
            "event_id": "event-prod-001",
            "endpoint_id": "endpoint-prod-001",
            "detection_types": ["KNOWN_MALICIOUS_HASH", "SUSPICIOUS_PROCESS_CHAIN"],
            "detection_count": 2,
            "detection_confidence": 0.99,
            "risk_score": 98,
            "risk_level": "CRITICAL",
            "policy_outcome": "AUTHORIZED_AUTONOMOUS_QUARANTINE",
            "policy_reason": "two independent high-confidence detections",
            "verifier_outcome": "VERIFIED",
        }
        value.update(updates)
        return QuarantineRequest.from_mapping(value)

    @staticmethod
    def admitted_health(**updates) -> dict:
        value = {
            "runtime_health_admitted": True,
            "healthy_cycle_streak": 3,
            "component_failures": 0,
            "resource_state": "NORMAL",
        }
        value.update(updates)
        return value

    def test_signed_policy_and_health_gate_authorize_one_encrypted_executable_containment(self) -> None:
        request = self.request()
        capability = self.issuer.issue(
            request, signed_policy=self.signed_policy(), runtime_health=self.admitted_health()
        )
        result = self.executor.execute(request, capability)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["production_authorization"], "SIGNED_POLICY_CAPABILITY_CONSUMED")
        self.assertEqual(result["lab_authorization"], "NOT_APPLICABLE")
        self.assertFalse(self.target.exists())
        record = self.vault.get_verified_record(result["quarantine_id"])
        self.assertEqual(record["authorization_policy_id"], "prod-policy-2026-10")
        self.assertTrue(self.vault.verify_object(record))
        with self.assertRaises(QuarantineContractError):
            self.issuer.consume(capability, request)

    def test_bad_signature_expiry_low_confidence_and_unhealthy_runtime_fail_closed(self) -> None:
        request = self.request()
        tampered = self.signed_policy()
        tampered["payload"]["min_risk_score"] = 80
        cases = (
            (tampered, self.admitted_health(), request),
            (self.signed_policy(expires_at=self.clock[0] - 1), self.admitted_health(), request),
            (self.signed_policy(), self.admitted_health(), self.request(detection_confidence=0.5)),
            (self.signed_policy(), self.admitted_health(), self.request(endpoint_id="other-endpoint")),
            (self.signed_policy(), self.admitted_health(component_failures=1), request),
        )
        for policy, health, candidate in cases:
            with self.subTest(policy=policy["payload"], health=health), self.assertRaises(QuarantineContractError):
                self.issuer.issue(candidate, signed_policy=policy, runtime_health=health)
        self.assertTrue(self.target.exists())

    def test_pipeline_emits_cloud_valid_policy_attributed_evidence(self) -> None:
        request = self.request()
        result = AutonomousQuarantinePipeline(self.issuer, self.executor).handle(
            request,
            signed_policy=self.signed_policy(),
            runtime_health=self.admitted_health(),
        )
        self.assertEqual(result["status"], "VERIFIED_QUARANTINED")
        runtime = type("Runtime", (), {"last_quarantine_result": result})()
        evidence = ServiceRunner._response_evidence(runtime)
        normalized = validate_response_evidence(evidence, endpoint_id="endpoint-prod-001")
        self.assertEqual(
            normalized["production_authorization"], "SIGNED_POLICY_CAPABILITY_CONSUMED"
        )
        self.assertEqual(normalized["authorization_policy_id"], "prod-policy-2026-10")


if __name__ == "__main__":
    unittest.main()
