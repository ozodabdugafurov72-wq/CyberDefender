from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
import uuid
from dataclasses import replace
from pathlib import Path

from agent.attack_graph import AttackGraph
from agent.correlation.engine import CorrelationEngine
from agent.detection.detector import Detector
from agent.detection.rules import RuleEngine
from agent.independent_verifier import IndependentVerifier
from agent.policy_engine import PolicyEngine
from agent.quarantine import (
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
    LAB_CANARY_EXECUTION,
    LabQuarantineCoordinator,
    QuarantineCapabilityIssuer,
    RestoreCapabilityIssuer,
    RestoreRequest,
)
from agent.risk_engine import RiskEngine
from agent.safety import SafetyCore
from dashboard_owner.quarantine_read_model import QuarantineReadModel


class QuarantineRestoreAndLatencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cd-qv2-restore-")
        self.base = Path(self.temporary.name)
        self.root = self.base / "canary-root"
        self.root.mkdir()
        (self.root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
        self.vault = BoundedQuarantineVault(
            self.base / "vault", max_records=8, max_bytes=2 * 1024 * 1024
        )
        self.quarantine_issuer = QuarantineCapabilityIssuer()
        self.restore_issuer = RestoreCapabilityIssuer()
        self.executor = BoundedQuarantineExecutor(
            self.vault,
            self.quarantine_issuer,
            approved_root=self.root,
            restore_issuer=self.restore_issuer,
        )
        self.safety = SafetyCore()
        self.coordinator = LabQuarantineCoordinator(
            detector=Detector(RuleEngine()),
            correlation_engine=CorrelationEngine(),
            risk_engine=RiskEngine(),
            attack_graph=AttackGraph(),
            policy_engine=PolicyEngine(),
            independent_verifier=IndependentVerifier(),
            safety=self.safety,
            issuer=self.quarantine_issuer,
            executor=self.executor,
            approved_root=self.root,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _quarantine(self, name: str = "harmless-canary.txt") -> tuple[Path, bytes, dict[str, object]]:
        target = self.root / name
        raw = b"harmless bounded recovery canary\n"
        target.write_bytes(raw)
        event_id = "telemetry-" + uuid.uuid4().hex
        observed_at = time.time()
        result = self.coordinator.run(
            {
                "event_type": "HOST_SNAPSHOT",
                "event_id": event_id,
                "timestamp": observed_at,
                "data": {
                    "memory_percent": 99.0,
                    "tenant_id": "lab-tenant",
                    "endpoint_id": "lab-endpoint-1",
                    "target": str(target),
                    "approved_root": str(self.root),
                    "execution_mode": LAB_CANARY_EXECUTION,
                    "lab_canary": True,
                    "requested_action": "QUARANTINE",
                    "evidence_ref": "evidence://" + event_id,
                },
            },
            operator_approved=True,
        )
        self.assertEqual(result["status"], "VERIFIED_QUARANTINED")
        self.assertTrue(result["accepted"])
        self.assertTrue(result["latency_evidence_persisted"])
        self.assertIsInstance(result["response_latency_ms"], float)
        self.assertIsInstance(result["execution_latency_ms"], float)
        self.assertIsInstance(result["detection_to_response_ms"], float)
        self.assertFalse(target.exists())
        return target, raw, result

    def _restore_request(self, quarantine_id: str) -> tuple[RestoreRequest, dict[str, object]]:
        record = self.vault.get_verified_record(quarantine_id)
        self.assertIsInstance(record, dict)
        eligibility = self.executor.verifier.verify_restore_eligibility(quarantine_id)
        self.assertEqual(eligibility["verification_outcome"], "RESTORE_ELIGIBLE_VERIFIED")
        request = RestoreRequest.from_mapping({
            "quarantine_id": quarantine_id,
            "incident_id": record["incident_id"],
            "idempotency_key": f"{quarantine_id}:restore",
            "target": record["original_path"],
            "approved_root": record["approved_root"],
            "target_sha256": record["target_sha256"],
            "requester": "local-lab-operator",
            "restore_reason": "LAB_CANARY_RESET",
        })
        return request, eligibility

    def test_verified_quarantine_restore_and_owner_evidence(self) -> None:
        target, raw, quarantine = self._quarantine()
        quarantine_id = str(quarantine["quarantine_id"])
        request, eligibility = self._restore_request(quarantine_id)
        capability = self.restore_issuer.issue(
            request,
            eligibility_verification=eligibility,
            safety=self.safety,
            operator_approved=True,
        )
        result = self.executor.restore(request, capability)
        self.assertTrue(result["accepted"])
        self.assertTrue(result["executed"])
        self.assertEqual(result["status"], "RESTORED")
        self.assertEqual(target.read_bytes(), raw)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), request.target_sha256)
        self.assertEqual(result["verification"]["verification_outcome"], "RESTORED_VERIFIED")
        self.assertIsInstance(result["restore_latency_ms"], float)
        record = self.vault.get_verified_record(quarantine_id)
        self.assertEqual(record["state"], "RESTORED")
        self.assertTrue(record["post_restore_verification"])
        self.assertFalse(Path(record["object_path"]).exists())
        self.assertTrue(self.vault.verify_restore_receipt(quarantine_id, record))

        previous = QuarantineReadModel.APPROVED_VAULTS
        try:
            QuarantineReadModel.APPROVED_VAULTS = (("test", self.vault.root),)
            detail = QuarantineReadModel(self.vault.root).detail(quarantine_id)
        finally:
            QuarantineReadModel.APPROVED_VAULTS = previous
        self.assertIsInstance(detail, dict)
        self.assertEqual(detail["containment_state"], "RESTORED")
        self.assertEqual(detail["restore_verification_outcome"], "RESTORED_VERIFIED")
        self.assertTrue(detail["post_action_verification"])
        self.assertTrue(detail["restore_receipt_integrity"])
        self.assertIsInstance(detail["response_latency_ms"], float)
        self.assertIsInstance(detail["execution_latency_ms"], float)
        self.assertIsInstance(detail["detection_to_response_ms"], float)
        self.assertIsInstance(detail["restore_latency_ms"], float)

        replay = self.executor.restore(request, capability)
        self.assertFalse(replay["accepted"])
        self.assertEqual(replay["reason"], "RESTORE_DENIED")

    def test_restore_scope_and_destination_collision_fail_closed(self) -> None:
        target, raw, quarantine = self._quarantine("scope-canary.txt")
        quarantine_id = str(quarantine["quarantine_id"])
        request, eligibility = self._restore_request(quarantine_id)
        capability = self.restore_issuer.issue(
            request,
            eligibility_verification=eligibility,
            safety=self.safety,
            operator_approved=True,
        )
        wrong = replace(request, requester="different-operator")
        denied = self.executor.restore(wrong, capability)
        self.assertFalse(denied["accepted"])
        self.assertEqual(denied["reason"], "RESTORE_DENIED")
        self.assertFalse(target.exists())

        target.write_bytes(b"unrelated existing data")
        collision = self.executor.restore(request, capability)
        self.assertFalse(collision["accepted"])
        self.assertEqual(collision["reason"], "RESTORE_DESTINATION_EXISTS")
        self.assertEqual(target.read_bytes(), b"unrelated existing data")
        record = self.vault.get_verified_record(quarantine_id)
        self.assertEqual(record["state"], "QUARANTINED")
        self.assertTrue(self.vault.verify_object(record))
        self.assertNotEqual(target.read_bytes(), raw)

    def test_vault_pre_effect_restore_failure_preserves_quarantine_truth(self) -> None:
        target, _raw, quarantine = self._quarantine("pre-effect-canary.txt")
        quarantine_id = str(quarantine["quarantine_id"])
        record = self.vault.get_verified_record(quarantine_id)
        self.assertIsInstance(record, dict)
        target.write_bytes(b"destination collision")

        result = self.vault.restore(
            record,
            target,
            capability_id="restore-capability-test",
            scope_digest="d" * 64,
            requester="local-lab-operator",
            restore_reason="LAB_CANARY_RESET",
        )

        self.assertEqual(result["state"], "QUARANTINED")
        self.assertEqual(result["last_restore_failure_code"], "RESTORE_FAILED")
        self.assertFalse(result["recovery_required"])
        self.assertTrue(self.vault.verify_object(result))
        self.assertEqual(target.read_bytes(), b"destination collision")

    def test_restore_receipt_tamper_is_detected(self) -> None:
        _target, _raw, quarantine = self._quarantine("receipt-tamper-canary.txt")
        quarantine_id = str(quarantine["quarantine_id"])
        request, eligibility = self._restore_request(quarantine_id)
        capability = self.restore_issuer.issue(
            request,
            eligibility_verification=eligibility,
            safety=self.safety,
            operator_approved=True,
        )
        result = self.executor.restore(request, capability)
        self.assertEqual(result["status"], "RESTORED")
        record = self.vault.get_verified_record(quarantine_id)
        receipt_path = self.vault.restore_receipts_dir / f"{quarantine_id}.json"
        receipt_path.write_text('{"tampered":true}', encoding="utf-8")

        self.assertFalse(self.vault.verify_restore_receipt(quarantine_id, record))
        previous = QuarantineReadModel.APPROVED_VAULTS
        try:
            QuarantineReadModel.APPROVED_VAULTS = (("test", self.vault.root),)
            detail = QuarantineReadModel(self.vault.root).detail(quarantine_id)
        finally:
            QuarantineReadModel.APPROVED_VAULTS = previous
        self.assertIsInstance(detail, dict)
        self.assertFalse(detail["restore_receipt_integrity"])
        self.assertTrue(detail["integrity_problem"])


if __name__ == "__main__":
    unittest.main()
