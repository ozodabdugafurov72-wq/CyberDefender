from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
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
    QuarantineRequest,
)
from agent.risk_engine import RiskEngine
from agent.safety import SafetyCore
from dashboard_owner.quarantine_read_model import QuarantineReadModel


class _LabSafety:
    def health_snapshot(self) -> dict[str, object]:
        return {"safe_mode": False, "shutdown_requested": False}

    def authorize_lab_quarantine(self, scope: dict[str, str]) -> dict[str, object]:
        from agent.quarantine.contracts import canonical_scope_digest
        return {"allowed": True, "mode": LAB_CANARY_EXECUTION,
                "scope_digest": canonical_scope_digest(scope),
                "production_authorization": "NOT_GRANTED",
                "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED"}


class QuarantineDataFidelityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cd-data-fidelity-")
        self.base = Path(self.temp.name)
        self.root = self.base / "canary"
        self.root.mkdir()
        (self.root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
        self.previous_vaults = QuarantineReadModel.APPROVED_VAULTS

    def tearDown(self) -> None:
        QuarantineReadModel.APPROVED_VAULTS = self.previous_vaults
        self.temp.cleanup()

    def _coordinator(self, vault_root: Path) -> LabQuarantineCoordinator:
        issuer = QuarantineCapabilityIssuer()
        vault = BoundedQuarantineVault(vault_root, max_records=8, max_bytes=2 * 1024 * 1024)
        executor = BoundedQuarantineExecutor(vault, issuer, approved_root=self.root)
        return LabQuarantineCoordinator(
            detector=Detector(RuleEngine()), correlation_engine=CorrelationEngine(), risk_engine=RiskEngine(),
            attack_graph=AttackGraph(), policy_engine=PolicyEngine(), independent_verifier=IndependentVerifier(),
            safety=SafetyCore(), issuer=issuer, executor=executor, approved_root=self.root,
        )

    def _event(self, target: Path, *, endpoint: str | None = "endpoint-a", tenant: str | None = "tenant-a") -> dict[str, object]:
        return {"event_type": "HOST_SNAPSHOT", "event_id": "telemetry-fidelity-1", "data": {
            "memory_percent": 99.0, "endpoint_id": endpoint, "tenant_id": tenant,
            "target": str(target), "approved_root": str(self.root), "execution_mode": LAB_CANARY_EXECUTION,
            "lab_canary": True, "requested_action": "QUARANTINE", "evidence_ref": "evidence://telemetry-fidelity-1",
        }}

    def test_full_trusted_metadata_is_persisted_and_projected(self) -> None:
        target = self.root / "full.txt"
        target.write_text("full metadata\n", encoding="utf-8")
        coordinator = self._coordinator(self.base / "vault")
        report = coordinator.run(self._event(target), operator_approved=True)
        self.assertEqual(report["status"], "VERIFIED_QUARANTINED")
        record = coordinator.executor.vault.get_verified_record(report["quarantine_id"])
        self.assertEqual(record["event_id"], "telemetry-fidelity-1")
        self.assertEqual(record["endpoint_id"], "endpoint-a")
        self.assertEqual(record["tenant_id"], "tenant-a")
        self.assertEqual(record["detection_types"], ["HIGH_MEMORY_USAGE"])
        self.assertEqual(record["detection_count"], 1)
        self.assertEqual(record["risk_level"], "CRITICAL")
        self.assertEqual(record["risk_score"], 90)
        self.assertEqual(record["policy_outcome"], "REQUIRE_VERIFICATION")
        self.assertEqual(record["verifier_outcome"], "VERIFIED")
        self.assertNotIn("token_mac", json.dumps(record))
        QuarantineReadModel.APPROVED_VAULTS = (("test", self.base / "vault"),)
        item = QuarantineReadModel(self.base / "vault").snapshot(detail=True)["items"][0]
        self.assertEqual(item["event_id"], "telemetry-fidelity-1")
        self.assertEqual(item["detection_types"], ["HIGH_MEMORY_USAGE"])
        self.assertEqual(item["risk_level"], "CRITICAL")
        self.assertEqual(item["provenance"]["risk_level"], "record")

    def test_missing_endpoint_and_tenant_remain_unknown(self) -> None:
        target = self.root / "missing.txt"
        target.write_text("missing attribution\n", encoding="utf-8")
        coordinator = self._coordinator(self.base / "vault")
        report = coordinator.run(self._event(target, endpoint=None, tenant=None), operator_approved=True)
        self.assertEqual(report["status"], "VERIFIED_QUARANTINED")
        record = coordinator.executor.vault.get_verified_record(report["quarantine_id"])
        self.assertNotIn("endpoint_id", record)
        self.assertNotIn("tenant_id", record)
        QuarantineReadModel.APPROVED_VAULTS = (("test", self.base / "vault"),)
        snapshot = QuarantineReadModel(self.base / "vault").snapshot(detail=True)
        item = snapshot["items"][0]
        self.assertEqual(item["endpoint_id"], "UNKNOWN")
        self.assertEqual(item["tenant_id"], "UNKNOWN")
        self.assertEqual(snapshot["summary"]["affected_endpoints"], 0)
        self.assertEqual(snapshot["summary"]["affected_tenants"], 0)

    def test_multi_detection_metadata_and_critical_risk_are_preserved(self) -> None:
        target = self.root / "multi.txt"
        target.write_text("multi\n", encoding="utf-8")
        vault = BoundedQuarantineVault(self.base / "vault", max_records=8, max_bytes=2 * 1024 * 1024)
        issuer = QuarantineCapabilityIssuer()
        request = QuarantineRequest.from_mapping({
            "incident_id": "INC-MULTI", "idempotency_key": "multi-key", "target": str(target),
            "approved_root": str(self.root), "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "requester": "operator", "evidence_ref": "evidence://INC-MULTI",
            "decision_digest": hashlib.sha256(b"multi-decision").hexdigest(), "mode": LAB_CANARY_EXECUTION,
            "event_id": "event-multi", "endpoint_id": "endpoint-multi", "tenant_id": "tenant-multi",
            "detection_types": ["MASS_FILE_MODIFICATION", "RAPID_RENAME_BURST"], "detection_count": 7,
            "detection_confidence": 0.95, "risk_score": 97, "risk_level": "CRITICAL",
            "policy_outcome": "REQUIRE_VERIFICATION", "policy_reason": "MULTI_SIGNAL",
            "verifier_outcome": "VERIFIED",
        })
        row = {"incident_id": request.incident_id, "requested_action": "QUARANTINE", "decision_digest": request.decision_digest}
        policy = {"accepted": True, "policy_outcome": "REQUIRE_VERIFICATION", "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY", "assessments": [dict(row)]}
        verification = {"accepted": True, "verified": True, "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY", "assessments": [dict(row)]}
        capability = issuer.issue(request, policy_result=policy, verification_result=verification, safety=_LabSafety(), operator_approved=True)
        result = BoundedQuarantineExecutor(vault, issuer, approved_root=self.root).execute(request, capability)
        record = vault.get_verified_record(result["quarantine_id"])
        self.assertEqual(record["detection_types"], ["MASS_FILE_MODIFICATION", "RAPID_RENAME_BURST"])
        self.assertEqual(record["detection_count"], 7)
        self.assertEqual(record["risk_level"], "CRITICAL")
        self.assertEqual(record["risk_score"], 97)

    def test_conflicting_endpoint_and_tenant_attribution_fails_closed(self) -> None:
        target = self.root / "conflict.txt"
        target.write_text("conflict\n", encoding="utf-8")

        class ConflictCorrelation:
            def ingest(self, event: dict[str, object], *, strict: bool = False) -> dict[str, object]:
                return {"event_type": "INCIDENT", "incident_id": "INC-CONFLICT", "tenant_id": "tenant-other",
                        "event_count": 1, "detection_types": ["HIGH_MEMORY_USAGE"],
                        "detections": [{"type": "HIGH_MEMORY_USAGE", "tenant_id": "tenant-other", "host_id": "endpoint-other"}]}

        issuer = QuarantineCapabilityIssuer()
        vault = BoundedQuarantineVault(self.base / "vault", max_records=8, max_bytes=2 * 1024 * 1024)
        coordinator = LabQuarantineCoordinator(
            detector=Detector(RuleEngine()), correlation_engine=ConflictCorrelation(), risk_engine=RiskEngine(),
            attack_graph=AttackGraph(), policy_engine=PolicyEngine(), independent_verifier=IndependentVerifier(),
            safety=SafetyCore(), issuer=issuer, executor=BoundedQuarantineExecutor(vault, issuer, approved_root=self.root), approved_root=self.root,
        )
        result = coordinator.run(self._event(target), operator_approved=True)
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(result["reason"], "TENANT_ATTRIBUTION_CONFLICT")
        self.assertTrue(target.exists())

    def test_legacy_receipt_backfill_is_provenance_labelled_and_unrecoverable_stays_unknown(self) -> None:
        target = self.root / "legacy.txt"
        target.write_text("legacy\n", encoding="utf-8")
        coordinator = self._coordinator(self.base / "vault")
        report = coordinator.run(self._event(target), operator_approved=True)
        vault = coordinator.executor.vault
        path = vault.records_dir / f"{report['quarantine_id']}.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        for field in ("event_id", "endpoint_id", "tenant_id", "detection_types", "risk_score", "risk_level"):
            record.pop(field, None)
        unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
        record["record_sha256"] = hashlib.sha256(vault._canonical(unsigned)).hexdigest()
        path.write_text(vault._canonical(record).decode("utf-8"), encoding="utf-8")
        QuarantineReadModel.APPROVED_VAULTS = (("test", self.base / "vault"),)
        item = QuarantineReadModel(self.base / "vault").snapshot(detail=True)["items"][0]
        self.assertEqual(item["event_id"], "telemetry-fidelity-1")
        self.assertEqual(item["endpoint_id"], "endpoint-a")
        self.assertEqual(item["tenant_id"], "tenant-a")
        self.assertEqual(item["provenance"]["event_id"], "receipt")
        self.assertEqual(item["risk_level"], "CRITICAL")

        receipt_path = vault.receipts_dir / f"{report['quarantine_id']}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        for field in ("event_id", "endpoint_id", "tenant_id", "detection_types", "risk_score", "risk_level"):
            receipt.pop(field, None)
        receipt_unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        receipt["receipt_sha256"] = hashlib.sha256(vault._canonical(receipt_unsigned)).hexdigest()
        receipt_path.write_text(vault._canonical(receipt).decode("utf-8"), encoding="utf-8")
        item = QuarantineReadModel(self.base / "vault").snapshot(detail=True)["items"][0]
        self.assertEqual(item["event_id"], "UNKNOWN")
        self.assertEqual(item["endpoint_id"], "UNKNOWN")
        self.assertEqual(item["tenant_id"], "UNKNOWN")

    def test_integrity_metrics_and_no_secret_leakage(self) -> None:
        target = self.root / "integrity.txt"
        target.write_text("integrity\n", encoding="utf-8")
        coordinator = self._coordinator(self.base / "vault")
        report = coordinator.run(self._event(target), operator_approved=True)
        QuarantineReadModel.APPROVED_VAULTS = (("test", self.base / "vault"),)
        model = QuarantineReadModel(self.base / "vault")
        snapshot = model.snapshot(detail=True)
        self.assertEqual(snapshot["summary"]["evidence_verified"], 1)
        self.assertEqual(snapshot["summary"]["integrity_problems"], 0)
        receipt_path = coordinator.executor.vault.receipts_dir / f"{report['quarantine_id']}.json"
        receipt_path.write_text("{}", encoding="utf-8")
        damaged = model.snapshot(detail=True)
        self.assertGreaterEqual(damaged["summary"]["integrity_problems"], 1)
        self.assertNotIn("token_mac", json.dumps(damaged))


if __name__ == "__main__":
    unittest.main(verbosity=2)
