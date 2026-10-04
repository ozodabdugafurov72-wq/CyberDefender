from __future__ import annotations

import hashlib
import tempfile
import unittest
import uuid
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
)
from agent.risk_engine import RiskEngine
from agent.safety import SafetyCore


class QuarantineV2ServiceIntegrationTests(unittest.TestCase):
    def _coordinator(self, root: Path, vault_root: Path) -> LabQuarantineCoordinator:
        issuer = QuarantineCapabilityIssuer()
        vault = BoundedQuarantineVault(vault_root, max_records=8, max_bytes=2 * 1024 * 1024)
        executor = BoundedQuarantineExecutor(vault, issuer, approved_root=root)
        return LabQuarantineCoordinator(
            detector=Detector(RuleEngine()),
            correlation_engine=CorrelationEngine(),
            risk_engine=RiskEngine(),
            attack_graph=AttackGraph(),
            policy_engine=PolicyEngine(),
            independent_verifier=IndependentVerifier(),
            safety=SafetyCore(),
            issuer=issuer,
            executor=executor,
            approved_root=root,
        )

    def test_real_detection_chain_can_quarantine_one_harmless_canary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-QV2-service-") as temporary:
            base = Path(temporary)
            root = base / "canary-root"
            vault_root = base / "vault"
            root.mkdir()
            (root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
            target = root / "harmless-canary.txt"
            target.write_text("service-driven harmless canary\n", encoding="utf-8")
            expected_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            event_id = "telemetry-" + uuid.uuid4().hex
            coordinator = self._coordinator(root, vault_root)
            report = coordinator.run(
                {
                    "event_type": "HOST_SNAPSHOT",
                    "event_id": event_id,
                    "data": {
                        "memory_percent": 99.0,
                        "tenant_id": "lab-tenant",
                        "endpoint_id": "lab-endpoint-1",
                        "target": str(target),
                        "approved_root": str(root),
                        "execution_mode": LAB_CANARY_EXECUTION,
                        "lab_canary": True,
                        "requested_action": "QUARANTINE",
                        "evidence_ref": "evidence://" + event_id,
                    },
                },
                operator_approved=True,
            )
            self.assertEqual(report["status"], "VERIFIED_QUARANTINED")
            self.assertTrue(report["accepted"])
            self.assertFalse(target.exists())
            self.assertEqual(report["event_id"], event_id)
            self.assertEqual(report["endpoint_id"], "lab-endpoint-1")
            self.assertEqual(report["production_authorization"], "NOT_GRANTED")
            self.assertEqual(report["lab_authorization"], "QUARANTINE_CAPABILITY_CONSUMED")
            self.assertEqual(report["real_world_effect"], True)
            self.assertEqual(report["verification_outcome"], "QUARANTINED_VERIFIED")
            policy_item = report["policy_decision"]["assessments"][0]
            verification_item = report["independent_verification"]["assessments"][0]
            self.assertEqual(policy_item["requested_action"], "QUARANTINE")
            self.assertEqual(policy_item["policy_outcome"], "REQUIRE_VERIFICATION")
            self.assertEqual(policy_item["decision_digest"], report["decision_digest"])
            self.assertEqual(verification_item["requested_action"], "QUARANTINE")
            self.assertEqual(verification_item["decision_digest"], report["decision_digest"])
            self.assertEqual(report["pipeline_trace"][0:6], [
                "TELEMETRY", "DETECTION", "CORRELATION", "RISK", "POLICY", "INDEPENDENT_VERIFIER",
            ])
            self.assertEqual(report["pipeline_trace"][-2:], [
                "BOUNDED_QUARANTINE_EXECUTOR", "QUARANTINE_INDEPENDENT_VERIFIER",
            ])
            record = coordinator.executor.vault.get_verified_record(report["quarantine_id"])
            self.assertIsInstance(record, dict)
            self.assertTrue(coordinator.executor.vault.verify_object(record))
            self.assertTrue(coordinator.executor.vault.verify_receipt(report["quarantine_id"], record))
            self.assertTrue(coordinator.executor.vault.evidence_vault.verify_evidence(record["evidence_quarantine_id"]))
            self.assertEqual(record["target_sha256"], expected_hash)
            self.assertEqual(coordinator.issuer.consumed, 1)
            self.assertEqual(coordinator.issuer.replays, 0)
            self.assertNotIn("token_mac", str(report))
            self.assertNotIn("token_mac", str(record))

    def test_unmarked_or_outside_canary_events_never_reach_executor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-QV2-admission-") as temporary:
            base = Path(temporary)
            root = base / "canary-root"
            root.mkdir()
            (root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
            target = root / "harmless-canary.txt"
            target.write_text("safe\n", encoding="utf-8")
            coordinator = self._coordinator(root, base / "vault")
            event = {
                "event_type": "HOST_SNAPSHOT",
                "event_id": "unmarked-event",
                "data": {
                    "memory_percent": 99.0,
                    "target": str(target),
                    "approved_root": str(root),
                    "execution_mode": LAB_CANARY_EXECUTION,
                    "requested_action": "QUARANTINE",
                    "evidence_ref": "evidence://unmarked-event",
                },
            }
            report = coordinator.run(event, operator_approved=True)
            self.assertEqual(report["status"], "DENIED")
            self.assertEqual(report["reason"], "LAB_CANARY_MARKER_REQUIRED")
            self.assertTrue(target.exists())
            self.assertEqual(coordinator.issuer.issued, 0)

            outside = base / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            outside_event = dict(event)
            outside_event["event_id"] = "outside-event"
            outside_event["data"] = dict(event["data"], lab_canary=True, target=str(outside), evidence_ref="evidence://outside-event")
            outside_report = coordinator.run(outside_event, operator_approved=True)
            self.assertEqual(outside_report["status"], "DENIED")
            self.assertEqual(outside_report["reason"], "TARGET_OUTSIDE_APPROVED_ROOT")
            self.assertTrue(outside.exists())
            self.assertEqual(coordinator.issuer.issued, 0)


if __name__ == "__main__":
    unittest.main()
