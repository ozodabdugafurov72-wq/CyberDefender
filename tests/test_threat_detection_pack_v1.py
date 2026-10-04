from __future__ import annotations

import hashlib
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
)
from agent.risk_engine import RiskEngine
from agent.safety import SafetyCore
from scripts.simulate_ransomware_behavior_v1 import simulate_ransomware_behavior


def _activity(event_id: str, timestamp: float, data: dict) -> dict:
    return {"event_type": "FILE_ACTIVITY", "event_id": event_id, "timestamp": timestamp, "data": data}


class ThreatDetectionPackTests(unittest.TestCase):
    def test_positive_ransomware_behavior_detection(self) -> None:
        detections: list[dict] = []
        engine = RuleEngine()
        simulate_ransomware_behavior(lambda event: detections.extend(engine.analyze_event(event)))
        kinds = {item["type"] for item in detections}
        self.assertIn("MASS_FILE_MODIFICATION", kinds)
        self.assertIn("RAPID_RENAME_BURST", kinds)
        self.assertIn("RANSOM_NOTE_LIKE_FILE", kinds)
        self.assertIn("RANSOMWARE_BEHAVIOR", kinds)
        self.assertTrue(all(item.get("signal_category") for item in detections))
        self.assertTrue(all(item.get("evidence") for item in detections))

    def test_ordinary_file_activity_negative_control(self) -> None:
        engine = RuleEngine()
        detections: list[dict] = []
        for index in range(3):
            detections.extend(engine.analyze_event(_activity(
                f"ordinary-{index}", 1000.0 + index,
                {"operation": "WRITE", "path": f"C:/lab/ordinary-{index}.txt", "host_id": "ordinary-host"},
            )))
        self.assertEqual([], detections)

    def test_suspicious_process_chain_positive(self) -> None:
        detections = Detector(RuleEngine()).handle_event({
            "event_type": "PROCESS_START", "event_id": "proc-positive", "timestamp": 1000.0,
            "data": {"process_name": "powershell.exe", "parent_process_name": "winword.exe", "command_line": "powershell -enc AAA", "host_id": "host-a"},
        })
        self.assertIn("SUSPICIOUS_PROCESS_CHAIN", {item["type"] for item in detections})

    def test_benign_process_negative_control(self) -> None:
        detections = Detector(RuleEngine()).handle_event({
            "event_type": "PROCESS_START", "event_id": "proc-benign", "timestamp": 1000.0,
            "data": {"process_name": "notepad.exe", "parent_process_name": "explorer.exe", "command_line": "notepad.exe", "host_id": "host-a"},
        })
        self.assertEqual([], detections)

    def test_script_abuse_signal(self) -> None:
        detections = Detector(RuleEngine()).handle_event({
            "event_type": "SCRIPT_ACTIVITY", "event_id": "script-positive", "timestamp": 1000.0,
            "data": {"interpreter": "powershell.exe", "command_line": "powershell -nop -w hidden -enc AAA", "host_id": "host-a"},
        })
        self.assertIn("SCRIPT_ABUSE_INDICATOR", {item["type"] for item in detections})
        self.assertNotIn("RANSOMWARE_BEHAVIOR", {item["type"] for item in detections})

    def test_explicit_lab_ioc_hash_indicator(self) -> None:
        indicator = hashlib.sha256(b"harmless lab IOC fixture").hexdigest()
        detector = Detector(RuleEngine({"threat_detection": {"lab_ioc_hashes": [indicator]}}))
        detections = detector.handle_event({
            "event_type": "FILE_INDICATOR", "event_id": "ioc-positive", "timestamp": 1000.0,
            "data": {"indicator_type": "SHA256", "indicator": indicator, "scope": "LAB", "host_id": "host-a"},
        })
        self.assertIn("EXPLICIT_LAB_IOC_MATCH", {item["type"] for item in detections})
        unconfigured = Detector(RuleEngine()).handle_event({
            "event_type": "FILE_INDICATOR", "event_id": "ioc-negative", "timestamp": 1000.0,
            "data": {"indicator_type": "SHA256", "indicator": indicator, "scope": "LAB", "host_id": "host-a"},
        })
        self.assertEqual([], unconfigured)

    def test_combined_signals_produce_high_or_critical_risk(self) -> None:
        engine = RuleEngine()
        correlation = CorrelationEngine(window_seconds=60)
        detections: list[dict] = []
        for index in range(8):
            detections.extend(engine.analyze_event(_activity(
                f"mass-{index}", 1000.0 + index * 0.1,
                {"operation": "WRITE", "path": f"C:/lab/data-{index}.txt", "host_id": "host-risk", "tenant_id": "tenant-risk"},
            )))
        for index in range(4):
            detections.extend(engine.analyze_event(_activity(
                f"rename-{index}", 1002.0 + index * 0.1,
                {"operation": "RENAME", "old_path": f"C:/lab/data-{index}.txt", "new_path": f"C:/lab/data-{index}.locked", "path": f"C:/lab/data-{index}.locked", "host_id": "host-risk", "tenant_id": "tenant-risk"},
            )))
        detections.extend(engine.analyze_event(_activity(
            "note-risk", 1004.0,
            {"operation": "CREATE", "path": "C:/lab/RECOVER_FILES.txt", "host_id": "host-risk", "tenant_id": "tenant-risk"},
        )))
        self.assertIn("RANSOMWARE_BEHAVIOR", {item["type"] for item in detections})
        for index, detection in enumerate(detections):
            correlation.ingest({"event_type": "DETECTION", "event_id": f"det-{index}", "timestamp": detection["timestamp"], "data": detection}, strict=True)
        risk = RiskEngine().assess(AttackGraph(), correlation.get_recent_incidents(limit=10))
        self.assertEqual("CRITICAL", risk["assessments"][0]["risk_level"])
        self.assertGreaterEqual(risk["assessments"][0]["risk_score"], 80)

    def test_simulator_detection_correlation_risk_chain(self) -> None:
        engine = RuleEngine()
        correlation = CorrelationEngine(window_seconds=60)
        emitted = []
        def consume(event: dict) -> None:
            for index, detection in enumerate(Detector(engine).handle_event(event)):
                emitted.append(detection)
                correlation.ingest({"event_type": "DETECTION", "event_id": f"sim-detection-{len(emitted)}-{index}", "timestamp": detection["timestamp"], "data": detection}, strict=True)
        simulate_ransomware_behavior(consume)
        risk = RiskEngine().assess(AttackGraph(), correlation.get_recent_incidents(limit=10))
        self.assertTrue(emitted)
        self.assertTrue(any(item["type"] == "RANSOMWARE_BEHAVIOR" for item in emitted))
        self.assertTrue(risk["assessments"])
        self.assertIn(risk["assessments"][0]["risk_level"], {"HIGH", "CRITICAL"})

    def _coordinator(self, root: Path, vault_root: Path) -> LabQuarantineCoordinator:
        issuer = QuarantineCapabilityIssuer()
        vault = BoundedQuarantineVault(vault_root, max_records=8, max_bytes=2 * 1024 * 1024)
        executor = BoundedQuarantineExecutor(vault, issuer, approved_root=root)
        return LabQuarantineCoordinator(
            detector=Detector(RuleEngine()), correlation_engine=CorrelationEngine(), risk_engine=RiskEngine(),
            attack_graph=AttackGraph(), policy_engine=PolicyEngine(), independent_verifier=IndependentVerifier(),
            safety=SafetyCore(), issuer=issuer, executor=executor, approved_root=root,
        )

    def test_lab_canary_can_proceed_only_after_threat_event_admission(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-threat-canary-") as directory:
            base = Path(directory)
            root = base / "canary-root"
            root.mkdir()
            (root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
            target = root / "recover_canary.txt"
            target.write_text("harmless canary\n", encoding="utf-8")
            event_id = "threat-canary"
            result = self._coordinator(root, base / "vault").run({
                "event_type": "FILE_ACTIVITY", "event_id": event_id, "timestamp": 1000.0,
                "data": {
                    "operation": "CREATE", "path": str(target), "target": str(target),
                    "approved_root": str(root), "lab_canary": True, "execution_mode": LAB_CANARY_EXECUTION,
                    "requested_action": "QUARANTINE", "evidence_ref": "evidence://" + event_id,
                    "endpoint_id": "lab-endpoint", "tenant_id": "lab-tenant",
                },
            }, operator_approved=True)
            self.assertEqual("VERIFIED_QUARANTINED", result["status"])
            self.assertFalse(target.exists())
            self.assertEqual("NOT_GRANTED", result["production_authorization"])
            self.assertEqual("QUARANTINE_CAPABILITY_CONSUMED", result["lab_authorization"])

    def test_outside_approved_root_remains_non_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-threat-root-") as directory:
            base = Path(directory)
            root = base / "canary-root"
            root.mkdir()
            (root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
            target = base / "outside-recover.txt"
            target.write_text("outside\n", encoding="utf-8")
            result = self._coordinator(root, base / "vault").run({
                "event_type": "FILE_ACTIVITY", "event_id": "outside-threat", "timestamp": 1000.0,
                "data": {
                    "operation": "CREATE", "path": str(target), "target": str(target), "approved_root": str(root),
                    "lab_canary": True, "execution_mode": LAB_CANARY_EXECUTION, "requested_action": "QUARANTINE",
                    "evidence_ref": "evidence://outside-threat",
                },
            }, operator_approved=True)
            self.assertEqual("DENIED", result["status"])
            self.assertEqual("TARGET_OUTSIDE_APPROVED_ROOT", result["reason"])
            self.assertTrue(target.exists())

    def test_production_authorization_stays_not_granted(self) -> None:
        policy = PolicyEngine().evaluate({"assessments": [{"incident_id": "i", "risk_score": 90, "risk_level": "CRITICAL", "requested_action": "QUARANTINE"}]}, safety=SafetyCore())
        self.assertEqual("NOT_GRANTED", policy["authorization"])
        self.assertEqual("OBSERVE_ONLY", policy["action"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
