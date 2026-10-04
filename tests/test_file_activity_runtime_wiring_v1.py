from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from agent.detection.detector import Detector
from agent.detection.rules import RuleEngine
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.engine import CorrelationEngine
from agent.attack_graph import AttackGraph
from agent.independent_verifier import IndependentVerifier
from agent.main import CyberDefenderRuntime
from agent.policy_engine import PolicyEngine
from agent.quarantine import (
    BoundedQuarantineExecutor,
    BoundedQuarantineVault,
    LAB_CANARY_EXECUTION,
    LabQuarantineCoordinator,
    QuarantineCapabilityIssuer,
    CANARY_MARKER,
    CANARY_MARKER_FILENAME,
)
from agent.risk_engine import RiskEngine
from agent.safety import SafetyCore
from agent.sensors.file_activity_collector import (
    FILE_ACTIVITY_CANARY_MARKER,
    FILE_ACTIVITY_CANARY_MARKER_FILENAME,
    FileActivityCollector,
)


class FileActivityRuntimeWiringV1Tests(unittest.TestCase):
    def test_collector_events_enter_existing_threat_detector(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-file-wiring-") as directory:
            base = Path(directory)
            root = base / "LiveRansomwareTest"
            root.mkdir()
            (root / FILE_ACTIVITY_CANARY_MARKER_FILENAME).write_text(
                FILE_ACTIVITY_CANARY_MARKER,
                encoding="utf-8",
            )
            runtime = object.__new__(CyberDefenderRuntime)
            runtime.file_activity_collector = FileActivityCollector(
                root,
                endpoint_id="endpoint-lab",
                tenant_id="tenant-lab",
            )
            runtime.threat_telemetry_detector = Detector(RuleEngine())
            runtime.file_activity_events_seen = 0
            runtime.file_activity_events_dropped = 0
            runtime.file_activity_failures = 0
            runtime.last_file_activity_events = []
            runtime.last_file_activity_detections = []
            runtime.last_file_activity_trigger = None
            admitted: list[dict] = []
            runtime.process_detection = lambda **kwargs: admitted.append(kwargs["detection"])
            event_types: set[str] = set()

            self.assertEqual([], runtime.collect_file_activity(event_types))
            for index in range(8):
                (root / f"data-{index}.txt").write_text("one", encoding="utf-8")
            time.sleep(0.002)
            events = runtime.collect_file_activity(event_types)
            self.assertTrue(events)
            self.assertTrue(admitted)

            for index in range(4):
                source = root / f"data-{index}.txt"
                destination = root / f"data-{index}.locked"
                source.rename(destination)
            (root / "RECOVER_FILES.txt").write_text("harmless note", encoding="utf-8")
            runtime.collect_file_activity(event_types)

            detection_types = {item.get("type") for item in runtime.last_file_activity_detections}
            self.assertIn("RANSOMWARE_BEHAVIOR", detection_types)
            self.assertIsNotNone(runtime.last_file_activity_trigger)
            self.assertTrue(all(item.get("source") == "ThreatRuleEngine" for item in runtime.last_file_activity_detections))
            self.assertTrue(all(item.get("target") is None for item in runtime.last_file_activity_detections))

    def test_lab_provenance_survives_canonical_event_and_correlation(self) -> None:
        target = r"C:\CD\LAB\LiveRansomwareTest\recover.txt"
        event = CyberDefenderRuntime._build_event(
            {
                "type": "RANSOMWARE_BEHAVIOR",
                "severity": "CRITICAL",
                "value": {"signal_categories": ["mass_file_modification", "rapid_rename", "ransom_note"]},
                "message": "bounded lab evidence",
                "tenant_id": "lab-tenant",
                "host_id": "endpoint-lab",
                "sensor_id": "FileActivityCollector",
                "provenance": {
                    "activity_event_id": "file-123",
                    "target": target,
                    "approved_root": r"C:\CD\LAB\LiveRansomwareTest",
                    "lab_canary": True,
                    "execution_mode": "LAB_CANARY_EXECUTION",
                    "secret": "must-drop",
                },
            },
            "FileActivityCollector",
        )
        detection = SecurityEventBridge.to_detection(event)
        incident = CorrelationEngine().ingest(detection, strict=True)
        stored = incident["detections"][0]["provenance"]
        self.assertEqual("file-123", stored["activity_event_id"])
        self.assertEqual(target, stored["target"])
        self.assertNotIn("secret", stored)

    def test_existing_pipeline_can_execute_one_collector_derived_lab_canary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="CyberDefender-file-response-") as directory:
            base = Path(directory)
            root = base / "LiveRansomwareTest"
            root.mkdir()
            (root / FILE_ACTIVITY_CANARY_MARKER_FILENAME).write_text(FILE_ACTIVITY_CANARY_MARKER, encoding="utf-8")
            (root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")
            collector = FileActivityCollector(root, endpoint_id="endpoint-lab", tenant_id="lab-tenant")
            telemetry_detector = Detector(RuleEngine())
            correlation = CorrelationEngine(window_seconds=60)

            def feed(events: list[dict]) -> list[tuple[dict, dict]]:
                triggers: list[tuple[dict, dict]] = []
                for raw in events:
                    for raw_detection in telemetry_detector.handle_event(raw):
                        detection = dict(raw_detection)
                        data = raw.get("data", {})
                        detection["provenance"] = {
                            "activity_event_id": raw["event_id"],
                            "target": data.get("path") or data.get("new_path"),
                            "approved_root": str(root),
                            "lab_canary": True,
                            "execution_mode": LAB_CANARY_EXECUTION,
                        }
                        if detection.get("type") == "RANSOMWARE_BEHAVIOR":
                            triggers.append((raw, detection))
                        event = CyberDefenderRuntime._build_event(detection, "FileActivityCollector")
                        correlation.ingest(SecurityEventBridge.to_detection(event), strict=True)
                return triggers

            collector.poll()
            for index in range(8):
                (root / f"doc-{index}.txt").write_text("plain", encoding="utf-8")
            triggers = feed(collector.poll())
            for index in range(4):
                (root / f"doc-{index}.txt").rename(root / f"doc-{index}.locked")
            (root / "RECOVER_FILES.txt").write_text("harmless note", encoding="utf-8")
            triggers.extend(feed(collector.poll()))
            self.assertTrue(triggers)

            issuer = QuarantineCapabilityIssuer()
            vault = BoundedQuarantineVault(base / "vault", max_records=8, max_bytes=2 * 1024 * 1024)
            executor = BoundedQuarantineExecutor(vault, issuer, approved_root=root)
            coordinator = LabQuarantineCoordinator(
                detector=telemetry_detector,
                correlation_engine=correlation,
                risk_engine=RiskEngine(),
                attack_graph=AttackGraph(),
                policy_engine=PolicyEngine(),
                independent_verifier=IndependentVerifier(),
                safety=SafetyCore(),
                issuer=issuer,
                executor=executor,
                approved_root=root,
            )
            runtime = object.__new__(CyberDefenderRuntime)
            runtime.lab_quarantine_coordinator = coordinator
            runtime.last_file_activity_trigger = triggers[-1]
            runtime.correlation_engine = correlation
            runtime.lab_quarantine_attempts = {}
            runtime.last_lab_quarantine_result = None
            result = runtime.run_lab_file_response()
            self.assertEqual("VERIFIED_QUARANTINED", result["status"])
            self.assertEqual("CRITICAL", result["risk_result"]["overall_risk_level"])
            self.assertEqual("REQUIRE_VERIFICATION", result["policy_decision"]["policy_outcome"])
            self.assertEqual("VERIFIED", result["independent_verification"]["verification_outcome"])
            self.assertEqual("NOT_GRANTED", result["production_authorization"])
            self.assertEqual("QUARANTINE_CAPABILITY_CONSUMED", result["lab_authorization"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
