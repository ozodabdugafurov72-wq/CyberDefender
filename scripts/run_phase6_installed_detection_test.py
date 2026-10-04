from __future__ import annotations

"""Run the Phase 6.1 threat-detection chain in one disposable lab root.

This runner is deliberately explicit and source-only.  It creates a temporary
canary directory, feeds the existing harmless simulator through the real
observation pipeline, and then sends one separately admitted harmless canary
file through the existing bounded Quarantine v2 coordinator.  No service,
network, firewall, registry, or user-file operation is available here.
"""

import hashlib
import json
import tempfile
from pathlib import Path
import sys
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

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


def _feed_to_pipeline(
    event: dict[str, Any],
    detector: Detector,
    correlation: CorrelationEngine,
    detections: list[dict[str, Any]],
) -> None:
    """Pass one lower-level telemetry event through Detector and Correlation."""
    for detection in detector.handle_event(event):
        detections.append(dict(detection))
        detection_event = {
            "event_type": "DETECTION",
            "event_id": detection.get("event_id") or event.get("event_id"),
            "timestamp": detection.get("timestamp", event.get("timestamp")),
            "source": "Phase6.1Runner",
            "data": detection,
        }
        correlation.ingest(detection_event, strict=True)


def _decision_snapshot(risk: dict[str, Any], safety: SafetyCore) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the real policy and independent-verification layers for observed risk."""
    decision_risk = dict(risk)
    decision_risk["assessments"] = [
        dict(item, requested_action="QUARANTINE")
        for item in risk.get("assessments", [])
        if isinstance(item, dict)
    ]
    policy = PolicyEngine().evaluate(decision_risk, safety=safety)
    verification = IndependentVerifier().verify(decision_risk, policy, safety=safety)
    return policy, verification


def _build_coordinator(root: Path, vault_root: Path) -> LabQuarantineCoordinator:
    issuer = QuarantineCapabilityIssuer()
    vault = BoundedQuarantineVault(vault_root, max_records=8, max_bytes=2 * 1024 * 1024)
    executor = BoundedQuarantineExecutor(vault, issuer, approved_root=root)
    return LabQuarantineCoordinator(
        detector=Detector(RuleEngine()),
        correlation_engine=CorrelationEngine(window_seconds=60),
        risk_engine=RiskEngine(),
        attack_graph=AttackGraph(),
        policy_engine=PolicyEngine(),
        independent_verifier=IndependentVerifier(),
        safety=SafetyCore(),
        issuer=issuer,
        executor=executor,
        approved_root=root,
    )


def _negative_control() -> list[dict[str, Any]]:
    detector = Detector(RuleEngine())
    results: list[dict[str, Any]] = []
    for index in range(3):
        results.extend(detector.handle_event({
            "event_type": "FILE_ACTIVITY",
            "event_id": f"phase6-negative-{index}",
            "timestamp": 1000.0 + index,
            "data": {
                "operation": "WRITE",
                "path": f"C:/CyberDefender-Phase6-benign/ordinary-{index}.txt",
                "host_id": "phase6-negative-host",
                "tenant_id": "phase6-negative-tenant",
            },
        }))
    return results


def run_phase6_1() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="CyberDefender-Phase6.1-LAB-") as directory:
        base = Path(directory)
        canary_root = base / "canary-root"
        vault_root = base / "vault"
        canary_root.mkdir()
        (canary_root / CANARY_MARKER_FILENAME).write_text(CANARY_MARKER, encoding="utf-8")

        detector = Detector(RuleEngine())
        correlation = CorrelationEngine(window_seconds=60)
        detections: list[dict[str, Any]] = []
        simulator_events = simulate_ransomware_behavior(
            lambda event: _feed_to_pipeline(event, detector, correlation, detections),
            root=canary_root,
        )
        incidents = correlation.get_recent_incidents(limit=10)
        risk = RiskEngine().assess(AttackGraph(), incidents)
        safety = SafetyCore()
        policy, independent = _decision_snapshot(risk, safety)

        # Use a fresh coordinator so the one executable canary admission is
        # deterministic and is not confused with the simulator's many signals.
        target = canary_root / "recover_phase6_canary.txt"
        target.write_text("harmless plaintext Phase 6.1 canary\n", encoding="utf-8")
        target_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        event_id = "phase6.1-quarantine-canary"
        quarantine_event = {
            "event_type": "FILE_ACTIVITY",
            "event_id": event_id,
            "timestamp": 1000.0,
            "data": {
                "operation": "CREATE",
                "path": str(target),
                "target": str(target),
                "approved_root": str(canary_root),
                "lab_canary": True,
                "execution_mode": LAB_CANARY_EXECUTION,
                "requested_action": "QUARANTINE",
                "evidence_ref": f"evidence://{event_id}",
                "endpoint_id": "phase6-lab-endpoint",
                "tenant_id": "phase6-lab-tenant",
                "host_id": "phase6-lab-host",
            },
        }
        coordinator = _build_coordinator(canary_root, vault_root)
        quarantine = coordinator.run(quarantine_event, operator_approved=True)

        negative = _negative_control()
        detection_types = [item.get("type") for item in detections if isinstance(item.get("type"), str)]
        negative_types = [item.get("type") for item in negative if isinstance(item.get("type"), str)]
        aggregate = risk.get("assessments", [{}])[0] if risk.get("assessments") else {}
        status = quarantine.get("status")
        quarantine_policy = quarantine.get("policy_decision") if isinstance(quarantine.get("policy_decision"), dict) else {}
        quarantine_verification = quarantine.get("independent_verification") if isinstance(quarantine.get("independent_verification"), dict) else {}
        if "RANSOMWARE_BEHAVIOR" not in detection_types:
            raise RuntimeError("simulator did not produce RANSOMWARE_BEHAVIOR")
        if "RANSOMWARE_BEHAVIOR" in negative_types:
            raise RuntimeError("benign negative control produced RANSOMWARE_BEHAVIOR")
        if status != "VERIFIED_QUARANTINED" or quarantine.get("accepted") is not True:
            raise RuntimeError(f"bounded canary quarantine failed: {quarantine.get('reason', status)}")
        if quarantine_policy.get("policy_outcome") != "REQUIRE_VERIFICATION":
            raise RuntimeError("quarantine policy did not require independent verification")
        if quarantine_verification.get("verification_outcome") != "VERIFIED":
            raise RuntimeError("quarantine decision was not independently verified")
        if target.exists():
            raise RuntimeError("quarantine target remained in its original path")

        return {
            "status": "VERIFIED_QUARANTINED",
            "simulator_events": len(simulator_events),
            "detection_events": [
                {"event_id": item.get("event_id"), "type": item.get("type"), "severity": item.get("severity")}
                for item in detections
            ],
            "detection_types_produced": detection_types,
            "ransomware_behavior_detected": True,
            "aggregate_incident_id": aggregate.get("incident_id"),
            "final_risk_score": risk.get("overall_risk_score"),
            "final_risk_level": risk.get("overall_risk_level"),
            "policy_outcome": policy.get("policy_outcome"),
            "policy_authorization": policy.get("authorization"),
            "independent_verification": independent.get("verification_outcome"),
            "quarantine_incident_id": quarantine.get("incident_id"),
            "quarantine_policy_outcome": quarantine_policy.get("policy_outcome"),
            "quarantine_verification_outcome": quarantine_verification.get("verification_outcome"),
            "quarantine_result": status,
            "quarantine_id": quarantine.get("quarantine_id"),
            "target_sha256": target_sha256,
            "negative_control_detection_types": negative_types,
            "negative_control_ransomware_behavior": "RANSOMWARE_BEHAVIOR" in negative_types,
            "production_authorization": quarantine.get("production_authorization"),
            "lab_authorization": quarantine.get("lab_authorization"),
            "network_activity": False,
            "persistence": False,
            "privilege_escalation": False,
            "user_files_touched": False,
        }


def main() -> int:
    try:
        print(json.dumps(run_phase6_1(), sort_keys=True, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "PHASE6_1_FAILED", "error": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
