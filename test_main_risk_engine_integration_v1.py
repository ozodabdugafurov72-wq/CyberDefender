from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.config import load_config


def check(label: str, condition: bool) -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)


print("CYBERDEFENDER — RISK ENGINE v1 MAIN INTEGRATION TEST")
print("=" * 72)

old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
state_dir = tempfile.mkdtemp(prefix="cd-risk-")
os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"R" * 32).decode()

try:
    runtime = CyberDefenderRuntime(SafetyCore(), load_config())
    check("RiskEngine initialized", runtime.risk_engine is not None)
    check("RiskEngine HEALTHY", runtime.risk_engine.health_check()["status"] == "HEALTHY")
    check("AttackGraph HEALTHY", runtime.attack_graph.health_check()["status"] == "HEALTHY")

    process_result = runtime.update_process_graph()
    check("ProcessGraph runtime update accepted", isinstance(process_result, dict) and process_result.get("accepted") is True)
    attack_result = runtime.update_attack_graph()
    check("AttackGraph runtime update accepted", isinstance(attack_result, dict) and attack_result.get("accepted") is True)
    risk_result = runtime.update_risk()
    check("Risk update returned dict", isinstance(risk_result, dict))
    check("Risk result accepted", risk_result.get("accepted", True) is not False)
    check("Risk score bounded", 0 <= risk_result.get("overall_risk_score", -1) <= 100)
    check("Risk level valid", risk_result.get("overall_risk_level") in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
    check("Risk does not grant authorization", risk_result.get("authorization") == "NOT_GRANTED")
    check("Risk remains observe-only", risk_result.get("action") == "OBSERVE_ONLY")

    # Trusted incident from the same correlation contract.
    incident = {
        "incident_id": "INC-RISK-INTEGRATION-001",
        "correlation_key": "test",
        "risk_score": 70,
        "severity": "HIGH",
        "event_count": 2,
        "detections": [
            {"type": "SUSPICIOUS_PROCESS"},
            {"type": "NETWORK_ANOMALY"},
        ],
    }
    ingest = runtime.attack_graph.ingest_incident(incident)
    check("Synthetic trusted incident accepted by AttackGraph", ingest.get("accepted") is True)
    original_get_recent = runtime.correlation_engine.get_recent_incidents
    runtime.correlation_engine.get_recent_incidents = lambda limit=20: [incident]
    risk_result = runtime.update_risk()
    runtime.correlation_engine.get_recent_incidents = original_get_recent
    check("Risk reassessment returned dict", isinstance(risk_result, dict))
    check("Incident assessed by RiskEngine", risk_result.get("incidents_assessed") == 1)
    check("Incident risk is present", risk_result["assessments"][0]["incident_id"] == incident["incident_id"])
    check("Incident score remains bounded", 0 <= risk_result["assessments"][0]["risk_score"] <= 100)

    health = runtime.health_snapshot()
    check("Runtime health exposes RiskEngine", "risk_engine" in health)
    check("Runtime reports RiskEngine HEALTHY", health["risk_engine"]["status"] == "HEALTHY")
    check("Runtime health exposes AttackGraph", "attack_graph" in health)
    check("Overall runtime remains HEALTHY", health["runtime"]["status"] == "HEALTHY")
    check("Runtime RiskEngine failure counter is zero", runtime.risk_engine_failures == 0)

finally:
    if old_state is None:
        os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
    else:
        os.environ["CYBERDEFENDER_STATE_DIR"] = old_state
    if old_key is None:
        os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
    else:
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_key

print("\nRESULT: PASS")
