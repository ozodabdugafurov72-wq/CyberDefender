from __future__ import annotations

import base64
import os
import tempfile

from agent.config import load_config
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def check(label: str, condition: bool) -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)


print("CYBERDEFENDER — SAFETY AUTHORIZATION + ACTION GATEWAY MAIN INTEGRATION")
print("=" * 78)
old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
state_dir = tempfile.mkdtemp(prefix="cd-scag-main-")
os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"S" * 32).decode()

try:
    safety = SafetyCore()
    runtime = CyberDefenderRuntime(safety, load_config())
    check("SafetyAuthorizationGate initialized", runtime.authorization_gate is not None)
    check("ActionGateway initialized", runtime.action_gateway is not None)
    check("Authorization Gate HEALTHY", runtime.authorization_gate.health_check()["status"] == "HEALTHY")
    check("Action Gateway HEALTHY", runtime.action_gateway.health_check()["status"] == "HEALTHY")
    check("Gate is dry-run only", runtime.authorization_gate.health_check()["dry_run_only"] is True)
    check("Gateway is dry-run only", runtime.action_gateway.health_check()["dry_run_only"] is True)

    risk = {
        "component": "RiskEngine", "version": "1.0", "accepted": True,
        "overall_risk_score": 90, "overall_risk_level": "CRITICAL",
        "assessments": [{"incident_id": "INC-MAIN-SCAG-001", "risk_score": 90,
                         "risk_level": "CRITICAL", "requested_action": "PROCESS_TERMINATE"}],
        "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
    }
    runtime.last_risk_result = risk
    policy = runtime.update_policy()
    check("Runtime PolicyEngine accepts proposal", policy.get("accepted") is True)
    check("Runtime Policy requires verification", policy.get("policy_outcome") == "REQUIRE_VERIFICATION")
    verified = runtime.update_verification()
    check("Runtime IndependentVerifier verifies proposal", verified.get("verified") is True)
    digest = verified["assessments"][0]["decision_digest"]

    request = {
        "incident_id": "INC-MAIN-SCAG-001", "requester": "integration-test",
        "requested_action": "PROCESS_TERMINATE", "target": "pid:1234",
        "evidence_ref": "evidence://INC-MAIN-SCAG-001", "decision_digest": digest,
        "execution_mode": "DRY_RUN",
    }
    auth = runtime.authorize_dry_run(request)
    check("Runtime authorization gate issues dry-run capability", auth.get("accepted") is True)
    check("Runtime authorization is not real-world grant", auth.get("authorization") == "DRY_RUN_ONLY")
    action = runtime.execute_dry_run(auth, request=request)
    check("Runtime ActionGateway simulates action", action.get("accepted") is True)
    check("Runtime action not executed", action.get("executed") is False)
    check("Runtime action has no real-world effect", action.get("real_world_effect") is False)

    health = runtime.health_snapshot()
    check("Runtime health exposes authorization gate", "authorization_gate" in health)
    check("Runtime health exposes action gateway", "action_gateway" in health)
    check("Authorization gate remains HEALTHY", health["authorization_gate"]["status"] == "HEALTHY")
    check("Action gateway remains HEALTHY", health["action_gateway"]["status"] == "HEALTHY")
    check("Overall runtime remains HEALTHY", health["runtime"]["status"] == "HEALTHY")

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
