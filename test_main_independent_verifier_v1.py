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


print("CYBERDEFENDER — INDEPENDENT VERIFIER v1 MAIN INTEGRATION TEST")
print("=" * 72)
old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
state_dir = tempfile.mkdtemp(prefix="cd-verifier-")
os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"V" * 32).decode()

try:
    safety = SafetyCore()
    runtime = CyberDefenderRuntime(safety, load_config())
    check("IndependentVerifier initialized", runtime.independent_verifier is not None)
    check("IndependentVerifier HEALTHY", runtime.independent_verifier.health_check()["status"] == "HEALTHY")
    check("PolicyEngine HEALTHY", runtime.policy_engine.health_check()["status"] == "HEALTHY")
    check("RiskEngine HEALTHY", runtime.risk_engine.health_check()["status"] == "HEALTHY")
    check("AttackGraph HEALTHY", runtime.attack_graph.health_check()["status"] == "HEALTHY")

    risk = {
        "component": "RiskEngine", "version": "1.0", "accepted": True,
        "overall_risk_score": 85, "overall_risk_level": "CRITICAL",
        "assessments": [{"incident_id":"INC-IV-MAIN-001", "risk_score":85, "risk_level":"CRITICAL", "requested_action":"OBSERVE_ONLY"}],
        "authorization":"NOT_GRANTED", "action":"OBSERVE_ONLY",
    }
    runtime.last_risk_result = risk
    policy = runtime.update_policy()
    check("Policy update accepted", isinstance(policy, dict) and policy.get("accepted") is True)
    check("Policy requires verification", policy.get("policy_outcome") == "REQUIRE_VERIFICATION")
    check("Policy remains unauthorized", policy.get("authorization") == "NOT_GRANTED")

    verified = runtime.update_verification()
    check("Verification update returned dict", isinstance(verified, dict))
    check("Verification accepted", verified.get("accepted") is True)
    check("Verification passed", verified.get("verified") is True)
    check("Verification outcome VERIFIED", verified.get("verification_outcome") == "VERIFIED")
    check("Verification preserves NOT_GRANTED", verified.get("authorization") == "NOT_GRANTED")
    check("Verification preserves OBSERVE_ONLY", verified.get("action") == "OBSERVE_ONLY")
    check("Decision digest present", len(verified["assessments"][0]["decision_digest"]) == 64)

    # End-to-end cycle ordering hook: call the three runtime stages in canonical order.
    runtime.update_risk = lambda: risk
    runtime.last_risk_result = risk
    runtime.update_policy()
    verified = runtime.update_verification()
    check("Canonical Risk→Policy→Verifier chain passes", verified.get("verified") is True)

    # Tamper should fail closed and be observable without authorizing anything.
    tampered = dict(policy)
    tampered["assessments"] = [dict(policy["assessments"][0])]
    tampered["assessments"][0]["authorization"] = "GRANTED"
    runtime.last_policy_result = tampered
    rejected = runtime.update_verification()
    check("Tampered policy rejected", rejected.get("verified") is False)
    check("Tampered policy remains unauthorized", rejected.get("authorization") == "NOT_GRANTED")
    check("Verifier failure counter increments", runtime.independent_verifier_failures >= 1)

    # Restore trusted policy and prove recovery of verification state.
    runtime.last_policy_result = policy
    recovered = runtime.update_verification()
    check("Trusted policy re-verifies", recovered.get("verified") is True)
    check("Runtime health exposes verifier", "independent_verifier" in runtime.health_snapshot())
    check("Runtime reports verifier HEALTHY", runtime.health_snapshot()["independent_verifier"]["status"] == "HEALTHY")
    check("Overall runtime remains HEALTHY", runtime.health_snapshot()["runtime"]["status"] == "HEALTHY")

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
