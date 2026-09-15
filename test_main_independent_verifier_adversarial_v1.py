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


def setup():
    old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
    old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
    os.environ["CYBERDEFENDER_STATE_DIR"] = tempfile.mkdtemp(prefix="cd-verifier-adv-")
    os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"A" * 32).decode()
    return old_state, old_key


def restore(old_state, old_key):
    if old_state is None:
        os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
    else:
        os.environ["CYBERDEFENDER_STATE_DIR"] = old_state
    if old_key is None:
        os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
    else:
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_key


print("CYBERDEFENDER — INDEPENDENT VERIFIER v1 ADVERSARIAL MAIN TEST")
print("=" * 72)
old_state, old_key = setup()
try:
    safety = SafetyCore()
    runtime = CyberDefenderRuntime(safety, load_config())
    base_risk = {
        "assessments": [{"incident_id":"INC-ADV-001","risk_score":90,"risk_level":"CRITICAL","requested_action":"PROCESS_TERMINATE"}]
    }
    runtime.last_risk_result = base_risk
    policy = runtime.update_policy()
    check("Baseline policy requires verification", policy.get("policy_outcome") == "REQUIRE_VERIFICATION")
    check("Baseline policy unauthorized", policy.get("authorization") == "NOT_GRANTED")
    ok = runtime.update_verification()
    check("Baseline independent verification passes", ok.get("verified") is True)

    # Attempt to smuggle authorization through policy output.
    tampered = {**policy, "assessments": [dict(policy["assessments"][0])]}
    tampered["assessments"][0]["authorization"] = "GRANTED"
    runtime.last_policy_result = tampered
    bad = runtime.update_verification()
    check("Authorization smuggling rejected", bad.get("verified") is False)
    check("Authorization smuggling remains fail-closed", bad.get("authorization") == "NOT_GRANTED")

    # Attempt policy outcome downgrade on critical risk.
    tampered = {**policy, "assessments": [dict(policy["assessments"][0])]}
    tampered["assessments"][0]["policy_outcome"] = "OBSERVE_ONLY"
    runtime.last_policy_result = tampered
    bad = runtime.update_verification()
    check("Critical-risk verification bypass rejected", bad.get("verified") is False)

    # Attempt risk score manipulation after policy evaluation.
    runtime.last_policy_result = policy
    tampered_risk = {**base_risk, "assessments": [dict(base_risk["assessments"][0])]}
    tampered_risk["assessments"][0]["risk_score"] = 10
    runtime.last_risk_result = tampered_risk
    bad = runtime.update_verification()
    check("Risk/policy tampering rejected", bad.get("verified") is False)

    # SafetyCore enters fail-safe state; a previously high-risk verification must be denied.
    runtime.last_risk_result = base_risk
    runtime.last_policy_result = policy
    safety.enter_safe_mode("adversarial-test")
    safe_policy = runtime.update_policy()
    check("Safe mode forces policy DENY", safe_policy.get("policy_outcome") == "DENY")
    safe_verified = runtime.update_verification()
    check("Safe-mode verification passes fail-closed", safe_verified.get("verified") is True)
    check("Safe-mode outcome remains DENY", safe_verified["assessments"][0]["policy_outcome"] == "DENY")
    check("Safe-mode authorization remains NOT_GRANTED", safe_verified.get("authorization") == "NOT_GRANTED")

    # Repeated malformed calls must not turn invalid input into authorization.
    for _ in range(20):
        bad = runtime.independent_verifier.verify({}, {}, safety=safety)
        check("Malformed input stays rejected", bad.get("verified") is False)
    check("Verifier remains fail-closed after malformed flood", runtime.independent_verifier.health_check()["authorization"] == "NOT_GRANTED")
    check("Verifier unexpected-failure counter remains zero", runtime.independent_verifier.health_check()["failed"] == 0)
    check("Runtime exposes verifier health", "independent_verifier" in runtime.health_snapshot())

finally:
    restore(old_state, old_key)

print("\nRESULT: PASS")
