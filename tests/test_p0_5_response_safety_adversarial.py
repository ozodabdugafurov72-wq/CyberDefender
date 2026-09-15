from __future__ import annotations

import base64
import os
import tempfile
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.blast_radius_guard import BlastRadiusGuard
from agent.config import load_config
from agent.main import CyberDefenderRuntime
from agent.post_action_verifier import PostActionVerifier
from agent.recovery_planner import RecoveryPlanner
from agent.safety import SafetyCore

PASS = 0
FAIL = 0


def check(label: str, condition: bool) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS | {label}")
    else:
        FAIL += 1
        print(f"FAIL | {label}")
        raise AssertionError(label)


print("=== CYBERDEFENDER P0.5 RESPONSE SAFETY ADVERSARIAL ===")

request = {
    "incident_id": "INC-ADV-001",
    "requester": "adversarial-test",
    "requested_action": "PROCESS_TERMINATE",
    "target": "pid:9999",
    "target_count": 1,
    "evidence_ref": "evidence://INC-ADV-001",
    "decision_digest": "a" * 64,
    "execution_mode": "DRY_RUN",
}
auth = {
    "accepted": True,
    "authorization": "DRY_RUN_ONLY",
    "execution_mode": "DRY_RUN",
    "real_world_effect": False,
    "token_id": "tok-adv-001",
}
baseline = {
    "accepted": True,
    "executed": False,
    "simulated": True,
    "execution_mode": "DRY_RUN",
    "real_world_effect": False,
    "action": "PROCESS_TERMINATE",
    "target": "pid:9999",
    "incident_id": "INC-ADV-001",
    "authorization_token_id": "tok-adv-001",
}

blast = BlastRadiusGuard()
# Malformed flood must fail closed without turning engine failure into a bypass.
malformed = [
    None, {}, {"execution_mode": "REAL"},
    dict(request, target_count=0), dict(request, target_count=-1),
    dict(request, target_count=True), dict(request, target_count="1"),
    dict(request, requested_action="UNKNOWN"),
    dict(request, requested_action="BOOT_MODIFY"),
    dict(request, target=""), dict(request, incident_id=""),
]
for idx, item in enumerate(malformed, 1):
    result = blast.evaluate(item)  # type: ignore[arg-type]
    check(f"Malformed blast request {idx} rejected", result.get("accepted") is False)
    check(f"Malformed blast request {idx} never authorizes", result.get("authorization") == "NOT_GRANTED")
check("Blast guard remains HEALTHY after malformed flood", blast.health_check()["status"] == "HEALTHY")
check("Blast guard unexpected engine failures remain zero", blast.health_check()["failed"] == 0)

post = PostActionVerifier()
real_effect = dict(baseline, executed=True, simulated=False, real_world_effect=True)
r = post.verify(real_effect, request=request, authorization=auth)
check("Forged real execution is rejected", r.get("verified") is False)
check("Forged real execution requires recovery", r.get("recovery_required") is True)
check("Forged real execution requires escalation", r.get("escalation_required") is True)

for label, mutation in [
    ("incident", {"incident_id": "INC-OTHER"}),
    ("action", {"action": "NETWORK_BLOCK"}),
    ("target", {"target": "pid:1111"}),
    ("token", {"authorization_token_id": "tok-forged"}),
    ("mode", {"execution_mode": "REAL"}),
    ("simulation", {"simulated": False}),
    ("execution uncertainty", {"executed": None}),
    ("effect uncertainty", {"real_world_effect": None}),
]:
    tampered = dict(baseline, **mutation)
    vr = post.verify(tampered, request=request, authorization=auth)
    check(f"Tampered {label} rejected", vr.get("verified") is False)
    check(f"Tampered {label} forces recovery planning", vr.get("recovery_required") is True)

bad_auth = dict(auth, authorization="REAL")
vr = post.verify(baseline, request=request, authorization=bad_auth)
check("Authorization contract tampering rejected", vr.get("verified") is False)
check("Authorization tampering fail-closed", vr.get("fail_closed") is True)
check("PostActionVerifier remains HEALTHY", post.health_check()["status"] == "HEALTHY")
check("PostActionVerifier grants no authority", post.last_result.get("authorization") == "NOT_GRANTED")

planner = RecoveryPlanner(max_steps=4)
uncertain_verification = {
    "accepted": False,
    "verified": False,
    "real_world_effect_observed": None,
    "recovery_required": True,
}
plan = planner.plan(uncertain_verification, request=request, action_result=real_effect)
check("Uncertain outcome requires recovery", plan.get("recovery_required") is True)
check("Recovery execution remains blocked", plan.get("recovery_executed") is False)
check("Recovery execution unsupported", plan.get("execution_supported") is False)
check("Recovery plan bounded to max_steps", plan.get("step_count") <= 4)
check("Recovery plan includes stop response", "STOP_AUTONOMOUS_RESPONSE" in plan.get("steps", []))
check("Recovery plan includes evidence preservation", "PRESERVE_EVIDENCE" in plan.get("steps", []))
check("Recovery plan grants no authority", plan.get("authorization") == "NOT_GRANTED")

bad_plan = planner.plan(None)  # type: ignore[arg-type]
check("Malformed recovery input fails closed", bad_plan.get("accepted") is False)
check("Malformed recovery still requires recovery/escalation", bad_plan.get("recovery_required") is True)
check("Malformed recovery never executes", bad_plan.get("recovery_executed") is False)
check("Recovery planner remains HEALTHY after contract rejection", planner.health_check()["status"] == "HEALTHY")

# Runtime adversarial path: a fake gateway returning real effect must be caught by
# the new independent post-response verifier and recovery planner.
old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
os.environ["CYBERDEFENDER_STATE_DIR"] = tempfile.mkdtemp(prefix="cd-p05-adv-")
os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"A" * 32).decode()
try:
    runtime = CyberDefenderRuntime(SafetyCore(), load_config())
    incident_id = "INC-P05-ADV-MAIN"
    runtime.last_risk_result = {
        "component": "RiskEngine", "version": "1.0", "accepted": True,
        "overall_risk_score": 90, "overall_risk_level": "CRITICAL",
        "assessments": [{
            "incident_id": incident_id,
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "requested_action": "PROCESS_TERMINATE",
        }],
        "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
    }
    policy = runtime.update_policy()
    verified = runtime.update_verification()
    digest = verified["assessments"][0]["decision_digest"]
    req = {
        "incident_id": incident_id,
        "requester": "p0.5-adv-main",
        "requested_action": "PROCESS_TERMINATE",
        "target": "pid:8888",
        "target_count": 1,
        "evidence_ref": f"evidence://{incident_id}",
        "decision_digest": digest,
        "execution_mode": "DRY_RUN",
    }

    original_execute = runtime.action_gateway.execute_dry_run
    def forged_execute(authorization, *, request):
        # Consume the valid token exactly as a gateway would, then return a
        # malicious/buggy result claiming real execution.
        consumed = runtime.authorization_gate.consume(
            authorization["token_id"], request=request,
            token_mac=authorization["token_mac"],
        )
        assert consumed.get("accepted") is True
        return {
            "accepted": True,
            "executed": True,
            "simulated": False,
            "execution_mode": "DRY_RUN",
            "real_world_effect": True,
            "action": request["requested_action"],
            "target": request["target"],
            "incident_id": request["incident_id"],
            "authorization_token_id": authorization["token_id"],
        }
    runtime.action_gateway.execute_dry_run = forged_execute
    lifecycle = runtime.run_response_dry_run(req)
    runtime.action_gateway.execute_dry_run = original_execute

    check("Forged runtime effect does not produce successful lifecycle", lifecycle.get("accepted") is False)
    check("Forged runtime effect lifecycle fails closed", lifecycle.get("stage") == "FAIL_CLOSED")
    check("Runtime post-action verifier rejects forged real effect", lifecycle["post_action_verification"].get("verified") is False)
    check("Runtime forged effect requires recovery", lifecycle["recovery"].get("recovery_required") is True)
    check("Runtime recovery remains plan-only", lifecycle["recovery"].get("recovery_executed") is False)
    check("Runtime aggregate still reports no authorized real execution", lifecycle.get("authorization") == "NOT_GRANTED")
    check("Runtime aggregate exposes forged real effect", lifecycle.get("real_world_effect") is True)
    check("Runtime aggregate marks forged effect unauthorized", lifecycle.get("real_world_effect_authorized") is False)
    check("Policy path remained valid before forged gateway", policy.get("accepted") is True)

    health = runtime.health_snapshot()
    check("Runtime health exposes post-action verifier", health["post_action_verifier"]["status"] == "HEALTHY")
    check("Runtime health exposes recovery planner", health["recovery_planner"]["status"] == "HEALTHY")
    check("ActionGateway production contract still dry-run only", runtime.action_gateway.health_check()["dry_run_only"] is True)
finally:
    if old_state is None:
        os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
    else:
        os.environ["CYBERDEFENDER_STATE_DIR"] = old_state
    if old_key is None:
        os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
    else:
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_key

print("\n=== P0.5 ADVERSARIAL RESULT ===")
print(f"PASS: {PASS}")
print(f"FAIL: {FAIL}")
print("Real-action claim cannot self-verify: VERIFIED")
print("Scope/result tampering: FAIL-CLOSED")
print("Recovery execution: BLOCKED / PLAN-ONLY")
print("Blast-radius expansion: BLOCKED")
print("RESULT: PASS")
