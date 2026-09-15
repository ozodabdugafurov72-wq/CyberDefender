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
from agent.main import CyberDefenderRuntime, RESPONSE_SAFETY_CONTRACT_VERSION
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


def prepare_runtime() -> CyberDefenderRuntime:
    return CyberDefenderRuntime(SafetyCore(), load_config())


def prepare_decision(runtime: CyberDefenderRuntime, *, incident_id: str, action: str) -> str:
    runtime.last_risk_result = {
        "component": "RiskEngine",
        "version": "1.0",
        "accepted": True,
        "overall_risk_score": 90,
        "overall_risk_level": "CRITICAL",
        "assessments": [
            {
                "incident_id": incident_id,
                "risk_score": 90,
                "risk_level": "CRITICAL",
                "requested_action": action,
            }
        ],
        "authorization": "NOT_GRANTED",
        "action": "OBSERVE_ONLY",
    }
    policy = runtime.update_policy()
    check("Policy accepted for bounded response test", isinstance(policy, dict) and policy.get("accepted") is True)
    check("Policy requires independent verification", policy.get("policy_outcome") == "REQUIRE_VERIFICATION")
    verified = runtime.update_verification()
    check("Pre-authorization verifier passes", isinstance(verified, dict) and verified.get("verified") is True)
    check("Pre-authorization verifier grants no authority", verified.get("authorization") == "NOT_GRANTED")
    return verified["assessments"][0]["decision_digest"]


print("=== CYBERDEFENDER P0.5 RESPONSE SAFETY FOUNDATION ===")

# Standalone blast radius contract.
blast = BlastRadiusGuard()
check("BlastRadiusGuard starts HEALTHY", blast.health_check()["status"] == "HEALTHY")
check("BlastRadiusGuard is fail-closed", blast.health_check()["fail_closed"] is True)
check("BlastRadiusGuard real execution unsupported", blast.health_check()["real_execution_supported"] is False)

base_request = {
    "incident_id": "INC-P05-001",
    "requester": "p0.5-test",
    "requested_action": "PROCESS_TERMINATE",
    "target": "pid:1234",
    "target_count": 1,
    "evidence_ref": "evidence://INC-P05-001",
    "decision_digest": "d" * 64,
    "execution_mode": "DRY_RUN",
}
allowed = blast.evaluate(base_request)
check("Single-target dry-run scope accepted", allowed.get("accepted") is True)
check("Single-target dry-run scope allowed", allowed.get("allowed") is True)
check("Blast guard does not authorize", allowed.get("authorization") == "NOT_GRANTED")
check("Blast guard has no real-world effect", allowed.get("real_world_effect") is False)
check("Blast guard target count is one", allowed.get("target_count") == 1)

wide = dict(base_request, target_count=2)
wide_result = blast.evaluate(wide)
check("Multi-target scope rejected", wide_result.get("accepted") is False)
check("Multi-target rejection reason is bounded", wide_result.get("reason") == "BLAST_RADIUS_EXCEEDED")
check("Multi-target scope never authorizes", wide_result.get("authorization") == "NOT_GRANTED")

l6 = dict(base_request, requested_action="SYSTEM_MODIFY")
l6_result = blast.evaluate(l6)
check("L6 action rejected at blast-radius boundary", l6_result.get("accepted") is False)
check("L6 reason explicit", l6_result.get("reason") == "L6_ACTION_BLOCKED")

real = dict(base_request, execution_mode="REAL")
real_result = blast.evaluate(real)
check("Real execution rejected", real_result.get("accepted") is False)
check("Real execution rejection explicit", real_result.get("reason") == "REAL_EXECUTION_NOT_SUPPORTED")

# Standalone post-action verification contract.
post = PostActionVerifier()
check("PostActionVerifier starts HEALTHY", post.health_check()["status"] == "HEALTHY")
check("PostActionVerifier real execution unsupported", post.health_check()["real_execution_supported"] is False)

authorization = {
    "accepted": True,
    "authorization": "DRY_RUN_ONLY",
    "execution_mode": "DRY_RUN",
    "real_world_effect": False,
    "token_id": "tok-p05-001",
}
action_result = {
    "accepted": True,
    "executed": False,
    "simulated": True,
    "execution_mode": "DRY_RUN",
    "real_world_effect": False,
    "action": "PROCESS_TERMINATE",
    "target": "pid:1234",
    "incident_id": "INC-P05-001",
    "authorization_token_id": "tok-p05-001",
    "verification_required": True,
}
post_ok = post.verify(action_result, request=base_request, authorization=authorization)
check("Dry-run response receipt verified", post_ok.get("verified") is True)
check("Dry-run response outcome explicit", post_ok.get("verification_outcome") == "DRY_RUN_VERIFIED")
check("No real-world effect independently recorded", post_ok.get("real_world_effect_observed") is False)
check("Verified dry-run requires no recovery", post_ok.get("recovery_required") is False)
check("Receipt digest present", isinstance(post_ok.get("receipt_digest"), str) and len(post_ok["receipt_digest"]) == 64)
check("Post verifier grants no authority", post_ok.get("authorization") == "NOT_GRANTED")

# Standalone recovery planning contract.
planner = RecoveryPlanner()
check("RecoveryPlanner starts HEALTHY", planner.health_check()["status"] == "HEALTHY")
check("RecoveryPlanner is plan-only", planner.health_check()["plan_only"] is True)
check("RecoveryPlanner real execution unsupported", planner.health_check()["real_execution_supported"] is False)
no_recovery = planner.plan(post_ok, request=base_request, action_result=action_result)
check("Verified no-effect response needs no recovery", no_recovery.get("recovery_required") is False)
check("No-recovery outcome explicit", no_recovery.get("recovery_outcome") == "NO_RECOVERY_REQUIRED")
check("Recovery never executes", no_recovery.get("recovery_executed") is False)
check("Recovery planner grants no authority", no_recovery.get("authorization") == "NOT_GRANTED")

# Full runtime lifecycle.
old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
os.environ["CYBERDEFENDER_STATE_DIR"] = tempfile.mkdtemp(prefix="cd-p05-main-")
os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"P" * 32).decode()
try:
    runtime = prepare_runtime()
    check("P0.5 response contract version exposed", RESPONSE_SAFETY_CONTRACT_VERSION == "P0.5-1")
    check("Main runtime hardened version is v2.4", runtime.VERSION == "2.4")
    check("BlastRadiusGuard initialized in runtime", runtime.blast_radius_guard is not None)
    check("PostActionVerifier initialized in runtime", runtime.post_action_verifier is not None)
    check("RecoveryPlanner initialized in runtime", runtime.recovery_planner is not None)
    check("ActionGateway still exists", runtime.action_gateway is not None)
    check("ActionGateway remains dry-run only", runtime.action_gateway.health_check()["dry_run_only"] is True)
    check("ActionGateway still reports no real-world effect", runtime.action_gateway.health_check()["real_world_effect"] is False)

    incident_id = "INC-P05-MAIN-001"
    digest = prepare_decision(runtime, incident_id=incident_id, action="PROCESS_TERMINATE")
    request = {
        "incident_id": incident_id,
        "requester": "p0.5-main-test",
        "requested_action": "PROCESS_TERMINATE",
        "target": "pid:4321",
        "target_count": 1,
        "evidence_ref": f"evidence://{incident_id}",
        "decision_digest": digest,
        "execution_mode": "DRY_RUN",
    }
    lifecycle = runtime.run_response_dry_run(request)
    check("Response lifecycle accepted", lifecycle.get("accepted") is True)
    check("Response lifecycle reaches COMPLETE", lifecycle.get("stage") == "COMPLETE")
    check("Lifecycle blast-radius passed", lifecycle["blast_radius"].get("allowed") is True)
    check("Lifecycle authorization is dry-run capability only", lifecycle["authorization_result"].get("authorization") == "DRY_RUN_ONLY")
    check("Lifecycle ActionGateway simulated", lifecycle["action_result"].get("simulated") is True)
    check("Lifecycle ActionGateway did not execute", lifecycle["action_result"].get("executed") is False)
    check("Lifecycle post-action verification passes", lifecycle["post_action_verification"].get("verified") is True)
    check("Lifecycle post-action outcome is DRY_RUN_VERIFIED", lifecycle["post_action_verification"].get("verification_outcome") == "DRY_RUN_VERIFIED")
    check("Lifecycle recovery not required", lifecycle["recovery"].get("recovery_required") is False)
    check("Lifecycle real-world effect remains false", lifecycle.get("real_world_effect") is False)
    check("Lifecycle aggregate never grants authority", lifecycle.get("authorization") == "NOT_GRANTED")
    check("Runtime stores blast-radius result", runtime.last_blast_radius_result is lifecycle["blast_radius"])
    check("Runtime stores post-action verification", runtime.last_post_action_verification_result is lifecycle["post_action_verification"])
    check("Runtime stores recovery result", runtime.last_response_recovery_result is lifecycle["recovery"])
    check("Runtime stores lifecycle result", runtime.last_response_lifecycle_result is lifecycle)

    health = runtime.health_snapshot()
    check("Health exposes blast-radius guard", "blast_radius_guard" in health)
    check("Health exposes post-action verifier", "post_action_verifier" in health)
    check("Health exposes recovery planner", "recovery_planner" in health)
    check("Blast-radius health remains HEALTHY", health["blast_radius_guard"]["status"] == "HEALTHY")
    check("Post-action verifier health remains HEALTHY", health["post_action_verifier"]["status"] == "HEALTHY")
    check("Recovery planner health remains HEALTHY", health["recovery_planner"]["status"] == "HEALTHY")
    check("Runtime component failures remain zero", health["runtime"]["component_failures"] == 0)
    check("Runtime remains HEALTHY", health["runtime"]["status"] == "HEALTHY")

    # Blast-radius denial must stop before authorization/execution.
    digest2 = prepare_decision(runtime, incident_id="INC-P05-WIDE", action="PROCESS_TERMINATE")
    wide_request = {
        "incident_id": "INC-P05-WIDE",
        "requester": "p0.5-main-test",
        "requested_action": "PROCESS_TERMINATE",
        "target": "pid-set:test",
        "target_count": 2,
        "evidence_ref": "evidence://INC-P05-WIDE",
        "decision_digest": digest2,
        "execution_mode": "DRY_RUN",
    }
    before_simulations = runtime.action_gateway.health_check()["simulations"]
    denied_lifecycle = runtime.run_response_dry_run(wide_request)
    after_simulations = runtime.action_gateway.health_check()["simulations"]
    check("Wide lifecycle rejected", denied_lifecycle.get("accepted") is False)
    check("Wide lifecycle stops at blast-radius stage", denied_lifecycle.get("stage") == "BLAST_RADIUS")
    check("Blast-radius denial prevents ActionGateway call", before_simulations == after_simulations)
    check("Blast-radius denial still has no real-world effect", denied_lifecycle.get("real_world_effect") is False)

    # Existing critical production security components remain version-stable.
    check("Production EventBus is v2.4", runtime.event_bus.VERSION == "2.4")
    check("DurableEventSpool remains v2.3", runtime.spool.VERSION == "2.3")
    check("DurableEventPipeline remains v1.3", runtime.pipeline.VERSION == "1.3")
    check("IndependentVerifier remains pre-authorization v1", runtime.independent_verifier.VERSION == "1.0")
    check("SafetyAuthorizationGate remains v1", runtime.authorization_gate.VERSION == "1.0")
    check("ActionGateway remains v1", runtime.action_gateway.VERSION == "1.0")
finally:
    if old_state is None:
        os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
    else:
        os.environ["CYBERDEFENDER_STATE_DIR"] = old_state
    if old_key is None:
        os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
    else:
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_key

# Static safety audit of the new components: no direct OS executor surface.
for filename in ["blast_radius_guard.py", "post_action_verifier.py", "recovery_planner.py"]:
    text = (Path(__file__).resolve().parents[1] / "agent" / filename).read_text(encoding="utf-8")
    lowered = text.lower()
    check(f"{filename} has no subprocess import", "import subprocess" not in lowered)
    check(f"{filename} has no os.system", "os.system(" not in lowered)
    check(f"{filename} has no winreg import", "import winreg" not in lowered)

print("\n=== P0.5 RESULT ===")
print(f"PASS: {PASS}")
print(f"FAIL: {FAIL}")
print("Blast-radius bounded response scope: VERIFIED")
print("Dry-run response lifecycle: VERIFIED")
print("Independent post-response no-effect verification: VERIFIED")
print("Recovery planning: BOUNDED / PLAN-ONLY")
print("Real privileged execution: BLOCKED")
print("RESULT: PASS")
