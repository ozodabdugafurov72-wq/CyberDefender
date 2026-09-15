from __future__ import annotations

import base64
import os
import tempfile
import time

from agent.action_gateway import ActionGateway
from agent.safety import SafetyCore
from agent.safety_authorization_gate import SafetyAuthorizationGate


def check(label: str, condition: bool) -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)


print("CYBERDEFENDER — SAFETY CORE AUTHORIZATION GATE v1 + ACTION GATEWAY v1")
print("FOCUSED + ADVERSARIAL DRY-RUN TEST")
print("=" * 78)

safety = SafetyCore()
gate = SafetyAuthorizationGate(ttl_seconds=2, max_outstanding=8)
gateway = ActionGateway(gate)

# Synthetic but contract-valid Risk -> Policy -> IndependentVerifier-shaped data.
risk = {
    "component": "RiskEngine", "version": "1.0", "accepted": True,
    "overall_risk_score": 90, "overall_risk_level": "CRITICAL",
    "assessments": [{
        "incident_id": "INC-SCAG-001", "risk_score": 90,
        "risk_level": "CRITICAL", "requested_action": "PROCESS_TERMINATE",
    }],
    "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
}

from agent.policy_engine import PolicyEngine
from agent.independent_verifier import IndependentVerifier
policy_engine = PolicyEngine()
policy = policy_engine.evaluate(risk, safety=safety)
verifier = IndependentVerifier()
verified = verifier.verify(risk, policy, safety=safety)
check("Policy requires independent verification", policy.get("policy_outcome") == "REQUIRE_VERIFICATION")
check("Policy remains unauthorized", policy.get("authorization") == "NOT_GRANTED")
check("Independent verification passes", verified.get("verified") is True)
check("Verifier remains unauthorized", verified.get("authorization") == "NOT_GRANTED")

assessment = verified["assessments"][0]
request = {
    "incident_id": "INC-SCAG-001",
    "requester": "owner-console-test",
    "requested_action": "PROCESS_TERMINATE",
    "target": "pid:4242",
    "evidence_ref": "evidence://INC-SCAG-001",
    "decision_digest": assessment["decision_digest"],
    "execution_mode": "DRY_RUN",
}

auth = gate.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=safety)
check("Dry-run authorization issued", auth.get("accepted") is True)
check("Authorization is explicitly DRY_RUN_ONLY", auth.get("authorization") == "DRY_RUN_ONLY")
check("Token is single-use", auth.get("single_use") is True)
check("Token has expiry", auth.get("expires_at", 0) > auth.get("issued_at", 0))
check("Real-world effect is false", auth.get("real_world_effect") is False)
check("Legacy SafetyCore privileged path remains DENY", safety.evaluate("PROCESS_TERMINATE")["decision"] == "DENY")

sim = gateway.execute_dry_run(auth, request=request)
check("Action Gateway accepts valid dry-run capability", sim.get("accepted") is True)
check("Action was NOT executed", sim.get("executed") is False)
check("Simulation occurred", sim.get("simulated") is True)
check("Real-world effect remains false", sim.get("real_world_effect") is False)
check("No-op executor used", sim.get("executor") == "NO_OP_DRY_RUN_EXECUTOR")

replay = gateway.execute_dry_run(auth, request=request)
check("Token replay is rejected", replay.get("accepted") is False)
check("Replay stays fail-closed", replay.get("fail_closed") is True)

# Scope escape: fresh authorization, modified target must fail.
auth2 = gate.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=safety)
check("Second valid token issued", auth2.get("accepted") is True)
mutated = dict(request)
mutated["target"] = "pid:9999"
scope_reject = gateway.execute_dry_run(auth2, request=mutated)
check("Scope escape rejected", scope_reject.get("accepted") is False)
check("Scope escape is fail-closed", scope_reject.get("fail_closed") is True)

# Tampered authorization metadata must not execute.
tampered = dict(auth2)
tampered["real_world_effect"] = True
tampered_result = gateway.execute_dry_run(tampered, request=request)
check("Tampered authorization rejected", tampered_result.get("accepted") is False)
check("Tampered authorization cannot execute", tampered_result.get("executed") is False)

# Token MAC tampering must be rejected.
auth_mac = gate.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=SafetyCore())
check("MAC-protected token issued", auth_mac.get("accepted") is True)
tampered_mac = dict(auth_mac)
tampered_mac["token_mac"] = "0" * 64
mac_result = gateway.execute_dry_run(tampered_mac, request=request)
check("Token MAC tampering rejected", mac_result.get("accepted") is False)
check("Token MAC tampering cannot execute", mac_result.get("executed") is False)

# Safety state must block new authorization.
safety.enter_safe_mode("adversarial-test")
blocked = gate.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=safety)
check("Safe Mode blocks authorization", blocked.get("accepted") is False)
check("Safe Mode denial is fail-closed", blocked.get("fail_closed") is True)

# Shutdown must block new authorization.
safety2 = SafetyCore()
safety2.request_shutdown()
gate2 = SafetyAuthorizationGate()
blocked_shutdown = gate2.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=safety2)
check("Shutdown blocks authorization", blocked_shutdown.get("accepted") is False)
check("Shutdown denial is fail-closed", blocked_shutdown.get("fail_closed") is True)

# L6/destructive class is never self-authorized in v1.
request_l6 = dict(request)
request_l6["requested_action"] = "BOOT_MODIFY"
risk_l6 = dict(risk)
risk_l6["assessments"] = [dict(risk["assessments"][0], requested_action="BOOT_MODIFY")]
policy_l6 = policy_engine.evaluate(risk_l6, safety=SafetyCore())
verified_l6 = verifier.verify(risk_l6, policy_l6, safety=SafetyCore())
# Even if policy/verifier contract says verification is required, v1 gate remains dry-run and must reject this destructive class.
request_l6["decision_digest"] = verified_l6["assessments"][0]["decision_digest"]
blocked_l6 = gate2.authorize_dry_run(request_l6, policy_result=policy_l6, verification_result=verified_l6, safety=SafetyCore())
check("Destructive L6-class action is denied", blocked_l6.get("accepted") is False)

# TTL: use a very short gate.
short_gate = SafetyAuthorizationGate(ttl_seconds=0.01)
short_auth = short_gate.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=SafetyCore())
check("Short-TTL authorization issued", short_auth.get("accepted") is True)
time.sleep(0.03)
expired = short_gate.consume(short_auth["token_id"], request=request)
check("Expired token rejected", expired.get("accepted") is False)
check("Expired token fail-closed", expired.get("fail_closed") is True)

# Single-use concurrency: exactly one of two concurrent consumers may succeed.
import threading
concurrent_gate = SafetyAuthorizationGate(ttl_seconds=5)
concurrent_gateway = ActionGateway(concurrent_gate)
concurrent_auth = concurrent_gate.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=SafetyCore())
results = []
lock = threading.Lock()
def consume_once() -> None:
    out = concurrent_gateway.execute_dry_run(concurrent_auth, request=request)
    with lock:
        results.append(out.get("accepted") is True)
threads = [threading.Thread(target=consume_once) for _ in range(2)]
[t.start() for t in threads]
[t.join() for t in threads]
check("Concurrent single-use token has exactly one success", results.count(True) == 1)
check("Concurrent second use is rejected", results.count(False) == 1)

# The dry-run gateway must not invoke process/system execution APIs.
import os as _os
import subprocess as _subprocess
_orig_system = _os.system
_orig_run = _subprocess.run
_orig_popen = _subprocess.Popen
def _forbidden(*args, **kwargs):
    raise AssertionError("real execution API invoked")
_os.system = _forbidden
_subprocess.run = _forbidden
_subprocess.Popen = _forbidden
try:
    no_op_auth = gate.authorize_dry_run(request, policy_result=policy, verification_result=verified, safety=SafetyCore())
    no_op = gateway.execute_dry_run(no_op_auth, request=request)
    check("No real execution API invoked", no_op.get("accepted") is True)
finally:
    _os.system = _orig_system
    _subprocess.run = _orig_run
    _subprocess.Popen = _orig_popen

print("\nGATE STATS")
print(gate.get_stats())
print("\nGATEWAY STATS")
print(gateway.get_stats())
print("\nRESULT: PASS")
