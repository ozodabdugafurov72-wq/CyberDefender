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


def build_runtime() -> CyberDefenderRuntime:
    safety = SafetyCore()
    return CyberDefenderRuntime(safety, load_config())


print("CYBERDEFENDER — SAFETY AUTHORIZATION + ACTION GATEWAY ADVERSARIAL MAIN TEST")
print("=" * 78)
old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
os.environ["CYBERDEFENDER_STATE_DIR"] = tempfile.mkdtemp(prefix="cd-scag-adv-")
os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(b"A" * 32).decode()

try:
    runtime = build_runtime()
    safety = runtime.safety
    risk = {
        "component": "RiskEngine", "version": "1.0", "accepted": True,
        "overall_risk_score": 90, "overall_risk_level": "CRITICAL",
        "assessments": [{"incident_id": "INC-ADV-SCAG-001", "risk_score": 90,
                         "risk_level": "CRITICAL", "requested_action": "PROCESS_TERMINATE"}],
        "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
    }
    runtime.last_risk_result = risk
    policy = runtime.update_policy()
    verified = runtime.update_verification()
    digest = verified["assessments"][0]["decision_digest"]
    request = {
        "incident_id": "INC-ADV-SCAG-001", "requester": "adversarial-test",
        "requested_action": "PROCESS_TERMINATE", "target": "pid:1111",
        "evidence_ref": "evidence://INC-ADV-SCAG-001", "decision_digest": digest,
        "execution_mode": "DRY_RUN",
    }
    check("Baseline verification passes", verified.get("verified") is True)

    # 1. Authorization smuggling through policy.
    tampered_policy = dict(policy)
    tampered_policy["authorization"] = "GRANTED"
    runtime.last_policy_result = tampered_policy
    denied = runtime.authorize_dry_run(request)
    check("Authorization smuggling rejected", denied.get("accepted") is False)
    check("Authorization smuggling remains NOT_GRANTED", denied.get("authorization") == "NOT_GRANTED")

    # Restore trusted policy.
    runtime.last_policy_result = policy
    fresh = runtime.authorize_dry_run(request)
    check("Trusted policy authorizes dry-run", fresh.get("accepted") is True)

    # 2. Scope escape.
    escaped = dict(request, target="pid:2222")
    result = runtime.execute_dry_run(fresh, request=escaped)
    check("Scope escape rejected", result.get("accepted") is False)
    check("Scope escape cannot execute", result.get("executed") is False)

    # 3. Token replay.
    first = runtime.execute_dry_run(runtime.authorize_dry_run(request), request=request)
    check("First single-use execution simulation succeeds", first.get("accepted") is True)
    replay_auth = runtime.last_authorization_result
    # replay_auth is now a fresh auth, because execute consumed its token but last result stores it.
    replay = runtime.execute_dry_run(replay_auth, request=request)
    check("Token replay rejected", replay.get("accepted") is False)
    check("Token replay fail-closed", replay.get("fail_closed") is True)

    # 4. SafetyCore safe mode.
    safety.enter_safe_mode("adversarial-safe-mode")
    blocked = runtime.authorize_dry_run(request)
    check("Safe Mode blocks new authorization", blocked.get("accepted") is False)
    check("Safe Mode remains fail-closed", blocked.get("fail_closed") is True)

    # 5. SafetyCore shutdown.
    runtime2 = build_runtime()
    runtime2.safety.request_shutdown()
    runtime2.last_risk_result = risk
    p2 = runtime2.update_policy()
    v2 = runtime2.update_verification()
    req2 = dict(request, decision_digest=v2["assessments"][0]["decision_digest"])
    shut = runtime2.authorize_dry_run(req2)
    check("Shutdown blocks authorization", shut.get("accepted") is False)
    check("Shutdown remains fail-closed", shut.get("fail_closed") is True)

    # 6. Malformed-request flood.
    runtime3 = build_runtime()
    runtime3.last_risk_result = risk
    p3 = runtime3.update_policy()
    v3 = runtime3.update_verification()
    for i in range(25):
        malformed = {"incident_id": "INC-ADV-SCAG-001", "execution_mode": "DRY_RUN"}
        out = runtime3.authorize_dry_run(malformed)
        check(f"Malformed request {i + 1} rejected", out.get("accepted") is False)
    gh = runtime3.authorization_gate.health_check()
    check("Gate remains fail-closed after malformed flood", gh.get("fail_closed") is True)
    check("Gate has no unexpected internal failure", gh.get("failed") == 0)

    # 7. ActionGateway cannot be used without a real dry-run capability.
    fake = runtime3.execute_dry_run({"authorization": "GRANTED", "token_id": "fake"}, request=request)
    check("Forged authorization rejected", fake.get("accepted") is False)
    check("Forged authorization cannot execute", fake.get("executed") is False)

    # 8. No subprocess/executor surface is exposed.
    gateway_health = runtime3.action_gateway.health_check()
    check("Gateway explicitly declares no real-world effect", gateway_health.get("real_world_effect") is False)
    check("Gateway explicitly declares dry-run only", gateway_health.get("dry_run_only") is True)

    # 9. Runtime overall health is preserved.
    check("Runtime remains HEALTHY", runtime3.health_snapshot()["runtime"]["status"] == "HEALTHY")

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
