from __future__ import annotations

from agent.independent_verifier import IndependentVerifier
from agent.safety import SafetyCore


def check(label: str, condition: bool) -> None:
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)


def make_pair(score=85, level="CRITICAL", action="OBSERVE_ONLY", outcome="REQUIRE_VERIFICATION"):
    risk_item = {
        "incident_id": "INC-IV-001", "risk_score": score, "risk_level": level,
        "requested_action": action,
    }
    policy_item = {
        "incident_id": "INC-IV-001", "risk_score": score, "risk_level": level,
        "requested_action": action, "policy_outcome": outcome,
        "policy_reason": "HIGH_RISK_REQUIRES_VERIFICATION",
        "recommendation": "ESCALATE_TO_INDEPENDENT_VERIFICATION",
        "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
        "requires_independent_verification": outcome == "REQUIRE_VERIFICATION",
        "safe_mode": False, "shutdown_requested": False,
    }
    return {"assessments": [risk_item]}, {"assessments": [policy_item]}


print("CYBERDEFENDER — INDEPENDENT VERIFIER v1 FOCUSED + ADVERSARIAL TEST")
print("=" * 72)

v = IndependentVerifier()
safety = SafetyCore()
risk, policy = make_pair()
r = v.verify(risk, policy, safety=safety)
check("Fresh verifier HEALTHY", v.health_check()["status"] == "HEALTHY")
check("Valid decision accepted", r.get("accepted") is True)
check("Valid decision verified", r.get("verified") is True)
check("Verification outcome VERIFIED", r.get("verification_outcome") == "VERIFIED")
check("One assessment verified", r.get("assessments_verified") == 1)
check("Authorization remains NOT_GRANTED", r.get("authorization") == "NOT_GRANTED")
check("Action remains OBSERVE_ONLY", r.get("action") == "OBSERVE_ONLY")
check("Decision digest exists", isinstance(r["assessments"][0].get("decision_digest"), str) and len(r["assessments"][0]["decision_digest"]) == 64)
check("Digest is deterministic", v.verify(risk, policy, safety=safety)["assessments"][0]["decision_digest"] == r["assessments"][0]["decision_digest"])

# Safety invariants.
safe = SafetyCore(); safe.enter_safe_mode("test")
risk2, policy2 = make_pair(score=95, level="CRITICAL")
policy2["assessments"][0]["policy_outcome"] = "DENY"
policy2["assessments"][0]["policy_reason"] = "SAFETY_CORE_SAFE_MODE"
policy2["assessments"][0]["recommendation"] = "NO_ACTION"
policy2["assessments"][0]["requires_independent_verification"] = False
policy2["assessments"][0]["safe_mode"] = True
r2 = v.verify(risk2, policy2, safety=safe)
check("Safe mode decision verified", r2.get("verified") is True)
check("Safe mode stays fail-closed", r2["assessments"][0]["policy_outcome"] == "DENY")

shutdown = SafetyCore(); shutdown.request_shutdown()
policy3 = make_pair(score=95, level="CRITICAL")[1]
policy3["assessments"][0].update({"policy_outcome":"DENY", "policy_reason":"SAFETY_CORE_SHUTDOWN_REQUESTED", "recommendation":"NO_ACTION", "requires_independent_verification":False, "shutdown_requested":True})
r3 = v.verify(make_pair(score=95, level="CRITICAL")[0], policy3, safety=shutdown)
check("Shutdown decision verified", r3.get("verified") is True)
check("Shutdown stays fail-closed", r3["assessments"][0]["policy_outcome"] == "DENY")

# Mismatch / tamper tests.
cases = []
def expect_reject(label, rr, pp, ss=safety):
    out = v.verify(rr, pp, safety=ss)
    check(label, out.get("verified") is False and out.get("verification_outcome") == "REJECTED")
    check(label + " preserves NOT_GRANTED", out.get("authorization") == "NOT_GRANTED")
    return out

rr, pp = make_pair(); pp["assessments"][0]["incident_id"] = "INC-TAMPER"
expect_reject("Incident ID mismatch rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"][0]["risk_score"] = 99
expect_reject("Risk score mismatch rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["risk_level"] = "HIGH"
expect_reject("Risk level inconsistency rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"][0]["risk_level"] = "HIGH"
expect_reject("Policy level mismatch rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"][0]["authorization"] = "GRANTED"
expect_reject("Authorization leakage rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"][0]["action"] = "PROCESS_TERMINATE"
expect_reject("Action leakage rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"][0]["policy_outcome"] = "ALLOW"
expect_reject("Unknown policy outcome rejected", rr, pp)
rr, pp = make_pair(score=50, level="MEDIUM"); pp["assessments"][0]["policy_outcome"] = "DENY"
expect_reject("Unexpected deny rejected", rr, pp)
rr, pp = make_pair(score=85, level="CRITICAL"); pp["assessments"][0]["requires_independent_verification"] = False
expect_reject("Verification bypass rejected", rr, pp)
rr, pp = make_pair(score=85, level="CRITICAL"); pp["assessments"][0]["safe_mode"] = True
expect_reject("Safety state mismatch rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"] = []
expect_reject("Risk/policy set mismatch rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"] = []
expect_reject("Policy/risk set mismatch rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["risk_score"] = 101
expect_reject("Out-of-range score rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["risk_score"] = -1
expect_reject("Negative score rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["risk_score"] = float("nan")
expect_reject("NaN score rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["risk_score"] = True
expect_reject("Boolean score rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["incident_id"] = ""
expect_reject("Empty incident ID rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["risk_level"] = "BOGUS"
expect_reject("Unknown risk level rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["risk_level"] = "HIGH"; rr["assessments"][0]["risk_score"] = 20
expect_reject("Score/level mismatch rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"][0]["recommendation"] = ""
expect_reject("Missing recommendation rejected", rr, pp)
rr, pp = make_pair(); pp["assessments"][0]["requested_action"] = "PROCESS_TERMINATE"
expect_reject("Risk/policy action mismatch rejected", rr, pp)
rr, pp = make_pair(); rr["assessments"][0]["requested_action"] = "PROCESS_TERMINATE"; pp["assessments"][0]["requested_action"] = "PROCESS_TERMINATE"; pp["assessments"][0]["policy_outcome"] = "REQUIRE_VERIFICATION"
check("Privileged action verification accepted", v.verify(rr, pp, safety=safety).get("verified") is True)

# Budget and malformed-input containment.
big = [{"incident_id": f"I-{i}", "risk_score": 1, "risk_level":"INFO", "requested_action":"OBSERVE_ONLY"} for i in range(129)]
rr = {"assessments": big}; pp = {"assessments": big.copy()}
out = v.verify(rr, pp, safety=safety)
check("Assessment budget rejected", out.get("verified") is False)
check("Budget rejection fail-closed", out.get("authorization") == "NOT_GRANTED")
check("Budget rejection does not degrade", v.health_check()["status"] == "HEALTHY")
check("Malformed top-level rejected", v.verify([], {}, safety=safety).get("verified") is False)
check("Malformed rejection fail-closed", v.verify({}, {}, safety=safety).get("authorization") == "NOT_GRANTED")
check("Unexpected dependency failure is isolated", v.verify(risk, policy, safety=object())["verified"] is False)
check("Health remains healthy after contract rejections", v.health_check()["status"] == "HEALTHY")
check("No verification failure recorded for invalid input", v.health_check()["failed"] == 0)
check("Verification counter increments only accepted batches", v.health_check()["verifications_run"] >= 3)
check("Authorization never becomes granted", v.health_check()["authorization"] == "NOT_GRANTED")
check("Post-action verification not falsely claimed", v.health_check()["post_action_verification"] is False)

print("\nFINAL STATS")
print(v.get_stats())
print("\nRESULT: PASS")
