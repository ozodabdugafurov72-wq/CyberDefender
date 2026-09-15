from __future__ import annotations

"""CyberDefender v6 Security Constitution.

These are architecture invariants, not runtime permissions.  This module is
pure data/validation and has no OS side effects.
"""

from dataclasses import dataclass, asdict
from typing import Final


@dataclass(frozen=True, slots=True)
class SecurityInvariant:
    invariant_id: str
    name: str
    statement: str
    enforcement: str
    fail_closed: bool = True


SECURITY_CONSTITUTION_VERSION: Final[str] = "6.0"

SECURITY_CONSTITUTION: Final[tuple[SecurityInvariant, ...]] = (
    SecurityInvariant("C-01", "ZERO_IMPLICIT_TRUST", "No component, source, identity, model, dashboard, cloud command, plugin, update, or peer is trusted merely because it is present or reachable.", "Authenticate, validate, scope, and authorize at every trust boundary."),
    SecurityInvariant("C-02", "RISK_NOT_AUTHORIZATION", "A risk score or severity is evidence for policy; it is never permission to act.", "Risk output cannot issue or consume an execution capability."),
    SecurityInvariant("C-03", "AI_NOT_AUTHORITY", "AI output is advisory and can never directly authorize or execute a privileged OS action.", "AI must terminate at a structured recommendation boundary before policy/verification/safety."),
    SecurityInvariant("C-04", "MANAGEMENT_NOT_EXECUTION", "Owner, Admin, SOC, dashboards, and management APIs are not privileged executors.", "Management requests must pass Command Gateway -> Policy -> Verification -> Local Safety -> Capability."),
    SecurityInvariant("C-05", "CLOUD_NOT_LOCAL_SAFETY_AUTHORITY", "Cloud or regional control cannot bypass the endpoint-local Safety Core.", "Every remote command is re-authorized at the local enforcement boundary."),
    SecurityInvariant("C-06", "FAIL_CLOSED_PRIVILEGED", "Uncertainty, missing trust evidence, invalid policy, stale authorization, or verifier failure denies privileged action.", "Privileged action defaults to DENY/NO_ACTION."),
    SecurityInvariant("C-07", "LOCAL_CONTINUITY", "Loss of cloud, AI, or optional remote services must not silently disable minimum local protection.", "Endpoint retains bounded local observation/detection/safety behavior."),
    SecurityInvariant("C-08", "BOUNDED_CAPABILITY", "Any future privileged action must be narrowly scoped, short-lived, single-use, and target-bound.", "Capability binds action, target, endpoint, tenant, evidence/policy digest, nonce, and expiry."),
    SecurityInvariant("C-09", "ATTRIBUTABLE_ACTION", "Every requested and executed security action must be attributable and auditable regardless of outcome.", "Record requester identity, policy version, capability ID, evidence digest, result, and verifier outcome."),
    SecurityInvariant("C-10", "INDEPENDENT_OUTCOME_VERIFICATION", "An executor cannot be the sole authority declaring its own action successful.", "Use independent post-action evidence and fail closed on uncertainty."),
    SecurityInvariant("C-11", "TENANT_ISOLATION", "Tenant identity and scope are mandatory across identity, events, storage, graph, policy, capabilities, and audit.", "Cross-tenant access is denied by default and cannot depend only on query filters."),
    SecurityInvariant("C-12", "NO_SELF_PROMOTION", "A compromised sensor, node, model, or service cannot promote itself to a higher authority role.", "Authority is externally configured, pinned, and independently observable."),
    SecurityInvariant("C-13", "SIGNED_SUPPLY_CHAIN", "An update or component is not trusted until provenance and cryptographic release policy are satisfied.", "Verify release metadata/signature before activation; fail/rollback atomically."),
    SecurityInvariant("C-14", "RECOVERY_REQUIRES_REATTESTATION", "Recovered does not automatically mean trusted.", "Restore trust only after integrity checks, required re-attestation, policy sync, and verification."),
    SecurityInvariant("C-15", "EVIDENCE_PRESERVATION", "Containment and recovery preserve forensic evidence whenever safety permits.", "Hash, retain, and link evidence to incident/action lineage."),
    SecurityInvariant("C-16", "LEARNING_NO_DIRECT_PROMOTION", "Telemetry, AI, or learned candidates cannot directly change production policy/rules/models.", "Candidate -> offline evaluation -> regression/adversarial tests -> canary -> signed promotion."),
)


def validate_constitution() -> None:
    ids = [item.invariant_id for item in SECURITY_CONSTITUTION]
    names = [item.name for item in SECURITY_CONSTITUTION]
    if len(ids) != len(set(ids)):
        raise RuntimeError("duplicate v6 constitution invariant id")
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate v6 constitution invariant name")
    if ids != [f"C-{index:02d}" for index in range(1, len(ids) + 1)]:
        raise RuntimeError("v6 constitution ids must be contiguous")
    if not all(item.fail_closed for item in SECURITY_CONSTITUTION):
        raise RuntimeError("v6 constitution invariant unexpectedly not fail-closed")


def constitution_snapshot() -> dict:
    validate_constitution()
    return {
        "component": "SecurityConstitution",
        "version": SECURITY_CONSTITUTION_VERSION,
        "invariants": [asdict(item) for item in SECURITY_CONSTITUTION],
        "fail_closed": True,
        "runtime_authority": "NONE",
    }


validate_constitution()
