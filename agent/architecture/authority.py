from __future__ import annotations

"""CyberDefender v6 authority matrix.

The matrix captures CURRENT authority, not future aspirations.  It is
intentionally conservative: the current release has no real-world privileged
executor and no component in this matrix is permitted to claim one.
"""

from dataclasses import dataclass, asdict
from enum import Enum
from types import MappingProxyType
from typing import Final, Mapping


class SecurityPlane(str, Enum):
    TRUST_FOUNDATION = "TRUST_FOUNDATION"
    ENDPOINT_TCB = "ENDPOINT_TCB"
    TELEMETRY_EVIDENCE = "TELEMETRY_EVIDENCE"
    XDR_INTELLIGENCE = "XDR_INTELLIGENCE"
    DECISION_RESPONSE = "DECISION_RESPONSE"
    DISTRIBUTED_CONTROL_RECOVERY = "DISTRIBUTED_CONTROL_RECOVERY"


class RuntimePlane(str, Enum):
    DATA = "DATA_PLANE"
    CONTROL = "CONTROL_PLANE"
    MANAGEMENT = "MANAGEMENT_PLANE"
    EXECUTION = "EXECUTION_PLANE"


@dataclass(frozen=True, slots=True)
class AuthorityProfile:
    component: str
    security_plane: SecurityPlane
    runtime_plane: RuntimePlane
    may_observe: bool = False
    may_analyze: bool = False
    may_recommend: bool = False
    may_govern_policy: bool = False
    may_verify_pre_action: bool = False
    may_issue_dry_run_capability: bool = False
    may_execute_dry_run: bool = False
    may_execute_real_world: bool = False
    may_verify_post_action: bool = False
    may_restore_trust: bool = False
    notes: str = ""


_PROFILES = {
    "ProcessSensor": AuthorityProfile("ProcessSensor", SecurityPlane.ENDPOINT_TCB, RuntimePlane.DATA, may_observe=True, notes="Python ProcessSensor is current authoritative process telemetry source; Rust canary is non-authoritative."),
    "RustProcessCanary": AuthorityProfile("RustProcessCanary", SecurityPlane.ENDPOINT_TCB, RuntimePlane.DATA, may_observe=True, notes="Shadow/canary evidence only; cannot self-promote."),
    "SystemObserver": AuthorityProfile("SystemObserver", SecurityPlane.ENDPOINT_TCB, RuntimePlane.DATA, may_observe=True),
    "CryptoReplayAdmissionGateway": AuthorityProfile("CryptoReplayAdmissionGateway", SecurityPlane.TRUST_FOUNDATION, RuntimePlane.DATA, may_observe=True, notes="Admits/rejects event trust; no OS authority."),
    "DurableEventPipeline": AuthorityProfile("DurableEventPipeline", SecurityPlane.TELEMETRY_EVIDENCE, RuntimePlane.DATA, may_observe=True),
    "DetectionEngine": AuthorityProfile("DetectionEngine", SecurityPlane.XDR_INTELLIGENCE, RuntimePlane.DATA, may_observe=True, may_analyze=True),
    "CorrelationEngine": AuthorityProfile("CorrelationEngine", SecurityPlane.XDR_INTELLIGENCE, RuntimePlane.DATA, may_observe=True, may_analyze=True),
    "ProcessGraph": AuthorityProfile("ProcessGraph", SecurityPlane.XDR_INTELLIGENCE, RuntimePlane.DATA, may_observe=True, may_analyze=True),
    "AttackGraph": AuthorityProfile("AttackGraph", SecurityPlane.XDR_INTELLIGENCE, RuntimePlane.DATA, may_observe=True, may_analyze=True),
    "RiskEngine": AuthorityProfile("RiskEngine", SecurityPlane.XDR_INTELLIGENCE, RuntimePlane.DATA, may_observe=True, may_analyze=True, notes="Risk != authorization."),
    "AIGateway": AuthorityProfile("AIGateway", SecurityPlane.XDR_INTELLIGENCE, RuntimePlane.CONTROL, may_observe=True, may_analyze=True, may_recommend=True, notes="Target/advisory only; no current privileged authority."),
    "PolicyEngine": AuthorityProfile("PolicyEngine", SecurityPlane.DECISION_RESPONSE, RuntimePlane.CONTROL, may_observe=True, may_analyze=True, may_govern_policy=True, notes="Policy governs eligibility; it does not grant execution authority."),
    "IndependentVerifier": AuthorityProfile("IndependentVerifier", SecurityPlane.DECISION_RESPONSE, RuntimePlane.CONTROL, may_observe=True, may_analyze=True, may_verify_pre_action=True),
    "BlastRadiusGuard": AuthorityProfile("BlastRadiusGuard", SecurityPlane.DECISION_RESPONSE, RuntimePlane.CONTROL, may_observe=True, may_analyze=True, notes="Scope limiter only."),
    "SafetyCore": AuthorityProfile("SafetyCore", SecurityPlane.ENDPOINT_TCB, RuntimePlane.EXECUTION, may_observe=True, may_analyze=True, notes="Local fail-closed safety boundary; current implementation only tightens/denies."),
    "SafetyAuthorizationGate": AuthorityProfile("SafetyAuthorizationGate", SecurityPlane.DECISION_RESPONSE, RuntimePlane.EXECUTION, may_observe=True, may_analyze=True, may_issue_dry_run_capability=True, notes="Current v1 issues DRY_RUN_ONLY capability."),
    "ActionGateway": AuthorityProfile("ActionGateway", SecurityPlane.DECISION_RESPONSE, RuntimePlane.EXECUTION, may_observe=True, may_execute_dry_run=True, notes="NO_OP_DRY_RUN_EXECUTOR; no real OS mutation."),
    "PostActionVerifier": AuthorityProfile("PostActionVerifier", SecurityPlane.DECISION_RESPONSE, RuntimePlane.CONTROL, may_observe=True, may_analyze=True, may_verify_post_action=True, notes="Current v1 verifies dry-run/no-effect only."),
    "RecoveryPlanner": AuthorityProfile("RecoveryPlanner", SecurityPlane.DISTRIBUTED_CONTROL_RECOVERY, RuntimePlane.CONTROL, may_observe=True, may_analyze=True, notes="Planning only; recovery != trust restoration."),
    "ControlPlane": AuthorityProfile("ControlPlane", SecurityPlane.DISTRIBUTED_CONTROL_RECOVERY, RuntimePlane.CONTROL, may_observe=True, may_analyze=True, notes="Orchestration/distribution; cannot bypass local safety."),
    "OwnerUI": AuthorityProfile("OwnerUI", SecurityPlane.DISTRIBUTED_CONTROL_RECOVERY, RuntimePlane.MANAGEMENT, may_observe=True, notes="Management/read model; no direct OS authority."),
    "AdminUI": AuthorityProfile("AdminUI", SecurityPlane.DISTRIBUTED_CONTROL_RECOVERY, RuntimePlane.MANAGEMENT, may_observe=True, notes="Management/read model; no direct OS authority."),
    "FamilyMeshNode": AuthorityProfile("FamilyMeshNode", SecurityPlane.DISTRIBUTED_CONTROL_RECOVERY, RuntimePlane.CONTROL, may_observe=True, notes="Target only; explicit consent and no transitive authority."),
}

AUTHORITY_MATRIX: Final[Mapping[str, AuthorityProfile]] = MappingProxyType(_PROFILES)


def validate_authority_matrix() -> None:
    if not AUTHORITY_MATRIX:
        raise RuntimeError("v6 authority matrix is empty")
    for name, profile in AUTHORITY_MATRIX.items():
        if name != profile.component:
            raise RuntimeError(f"authority matrix key mismatch: {name}")
        if profile.may_execute_real_world:
            raise RuntimeError(f"current v6 baseline must not expose real-world execution: {name}")
    for forbidden in ("OwnerUI", "AdminUI", "AIGateway", "RiskEngine", "DetectionEngine", "CorrelationEngine"):
        profile = AUTHORITY_MATRIX[forbidden]
        if profile.may_issue_dry_run_capability or profile.may_execute_dry_run or profile.may_execute_real_world:
            raise RuntimeError(f"authority leakage: {forbidden}")
    if AUTHORITY_MATRIX["PolicyEngine"].may_issue_dry_run_capability:
        raise RuntimeError("PolicyEngine must not issue capability")
    if not AUTHORITY_MATRIX["SafetyAuthorizationGate"].may_issue_dry_run_capability:
        raise RuntimeError("current dry-run capability issuer missing")
    if not AUTHORITY_MATRIX["ActionGateway"].may_execute_dry_run:
        raise RuntimeError("current dry-run executor contract missing")


def authority_snapshot() -> dict:
    validate_authority_matrix()
    rows = []
    for name in sorted(AUTHORITY_MATRIX):
        row = asdict(AUTHORITY_MATRIX[name])
        row["security_plane"] = AUTHORITY_MATRIX[name].security_plane.value
        row["runtime_plane"] = AUTHORITY_MATRIX[name].runtime_plane.value
        rows.append(row)
    return {
        "component": "V6AuthorityMatrix",
        "version": "6.0",
        "profiles": rows,
        "real_world_executor_present": False,
        "fail_closed": True,
    }


validate_authority_matrix()
