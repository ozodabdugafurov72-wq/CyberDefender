from __future__ import annotations

from dataclasses import replace

from agent.architecture.authority import AUTHORITY_MATRIX
from agent.architecture.constitution import SECURITY_CONSTITUTION
from agent.architecture.status import V6_IMPLEMENTATION_STATUS
from agent.identity import (
    DeviceIdentity,
    IDENTITY_SCHEMA_VERSION,
    IdentityAssurance,
    IdentityProvenance,
    ScopeKind,
    TrustState,
    WorkloadAuthState,
    WorkloadIdentity,
    WorkloadIdentityProvenance,
    WorkloadRole,
    build_local_device_identity,
    build_local_workload_identity,
    canonical_identity_json,
    content_digest_sha256,
    evaluate_phase1_trust_transition,
    identity_foundation_snapshot,
    privileged_identity_decision,
    verify_device_workload_binding,
)


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def main():
    device = build_local_device_identity(
        "d06ddcac-bec8-45e7-b1dc-adb622bebd16",
        device_identity_id="11111111-1111-4111-8111-111111111111",
    )
    agent = build_local_workload_identity(
        device,
        WorkloadRole.AGENT,
        workload_identity_id="22222222-2222-4222-8222-222222222222",
    )
    owner = build_local_workload_identity(
        device,
        WorkloadRole.OWNER_UI,
        workload_identity_id="33333333-3333-4333-8333-333333333333",
    )

    check(device.schema_version == IDENTITY_SCHEMA_VERSION, "identity schema is explicit and versioned")
    check(device.scope_kind is ScopeKind.LOCAL_STANDALONE, "current local device scope is explicit")
    check(device.tenant_id is None and device.enrollment_id is None, "local standalone identity invents no tenant/enrollment")
    check(device.provenance is IdentityProvenance.LEGACY_ENDPOINT_MIGRATION, "legacy endpoint provenance remains explicit")
    check(device.assurance is IdentityAssurance.DECLARED, "current device assurance is conservative")
    check(device.trust_state is TrustState.RESTRICTED, "current device does not self-promote to trusted")
    check(device.authority == "NONE", "device identity contains no authority grant")

    decision = verify_device_workload_binding(device, agent)
    check(decision.binding_valid, "agent binds to the exact device identity")
    check(not decision.privileged_authorization_eligible, "valid identity binding is not authorization")
    check(agent.device_generation == device.generation, "workload binds to exact device generation")
    check(agent.enrollment_id is None, "local workload invents no enrollment")
    check(agent.provenance is WorkloadIdentityProvenance.LOCAL_ROLE_DECLARATION, "local workload provenance is explicit")
    check(agent.auth_state is WorkloadAuthState.DECLARED_ONLY, "workload auth is declared-only in Phase 1")
    check(agent.trust_state is TrustState.RESTRICTED, "workload does not self-promote to trusted")
    check(agent.runtime_plane == "DATA_PLANE", "agent workload is bound to data plane")
    check(owner.runtime_plane == "MANAGEMENT_PLANE", "Owner UI workload is bound to management plane")
    check(owner.authority == "NONE", "Owner UI identity carries no execution authority")
    check("EXECUTOR" not in {role.name for role in WorkloadRole}, "Phase 1 defines no privileged executor workload identity")

    check(AUTHORITY_MATRIX["OwnerUI"].runtime_plane.value == owner.runtime_plane, "identity role matches canonical OwnerUI authority plane")
    check(not AUTHORITY_MATRIX["OwnerUI"].may_execute_real_world, "OwnerUI cannot execute real-world actions")
    check(not AUTHORITY_MATRIX["ProcessSensor"].may_execute_real_world, "ProcessSensor identity cannot become an executor")

    constitution_names = {item.name for item in SECURITY_CONSTITUTION}
    check("TENANT_ISOLATION" in constitution_names, "Phase 1 is anchored to tenant-isolation constitution")
    check("NO_SELF_PROMOTION" in constitution_names, "Phase 1 is anchored to no-self-promotion constitution")
    check("RISK_NOT_AUTHORIZATION" in constitution_names, "identity foundation preserves risk/authorization separation")

    check(V6_IMPLEMENTATION_STATUS["device_identity"] == "FOUNDATION_CONTRACT", "implementation map records device identity foundation")
    check(V6_IMPLEMENTATION_STATUS["workload_identity"] == "FOUNDATION_CONTRACT", "implementation map records workload identity foundation")
    check(V6_IMPLEMENTATION_STATUS["identity_runtime_integration"] == "NOT_IMPLEMENTED", "implementation map does not overclaim runtime identity integration")
    check(V6_IMPLEMENTATION_STATUS["device_attestation"] == "PLANNED", "implementation map does not overclaim attestation")

    snapshot = identity_foundation_snapshot(device, (agent, owner))
    check(snapshot["all_bindings_valid"] is True, "identity snapshot verifies all workload bindings")
    check(snapshot["identity_is_authorization"] is False, "identity snapshot explicitly denies authority equivalence")
    check(snapshot["privileged_authorization_eligible"] is False, "Phase 1 cannot authorize privileged action")
    check(snapshot["persistent_identity_implemented"] is False, "Phase 1 does not overclaim persistent v6 identity")
    check(snapshot["attestation_implemented"] is False, "Phase 1 does not overclaim attestation")
    check(snapshot["cryptographic_workload_authentication_implemented"] is False, "Phase 1 does not overclaim workload authentication")
    check(snapshot["trust_transition_authority_implemented"] is False, "Phase 1 does not overclaim trust transition authority")

    round_device = DeviceIdentity.from_dict(device.to_dict())
    round_workload = WorkloadIdentity.from_dict(agent.to_dict())
    check(round_device == device, "device identity strict serialization round-trip is exact")
    check(round_workload == agent, "workload identity strict serialization round-trip is exact")
    check(canonical_identity_json(device) == canonical_identity_json(round_device), "canonical identity serialization is stable")

    d1 = content_digest_sha256(device)
    d2 = content_digest_sha256(device)
    changed = content_digest_sha256(replace(device, generation=2))
    check(d1 == d2 and len(d1) == 64, "content digest is deterministic")
    check(changed != d1, "content digest changes when identity content changes")

    no_change = evaluate_phase1_trust_transition(TrustState.RESTRICTED, TrustState.RESTRICTED)
    promotion = evaluate_phase1_trust_transition(TrustState.RESTRICTED, TrustState.TRUSTED)
    revocation = evaluate_phase1_trust_transition(TrustState.RESTRICTED, TrustState.REVOKED)
    check(no_change.allowed, "no-op trust transition is allowed")
    check(not promotion.allowed, "Phase 1 has no trust-promotion authority")
    check(not revocation.allowed, "Phase 1 has no trust-revocation authority")

    privileged = privileged_identity_decision(device, agent)
    check(privileged.binding_valid, "privileged identity decision observes valid binding")
    check(not privileged.privileged_authorization_eligible, "Phase 1 remains fail-closed for privileged authorization")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
