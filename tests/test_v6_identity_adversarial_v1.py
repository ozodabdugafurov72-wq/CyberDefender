from __future__ import annotations

from dataclasses import replace

from agent.identity import (
    DeviceIdentity,
    IDENTITY_SCHEMA_VERSION,
    IdentityAssurance,
    IdentityContractError,
    IdentityProvenance,
    ScopeKind,
    TrustState,
    WorkloadAuthState,
    WorkloadIdentity,
    WorkloadIdentityProvenance,
    WorkloadRole,
    build_local_device_identity,
    build_local_workload_identity,
    evaluate_phase1_trust_transition,
    verify_device_workload_binding,
)


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def expect_contract_error(fn, message):
    try:
        fn()
    except IdentityContractError:
        print(f"PASS | {message}")
        return
    raise AssertionError(message)


def tenant_pair():
    device = DeviceIdentity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        device_identity_id="44444444-4444-4444-8444-444444444444",
        endpoint_id="endpoint-enterprise-01",
        scope_kind=ScopeKind.TENANT_BOUND,
        tenant_id="tenant-alpha",
        enrollment_id="55555555-5555-4555-8555-555555555555",
        provenance=IdentityProvenance.ENTERPRISE_ENROLLMENT,
        assurance=IdentityAssurance.ENROLLED,
        trust_state=TrustState.RESTRICTED,
        attestation_id=None,
        generation=7,
        authority="NONE",
    )
    device.validate()
    workload = WorkloadIdentity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        workload_identity_id="66666666-6666-4666-8666-666666666666",
        role=WorkloadRole.AGENT,
        device_identity_id=device.device_identity_id,
        device_generation=device.generation,
        endpoint_id=device.endpoint_id,
        scope_kind=ScopeKind.TENANT_BOUND,
        tenant_id=device.tenant_id,
        enrollment_id=device.enrollment_id,
        provenance=WorkloadIdentityProvenance.TENANT_ENROLLMENT_DERIVED,
        runtime_plane="DATA_PLANE",
        security_plane="ENDPOINT_TCB",
        auth_state=WorkloadAuthState.DECLARED_ONLY,
        trust_state=TrustState.RESTRICTED,
        generation=2,
        authority="NONE",
    )
    workload.validate()
    return device, workload


def main():
    device = build_local_device_identity(
        "endpoint-local-01",
        device_identity_id="11111111-1111-4111-8111-111111111111",
    )
    agent = build_local_workload_identity(
        device,
        WorkloadRole.AGENT,
        workload_identity_id="22222222-2222-4222-8222-222222222222",
    )

    expect_contract_error(lambda: replace(device, authority="EXECUTE").validate(), "authority smuggling in device identity is rejected")
    expect_contract_error(lambda: replace(agent, authority="ADMIN").validate(), "authority smuggling in workload identity is rejected")
    expect_contract_error(lambda: replace(agent, runtime_plane="EXECUTION_PLANE").validate(), "workload cannot rewrite its canonical runtime plane")
    expect_contract_error(lambda: replace(agent, security_plane="DECISION_RESPONSE").validate(), "workload cannot rewrite its canonical security plane")
    expect_contract_error(lambda: replace(device, assurance=IdentityAssurance.ATTESTED, attestation_id="88888888-8888-4888-8888-888888888888").validate(), "device cannot self-declare attestation")
    expect_contract_error(lambda: replace(device, trust_state=TrustState.TRUSTED).validate(), "device cannot self-promote to TRUSTED")
    expect_contract_error(lambda: replace(agent, auth_state=WorkloadAuthState.CRYPTO_AUTHENTICATED).validate(), "workload cannot self-declare cryptographic authentication")
    expect_contract_error(lambda: replace(agent, trust_state=TrustState.TRUSTED).validate(), "workload cannot self-promote to TRUSTED")

    tenant_device, tenant_agent = tenant_pair()
    check(verify_device_workload_binding(tenant_device, tenant_agent).binding_valid, "valid tenant-bound identity pair is consistent")

    cross_tenant = replace(tenant_agent, tenant_id="tenant-beta")
    check(not verify_device_workload_binding(tenant_device, cross_tenant).binding_valid, "cross-tenant substitution is rejected")
    cross_endpoint = replace(tenant_agent, endpoint_id="endpoint-other")
    check(not verify_device_workload_binding(tenant_device, cross_endpoint).binding_valid, "cross-endpoint substitution is rejected")
    cross_device = replace(tenant_agent, device_identity_id="77777777-7777-4777-8777-777777777777")
    check(not verify_device_workload_binding(tenant_device, cross_device).binding_valid, "cross-device substitution is rejected")
    stale_generation = replace(tenant_agent, device_generation=tenant_device.generation - 1)
    check(not verify_device_workload_binding(tenant_device, stale_generation).binding_valid, "stale device-generation binding is rejected")
    cross_enrollment = replace(tenant_agent, enrollment_id="99999999-9999-4999-8999-999999999999")
    check(not verify_device_workload_binding(tenant_device, cross_enrollment).binding_valid, "cross-enrollment substitution is rejected")
    revoked_device = replace(tenant_device, trust_state=TrustState.REVOKED)
    check(not verify_device_workload_binding(revoked_device, tenant_agent).binding_valid, "revoked device binding is rejected")
    revoked_workload = replace(tenant_agent, trust_state=TrustState.REVOKED)
    check(not verify_device_workload_binding(tenant_device, revoked_workload).binding_valid, "revoked workload binding is rejected")

    expect_contract_error(lambda: replace(device, tenant_id="tenant-alpha").validate(), "local identity cannot inject tenant membership")
    expect_contract_error(lambda: replace(tenant_device, tenant_id=None).validate(), "tenant-bound identity requires tenant id")
    expect_contract_error(lambda: replace(tenant_device, enrollment_id=None).validate(), "tenant-bound identity requires enrollment id")
    expect_contract_error(lambda: replace(tenant_device, assurance=IdentityAssurance.DECLARED).validate(), "tenant-bound identity cannot downgrade enrollment assurance semantics")
    expect_contract_error(lambda: replace(agent, tenant_id="tenant-alpha").validate(), "local workload cannot inject tenant membership")
    expect_contract_error(lambda: replace(tenant_agent, enrollment_id=None).validate(), "tenant-bound workload requires enrollment binding")

    expect_contract_error(lambda: replace(device, endpoint_id="../../escape").validate(), "path-like endpoint identifier is rejected")
    expect_contract_error(lambda: replace(device, endpoint_id=" endpoint-local-01").validate(), "non-canonical whitespace identifier is rejected")
    expect_contract_error(lambda: replace(device, device_identity_id="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").validate(), "non-canonical UUID representation is rejected")
    expect_contract_error(lambda: replace(device, generation=True).validate(), "boolean identity generation is rejected")
    expect_contract_error(lambda: replace(agent, generation=True).validate(), "boolean workload generation is rejected")

    payload = device.to_dict()
    payload["may_execute_real_world"] = True
    expect_contract_error(lambda: DeviceIdentity.from_dict(payload), "unknown execution-authority field injection is rejected")

    payload = device.to_dict()
    payload["generation"] = "1"
    expect_contract_error(lambda: DeviceIdentity.from_dict(payload), "coercive string generation is rejected")

    workload_payload = agent.to_dict()
    workload_payload["runtime_plane"] = "EXECUTION_PLANE"
    expect_contract_error(lambda: WorkloadIdentity.from_dict(workload_payload), "serialized plane escalation is rejected")

    workload_payload = agent.to_dict()
    workload_payload["role"] = "PrivilegedExecutor"
    expect_contract_error(lambda: WorkloadIdentity.from_dict(workload_payload), "unknown privileged workload role is rejected")

    malformed_direct = replace(agent, role="CyberDefenderAgent")
    check(not verify_device_workload_binding(device, malformed_direct).binding_valid, "direct-constructor type confusion fails closed at binding boundary")

    transition = evaluate_phase1_trust_transition(TrustState.RESTRICTED, TrustState.TRUSTED)
    check(not transition.allowed, "trust-promotion request is denied without transition authority")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
