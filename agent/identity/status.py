from __future__ import annotations

"""Read-model status for v6 Phase 1 identity foundation."""

from .binding import verify_device_workload_binding
from .contracts import DeviceIdentity, WorkloadIdentity, content_digest_sha256


def identity_foundation_snapshot(device: DeviceIdentity, workloads: tuple[WorkloadIdentity, ...]) -> dict:
    device.validate()
    workload_rows = []
    all_bound = True
    for workload in workloads:
        decision = verify_device_workload_binding(device, workload)
        all_bound = all_bound and decision.binding_valid
        workload_rows.append({
            "role": workload.role.value,
            "workload_identity_id": workload.workload_identity_id,
            "device_generation": workload.device_generation,
            "runtime_plane": workload.runtime_plane,
            "security_plane": workload.security_plane,
            "scope_kind": workload.scope_kind.value,
            "tenant_id": workload.tenant_id,
            "enrollment_id": workload.enrollment_id,
            "provenance": workload.provenance.value,
            "trust_state": workload.trust_state.value,
            "auth_state": workload.auth_state.value,
            "binding_valid": decision.binding_valid,
            "binding_reason": decision.reason,
            "content_digest_sha256": content_digest_sha256(workload),
        })
    return {
        "component": "V6IdentityFoundation",
        "version": "1.1",
        "schema_version": device.schema_version,
        "device_identity_id": device.device_identity_id,
        "endpoint_id": device.endpoint_id,
        "device_generation": device.generation,
        "scope_kind": device.scope_kind.value,
        "tenant_id": device.tenant_id,
        "enrollment_id": device.enrollment_id,
        "device_provenance": device.provenance.value,
        "device_trust_state": device.trust_state.value,
        "device_assurance": device.assurance.value,
        "device_content_digest_sha256": content_digest_sha256(device),
        "workloads": workload_rows,
        "all_bindings_valid": all_bound,
        "identity_is_authorization": False,
        "privileged_authorization_eligible": False,
        "persistent_identity_implemented": False,
        "enterprise_enrollment_ownership_implemented": False,
        "attestation_implemented": False,
        "cryptographic_workload_authentication_implemented": False,
        "trust_transition_authority_implemented": False,
        "runtime_authority": "NONE",
    }
