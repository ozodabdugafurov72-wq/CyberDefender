from __future__ import annotations

"""Safe constructors for the current Phase 1 identity foundation.

Constructed records are deliberately RESTRICTED and non-authoritative. Phase 1
never self-promotes an endpoint or workload to TRUSTED.
"""

import uuid

from .contracts import (
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
    expected_planes_for_role,
)


def build_local_device_identity(
    endpoint_id: str,
    *,
    device_identity_id: str | None = None,
    provenance: IdentityProvenance = IdentityProvenance.LEGACY_ENDPOINT_MIGRATION,
) -> DeviceIdentity:
    obj = DeviceIdentity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        device_identity_id=device_identity_id or str(uuid.uuid4()),
        endpoint_id=endpoint_id,
        scope_kind=ScopeKind.LOCAL_STANDALONE,
        tenant_id=None,
        enrollment_id=None,
        provenance=provenance,
        assurance=IdentityAssurance.DECLARED,
        trust_state=TrustState.RESTRICTED,
        attestation_id=None,
        generation=1,
        authority="NONE",
    )
    obj.validate()
    return obj


def build_local_workload_identity(
    device: DeviceIdentity,
    role: WorkloadRole,
    *,
    workload_identity_id: str | None = None,
) -> WorkloadIdentity:
    device.validate()
    runtime_plane, security_plane = expected_planes_for_role(role)
    provenance = (
        WorkloadIdentityProvenance.LOCAL_ROLE_DECLARATION
        if device.scope_kind is ScopeKind.LOCAL_STANDALONE
        else WorkloadIdentityProvenance.TENANT_ENROLLMENT_DERIVED
    )
    obj = WorkloadIdentity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        workload_identity_id=workload_identity_id or str(uuid.uuid4()),
        role=role,
        device_identity_id=device.device_identity_id,
        device_generation=device.generation,
        endpoint_id=device.endpoint_id,
        scope_kind=device.scope_kind,
        tenant_id=device.tenant_id,
        enrollment_id=device.enrollment_id,
        provenance=provenance,
        runtime_plane=runtime_plane,
        security_plane=security_plane,
        auth_state=WorkloadAuthState.DECLARED_ONLY,
        trust_state=TrustState.RESTRICTED,
        generation=1,
        authority="NONE",
    )
    obj.validate()
    return obj


def build_local_identity_set(endpoint_id: str) -> tuple[DeviceIdentity, tuple[WorkloadIdentity, ...]]:
    device = build_local_device_identity(endpoint_id)
    workloads = tuple(build_local_workload_identity(device, role) for role in WorkloadRole)
    return device, workloads
