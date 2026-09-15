from __future__ import annotations

"""Fail-closed device/workload binding checks for CyberDefender v6 Phase 1."""

from dataclasses import dataclass

from .contracts import DeviceIdentity, TrustState, WorkloadIdentity


@dataclass(frozen=True, slots=True)
class BindingDecision:
    binding_valid: bool
    reason: str
    privileged_authorization_eligible: bool = False


def verify_device_workload_binding(device: DeviceIdentity, workload: WorkloadIdentity) -> BindingDecision:
    """Verify identity consistency only; never grants execution authorization."""
    try:
        device.validate()
        workload.validate()
    except Exception:
        # Security boundary: malformed identity must fail closed. Detailed parser
        # errors are available at the contract boundary; this decision never
        # turns an unexpected validation error into authority.
        return BindingDecision(False, "IDENTITY_CONTRACT_INVALID", False)

    if device.trust_state is TrustState.REVOKED or workload.trust_state is TrustState.REVOKED:
        return BindingDecision(False, "IDENTITY_REVOKED", False)
    if workload.device_identity_id != device.device_identity_id:
        return BindingDecision(False, "DEVICE_IDENTITY_MISMATCH", False)
    if workload.device_generation != device.generation:
        return BindingDecision(False, "DEVICE_GENERATION_MISMATCH", False)
    if workload.endpoint_id != device.endpoint_id:
        return BindingDecision(False, "ENDPOINT_BINDING_MISMATCH", False)
    if workload.scope_kind is not device.scope_kind:
        return BindingDecision(False, "SCOPE_KIND_MISMATCH", False)
    if workload.tenant_id != device.tenant_id:
        return BindingDecision(False, "TENANT_BINDING_MISMATCH", False)
    if workload.enrollment_id != device.enrollment_id:
        return BindingDecision(False, "ENROLLMENT_BINDING_MISMATCH", False)

    return BindingDecision(True, "IDENTITY_BINDING_VALID", False)


def privileged_identity_decision(device: DeviceIdentity, workload: WorkloadIdentity) -> BindingDecision:
    """Explicitly fail closed: Phase 1 identity is never an execution grant."""
    binding = verify_device_workload_binding(device, workload)
    if not binding.binding_valid:
        return binding
    return BindingDecision(True, "IDENTITY_IS_NOT_AUTHORIZATION", False)
