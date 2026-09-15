from __future__ import annotations

"""CyberDefender v6 Phase 1 identity contracts.

This module defines identity structure and validation semantics only. It does
not authenticate a device, perform attestation, grant authorization, persist
identity state, or execute privileged actions.

Security invariant:
    IDENTITY != TRUST != AUTHORIZATION
"""

from dataclasses import asdict, dataclass, fields
from enum import Enum
import hashlib
import json
import re
import uuid
from typing import Any, Final


IDENTITY_SCHEMA_VERSION: Final[str] = "6.1.identity.v1.1"
_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class IdentityContractError(ValueError):
    """Raised when an identity object violates the Phase 1 contract."""


class ScopeKind(str, Enum):
    LOCAL_STANDALONE = "LOCAL_STANDALONE"
    TENANT_BOUND = "TENANT_BOUND"


class IdentityProvenance(str, Enum):
    LEGACY_ENDPOINT_MIGRATION = "LEGACY_ENDPOINT_MIGRATION"
    LOCAL_BOOTSTRAP = "LOCAL_BOOTSTRAP"
    ENTERPRISE_ENROLLMENT = "ENTERPRISE_ENROLLMENT"


class IdentityAssurance(str, Enum):
    DECLARED = "DECLARED"
    ENROLLED = "ENROLLED"
    ATTESTED = "ATTESTED"


class TrustState(str, Enum):
    IDENTIFIED = "IDENTIFIED"
    ATTESTATION_PENDING = "ATTESTATION_PENDING"
    RESTRICTED = "RESTRICTED"
    TRUSTED = "TRUSTED"
    REVOKED = "REVOKED"


class WorkloadRole(str, Enum):
    AGENT = "CyberDefenderAgent"
    CONTROL_PLANE = "CyberDefenderControlPlane"
    OWNER_UI = "CyberDefenderOwnerUI"
    RUST_PROCESS_CANARY = "RustProcessCanary"


class WorkloadIdentityProvenance(str, Enum):
    LOCAL_ROLE_DECLARATION = "LOCAL_ROLE_DECLARATION"
    TENANT_ENROLLMENT_DERIVED = "TENANT_ENROLLMENT_DERIVED"


class WorkloadAuthState(str, Enum):
    DECLARED_ONLY = "DECLARED_ONLY"
    CRYPTO_AUTHENTICATED = "CRYPTO_AUTHENTICATED"


_EXPECTED_RUNTIME_PLANE: Final[dict[WorkloadRole, str]] = {
    WorkloadRole.AGENT: "DATA_PLANE",
    WorkloadRole.CONTROL_PLANE: "CONTROL_PLANE",
    WorkloadRole.OWNER_UI: "MANAGEMENT_PLANE",
    WorkloadRole.RUST_PROCESS_CANARY: "DATA_PLANE",
}

_EXPECTED_SECURITY_PLANE: Final[dict[WorkloadRole, str]] = {
    WorkloadRole.AGENT: "ENDPOINT_TCB",
    WorkloadRole.CONTROL_PLANE: "DISTRIBUTED_CONTROL_RECOVERY",
    WorkloadRole.OWNER_UI: "DISTRIBUTED_CONTROL_RECOVERY",
    WorkloadRole.RUST_PROCESS_CANARY: "ENDPOINT_TCB",
}

_PHASE1_ALLOWED_DEVICE_ASSURANCE: Final[frozenset[IdentityAssurance]] = frozenset({
    IdentityAssurance.DECLARED,
    IdentityAssurance.ENROLLED,
})

_PHASE1_ALLOWED_TRUST_STATES: Final[frozenset[TrustState]] = frozenset({
    TrustState.IDENTIFIED,
    TrustState.ATTESTATION_PENDING,
    TrustState.RESTRICTED,
    TrustState.REVOKED,
})


def _require_exact_string(value: Any, label: str) -> str:
    if type(value) is not str:
        raise IdentityContractError(f"invalid {label} type")
    return value


def _require_identifier(value: Any, label: str) -> str:
    text = _require_exact_string(value, label)
    if text != text.strip() or not _IDENTIFIER_RE.fullmatch(text):
        raise IdentityContractError(f"invalid {label}")
    return text


def _require_uuid(value: Any, label: str) -> str:
    text = _require_exact_string(value, label)
    if text != text.strip():
        raise IdentityContractError(f"invalid {label}")
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError, TypeError) as exc:
        raise IdentityContractError(f"invalid {label}") from exc
    canonical = str(parsed)
    if text != canonical:
        raise IdentityContractError(f"non-canonical {label}")
    return text


def _require_generation(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise IdentityContractError(f"invalid {label}")
    return value


def _require_enum(value: Any, enum_type: type[Enum], label: str) -> None:
    if not isinstance(value, enum_type):
        raise IdentityContractError(f"invalid {label}")


def _strict_keys(payload: dict[str, Any], cls: type) -> None:
    expected = {field.name for field in fields(cls)}
    actual = set(payload)
    unknown = actual - expected
    missing = expected - actual
    if unknown:
        raise IdentityContractError("unknown identity field(s): " + ",".join(sorted(unknown)))
    if missing:
        raise IdentityContractError("missing identity field(s): " + ",".join(sorted(missing)))


def _parse_generation(value: Any, label: str) -> int:
    return _require_generation(value, label)


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    schema_version: str
    device_identity_id: str
    endpoint_id: str
    scope_kind: ScopeKind
    tenant_id: str | None
    enrollment_id: str | None
    provenance: IdentityProvenance
    assurance: IdentityAssurance
    trust_state: TrustState
    attestation_id: str | None
    generation: int
    authority: str = "NONE"

    def validate(self) -> None:
        if self.schema_version != IDENTITY_SCHEMA_VERSION:
            raise IdentityContractError("unsupported identity schema")
        _require_uuid(self.device_identity_id, "device_identity_id")
        _require_identifier(self.endpoint_id, "endpoint_id")
        _require_enum(self.scope_kind, ScopeKind, "scope_kind")
        _require_enum(self.provenance, IdentityProvenance, "provenance")
        _require_enum(self.assurance, IdentityAssurance, "assurance")
        _require_enum(self.trust_state, TrustState, "trust_state")
        _require_generation(self.generation, "identity generation")
        if self.authority != "NONE":
            raise IdentityContractError("identity cannot contain authority")

        if self.assurance not in _PHASE1_ALLOWED_DEVICE_ASSURANCE:
            raise IdentityContractError("ATTESTED assurance is reserved until attestation authority exists")
        if self.trust_state not in _PHASE1_ALLOWED_TRUST_STATES:
            raise IdentityContractError("TRUSTED state is reserved until trust authority exists")
        if self.attestation_id is not None:
            raise IdentityContractError("attestation_id is forbidden before attestation implementation")

        if self.scope_kind is ScopeKind.LOCAL_STANDALONE:
            if self.tenant_id is not None or self.enrollment_id is not None:
                raise IdentityContractError("local standalone identity cannot claim tenant enrollment")
            if self.provenance is IdentityProvenance.ENTERPRISE_ENROLLMENT:
                raise IdentityContractError("local standalone identity cannot claim enterprise enrollment provenance")
            if self.assurance is not IdentityAssurance.DECLARED:
                raise IdentityContractError("local standalone identity must remain DECLARED in Phase 1")
        elif self.scope_kind is ScopeKind.TENANT_BOUND:
            _require_identifier(self.tenant_id, "tenant_id")
            _require_uuid(self.enrollment_id, "enrollment_id")
            if self.provenance is not IdentityProvenance.ENTERPRISE_ENROLLMENT:
                raise IdentityContractError("tenant-bound identity requires enterprise enrollment provenance")
            if self.assurance is not IdentityAssurance.ENROLLED:
                raise IdentityContractError("tenant-bound identity must be ENROLLED in Phase 1")
        else:  # defensive; enum validation above should make this unreachable
            raise IdentityContractError("unsupported scope kind")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        row = asdict(self)
        row["scope_kind"] = self.scope_kind.value
        row["provenance"] = self.provenance.value
        row["assurance"] = self.assurance.value
        row["trust_state"] = self.trust_state.value
        return row

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DeviceIdentity":
        if not isinstance(payload, dict):
            raise IdentityContractError("device identity payload must be an object")
        _strict_keys(payload, cls)
        try:
            obj = cls(
                schema_version=_require_exact_string(payload["schema_version"], "schema_version"),
                device_identity_id=_require_exact_string(payload["device_identity_id"], "device_identity_id"),
                endpoint_id=_require_exact_string(payload["endpoint_id"], "endpoint_id"),
                scope_kind=ScopeKind(payload["scope_kind"]),
                tenant_id=None if payload["tenant_id"] is None else _require_exact_string(payload["tenant_id"], "tenant_id"),
                enrollment_id=None if payload["enrollment_id"] is None else _require_exact_string(payload["enrollment_id"], "enrollment_id"),
                provenance=IdentityProvenance(payload["provenance"]),
                assurance=IdentityAssurance(payload["assurance"]),
                trust_state=TrustState(payload["trust_state"]),
                attestation_id=None if payload["attestation_id"] is None else _require_exact_string(payload["attestation_id"], "attestation_id"),
                generation=_parse_generation(payload["generation"], "identity generation"),
                authority=_require_exact_string(payload["authority"], "authority"),
            )
        except (ValueError, TypeError, KeyError) as exc:
            if isinstance(exc, IdentityContractError):
                raise
            raise IdentityContractError("invalid device identity payload") from exc
        obj.validate()
        return obj


@dataclass(frozen=True, slots=True)
class WorkloadIdentity:
    schema_version: str
    workload_identity_id: str
    role: WorkloadRole
    device_identity_id: str
    device_generation: int
    endpoint_id: str
    scope_kind: ScopeKind
    tenant_id: str | None
    enrollment_id: str | None
    provenance: WorkloadIdentityProvenance
    runtime_plane: str
    security_plane: str
    auth_state: WorkloadAuthState
    trust_state: TrustState
    generation: int
    authority: str = "NONE"

    def validate(self) -> None:
        if self.schema_version != IDENTITY_SCHEMA_VERSION:
            raise IdentityContractError("unsupported identity schema")
        _require_uuid(self.workload_identity_id, "workload_identity_id")
        _require_enum(self.role, WorkloadRole, "workload role")
        _require_uuid(self.device_identity_id, "device_identity_id")
        _require_generation(self.device_generation, "device generation binding")
        _require_identifier(self.endpoint_id, "endpoint_id")
        _require_enum(self.scope_kind, ScopeKind, "scope_kind")
        _require_enum(self.provenance, WorkloadIdentityProvenance, "workload provenance")
        _require_enum(self.auth_state, WorkloadAuthState, "workload auth state")
        _require_enum(self.trust_state, TrustState, "workload trust state")
        _require_generation(self.generation, "workload generation")
        _require_exact_string(self.runtime_plane, "runtime_plane")
        _require_exact_string(self.security_plane, "security_plane")
        if self.authority != "NONE":
            raise IdentityContractError("workload identity cannot contain authority")

        if self.auth_state is not WorkloadAuthState.DECLARED_ONLY:
            raise IdentityContractError("cryptographic workload authentication is reserved for a later phase")
        if self.trust_state not in _PHASE1_ALLOWED_TRUST_STATES:
            raise IdentityContractError("TRUSTED workload state is reserved until trust authority exists")

        try:
            expected_runtime = _EXPECTED_RUNTIME_PLANE[self.role]
            expected_security = _EXPECTED_SECURITY_PLANE[self.role]
        except KeyError as exc:
            raise IdentityContractError("unsupported workload role") from exc
        if self.runtime_plane != expected_runtime:
            raise IdentityContractError("workload runtime plane mismatch")
        if self.security_plane != expected_security:
            raise IdentityContractError("workload security plane mismatch")

        if self.scope_kind is ScopeKind.LOCAL_STANDALONE:
            if self.tenant_id is not None or self.enrollment_id is not None:
                raise IdentityContractError("local standalone workload cannot claim tenant enrollment")
            if self.provenance is not WorkloadIdentityProvenance.LOCAL_ROLE_DECLARATION:
                raise IdentityContractError("local workload provenance mismatch")
        elif self.scope_kind is ScopeKind.TENANT_BOUND:
            _require_identifier(self.tenant_id, "tenant_id")
            _require_uuid(self.enrollment_id, "enrollment_id")
            if self.provenance is not WorkloadIdentityProvenance.TENANT_ENROLLMENT_DERIVED:
                raise IdentityContractError("tenant workload provenance mismatch")
        else:
            raise IdentityContractError("unsupported scope kind")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        row = asdict(self)
        row["role"] = self.role.value
        row["scope_kind"] = self.scope_kind.value
        row["provenance"] = self.provenance.value
        row["auth_state"] = self.auth_state.value
        row["trust_state"] = self.trust_state.value
        return row

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "WorkloadIdentity":
        if not isinstance(payload, dict):
            raise IdentityContractError("workload identity payload must be an object")
        _strict_keys(payload, cls)
        try:
            obj = cls(
                schema_version=_require_exact_string(payload["schema_version"], "schema_version"),
                workload_identity_id=_require_exact_string(payload["workload_identity_id"], "workload_identity_id"),
                role=WorkloadRole(payload["role"]),
                device_identity_id=_require_exact_string(payload["device_identity_id"], "device_identity_id"),
                device_generation=_parse_generation(payload["device_generation"], "device generation binding"),
                endpoint_id=_require_exact_string(payload["endpoint_id"], "endpoint_id"),
                scope_kind=ScopeKind(payload["scope_kind"]),
                tenant_id=None if payload["tenant_id"] is None else _require_exact_string(payload["tenant_id"], "tenant_id"),
                enrollment_id=None if payload["enrollment_id"] is None else _require_exact_string(payload["enrollment_id"], "enrollment_id"),
                provenance=WorkloadIdentityProvenance(payload["provenance"]),
                runtime_plane=_require_exact_string(payload["runtime_plane"], "runtime_plane"),
                security_plane=_require_exact_string(payload["security_plane"], "security_plane"),
                auth_state=WorkloadAuthState(payload["auth_state"]),
                trust_state=TrustState(payload["trust_state"]),
                generation=_parse_generation(payload["generation"], "workload generation"),
                authority=_require_exact_string(payload["authority"], "authority"),
            )
        except (ValueError, TypeError, KeyError) as exc:
            if isinstance(exc, IdentityContractError):
                raise
            raise IdentityContractError("invalid workload identity payload") from exc
        obj.validate()
        return obj


def canonical_identity_json(identity: DeviceIdentity | WorkloadIdentity) -> str:
    """Deterministic serialization for evidence/corruption checks.

    This is NOT a signature and MUST NOT be interpreted as authenticity.
    """
    return json.dumps(identity.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest_sha256(identity: DeviceIdentity | WorkloadIdentity) -> str:
    """Unkeyed content digest; evidence/corruption aid only, not trust proof."""
    return hashlib.sha256(canonical_identity_json(identity).encode("ascii")).hexdigest()


def expected_planes_for_role(role: WorkloadRole) -> tuple[str, str]:
    _require_enum(role, WorkloadRole, "workload role")
    return _EXPECTED_RUNTIME_PLANE[role], _EXPECTED_SECURITY_PLANE[role]
