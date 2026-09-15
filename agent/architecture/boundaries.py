from __future__ import annotations

"""CyberDefender v6 plane and trust-boundary contracts."""

from types import MappingProxyType
from typing import Final


# Canonical target decision/response path. Optional intelligence stages may
# enrich evidence, but no stage is allowed to skip the mandatory gates below.
ALLOWED_TARGET_FLOW: Final[tuple[str, ...]] = (
    "TRUSTED_EVIDENCE",
    "RISK_ENGINE",
    "AI_RECOMMENDATION_OPTIONAL",
    "POLICY_ENGINE",
    "PRE_ACTION_INDEPENDENT_VERIFIER",
    "BLAST_RADIUS_GUARD",
    "LOCAL_SAFETY_CORE",
    "SHORT_LIVED_ACTION_CAPABILITY",
    "PRIVILEGE_SEPARATED_EXECUTOR",
    "POST_ACTION_INDEPENDENT_VERIFIER",
    "EVIDENCE_PRESERVATION",
    "RECOVERY",
    "RE_ATTESTATION",
    "TRUST_RESTORATION",
)

FORBIDDEN_DIRECT_EDGES: Final[frozenset[tuple[str, str]]] = frozenset({
    ("OWNER_UI", "PRIVILEGED_EXECUTOR"),
    ("ADMIN_UI", "PRIVILEGED_EXECUTOR"),
    ("SOC_UI", "PRIVILEGED_EXECUTOR"),
    ("AI", "PRIVILEGED_EXECUTOR"),
    ("RISK_ENGINE", "PRIVILEGED_EXECUTOR"),
    ("DETECTION_ENGINE", "PRIVILEGED_EXECUTOR"),
    ("CORRELATION_ENGINE", "PRIVILEGED_EXECUTOR"),
    ("CLOUD_CONTROL", "PRIVILEGED_EXECUTOR"),
    ("FAMILY_MESH_NODE", "PRIVILEGED_EXECUTOR"),
    ("LEARNING_PIPELINE", "ACTIVE_POLICY"),
    ("RECOVERY", "TRUST_RESTORATION"),
})

# Explicit current/target trust crossings. These are architectural boundaries,
# not network ACL rules.
TRUST_CROSSINGS: Final[dict[str, tuple[str, ...]]] = MappingProxyType({
    "RAW_TO_TRUSTED_EVENT": (
        "SOURCE_IDENTITY", "SCHEMA", "PROVENANCE", "INTEGRITY", "FRESHNESS", "REPLAY", "TENANT_BINDING"
    ),
    "MANAGEMENT_TO_EXECUTION": (
        "COMMAND_GATEWAY", "REQUESTER_IDENTITY", "TENANT_SCOPE", "FRESHNESS", "POLICY", "PRE_ACTION_VERIFIER", "BLAST_RADIUS", "LOCAL_SAFETY", "CAPABILITY"
    ),
    "REMOTE_TO_ENDPOINT": (
        "REMOTE_IDENTITY", "SIGNATURE", "TENANT_SCOPE", "FRESHNESS", "POLICY", "LOCAL_SAFETY"
    ),
    "RECOVERY_TO_TRUST": (
        "INTEGRITY_CHECK", "RE_ATTESTATION", "POLICY_SYNC", "INDEPENDENT_VERIFICATION"
    ),
    "LEARNING_TO_PRODUCTION": (
        "OFFLINE_EVALUATION", "REGRESSION", "ADVERSARIAL_TEST", "CANARY", "APPROVAL", "SIGNED_PROMOTION"
    ),
})


def is_direct_edge_forbidden(source: str, destination: str) -> bool:
    return (str(source).strip().upper(), str(destination).strip().upper()) in FORBIDDEN_DIRECT_EDGES


def validate_boundaries() -> None:
    mandatory_order = (
        "POLICY_ENGINE",
        "PRE_ACTION_INDEPENDENT_VERIFIER",
        "BLAST_RADIUS_GUARD",
        "LOCAL_SAFETY_CORE",
        "SHORT_LIVED_ACTION_CAPABILITY",
        "PRIVILEGE_SEPARATED_EXECUTOR",
        "POST_ACTION_INDEPENDENT_VERIFIER",
    )
    positions = {name: ALLOWED_TARGET_FLOW.index(name) for name in mandatory_order}
    if list(positions.values()) != sorted(positions.values()):
        raise RuntimeError("v6 response gates are out of order")
    required_forbidden = {
        ("AI", "PRIVILEGED_EXECUTOR"),
        ("OWNER_UI", "PRIVILEGED_EXECUTOR"),
        ("RISK_ENGINE", "PRIVILEGED_EXECUTOR"),
        ("CLOUD_CONTROL", "PRIVILEGED_EXECUTOR"),
        ("RECOVERY", "TRUST_RESTORATION"),
    }
    if not required_forbidden.issubset(FORBIDDEN_DIRECT_EDGES):
        raise RuntimeError("mandatory v6 forbidden edge missing")


def boundary_snapshot() -> dict:
    validate_boundaries()
    return {
        "component": "V6PlaneBoundaryContract",
        "version": "6.0",
        "target_flow": list(ALLOWED_TARGET_FLOW),
        "forbidden_direct_edges": [list(edge) for edge in sorted(FORBIDDEN_DIRECT_EDGES)],
        "trust_crossings": {key: list(value) for key, value in TRUST_CROSSINGS.items()},
        "fail_closed": True,
    }


validate_boundaries()
