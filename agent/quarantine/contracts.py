from __future__ import annotations

"""Quarantine v2 contracts and scoped capability boundary."""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from threading import RLock
from typing import Any


class QuarantineContractError(Exception):
    """Invalid or unsafe quarantine contract."""


LAB_CANARY_EXECUTION = "LAB_CANARY_EXECUTION"
DRY_RUN_ONLY = "DRY_RUN_ONLY"
CANARY_MARKER = "CYBERDEFENDER_QUARANTINE_CANARY_V2"
CANARY_MARKER_FILENAME = ".cyberdefender-quarantine-canary"
SUPPORTED_MODES = frozenset({LAB_CANARY_EXECUTION, DRY_RUN_ONLY})


def _text(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise QuarantineContractError(f"{field} must be string")
    value = value.strip()
    if not value or len(value) > maximum:
        raise QuarantineContractError(f"invalid {field}")
    return value


def _sha256_text(value: Any, field: str) -> str:
    value = _text(value, field, 64).lower()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise QuarantineContractError(f"invalid {field}")
    return value


@dataclass(frozen=True, slots=True)
class QuarantineRequest:
    incident_id: str
    idempotency_key: str
    target: str
    approved_root: str
    target_sha256: str
    requester: str
    evidence_ref: str
    decision_digest: str
    mode: str = LAB_CANARY_EXECUTION
    canary_marker: str = CANARY_MARKER

    @classmethod
    def from_mapping(cls, value: Any) -> "QuarantineRequest":
        if not isinstance(value, dict):
            raise QuarantineContractError("request must be dict")
        mode = _text(value.get("mode", LAB_CANARY_EXECUTION), "mode", 32)
        if mode not in SUPPORTED_MODES:
            raise QuarantineContractError("unsupported quarantine mode")
        marker = _text(value.get("canary_marker", CANARY_MARKER), "canary_marker", 64)
        if mode == LAB_CANARY_EXECUTION and marker != CANARY_MARKER:
            raise QuarantineContractError("invalid lab canary marker")
        return cls(
            incident_id=_text(value.get("incident_id"), "incident_id", 128),
            idempotency_key=_text(value.get("idempotency_key"), "idempotency_key", 160),
            target=_text(value.get("target"), "target", 512),
            approved_root=_text(value.get("approved_root"), "approved_root", 512),
            target_sha256=_sha256_text(value.get("target_sha256"), "target_sha256"),
            requester=_text(value.get("requester"), "requester", 128),
            evidence_ref=_text(value.get("evidence_ref"), "evidence_ref", 256),
            decision_digest=_sha256_text(value.get("decision_digest"), "decision_digest"),
            mode=mode,
            canary_marker=marker,
        )

    def scope(self) -> dict[str, str]:
        return {
            "incident_id": self.incident_id,
            "idempotency_key": self.idempotency_key,
            "target": self.target,
            "approved_root": self.approved_root,
            "target_sha256": self.target_sha256,
            "requester": self.requester,
            "evidence_ref": self.evidence_ref,
            "decision_digest": self.decision_digest,
            "mode": self.mode,
            "canary_marker": self.canary_marker,
        }


def _canonical_scope(scope: dict[str, str]) -> bytes:
    return "|".join(f"{key}={scope[key]}" for key in sorted(scope)).encode("utf-8")


def canonical_scope_digest(scope: dict[str, str]) -> str:
    """Return the one canonical digest used by capability and Safety attestation."""
    return hashlib.sha256(_canonical_scope(scope)).hexdigest()


class QuarantineCapabilityIssuer:
    """Issue and consume narrowly scoped, lab-only capabilities."""

    VERSION = "2.0"
    DEFAULT_TTL_SECONDS = 30.0
    MAX_OUTSTANDING = 32

    def __init__(self, *, ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 max_outstanding: int = MAX_OUTSTANDING) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if isinstance(max_outstanding, bool) or not isinstance(max_outstanding, int) or max_outstanding < 1:
            raise ValueError("max_outstanding must be >= 1")
        self.ttl_seconds = float(ttl_seconds)
        self.max_outstanding = max_outstanding
        self._secret = secrets.token_bytes(32)
        self._lock = RLock()
        self._tokens: dict[str, dict[str, Any]] = {}
        self.issued = 0
        self.consumed = 0
        self.denied = 0
        self.replays = 0

    @staticmethod
    def _policy_and_verification_match(request: QuarantineRequest, policy: Any, verification: Any) -> bool:
        if not isinstance(policy, dict) or not isinstance(verification, dict):
            return False
        if policy.get("accepted") is not True or policy.get("policy_outcome") != "REQUIRE_VERIFICATION":
            return False
        if policy.get("authorization") != "NOT_GRANTED" or policy.get("action") != "OBSERVE_ONLY":
            return False
        if verification.get("accepted") is not True or verification.get("verified") is not True:
            return False
        if verification.get("authorization") != "NOT_GRANTED" or verification.get("action") != "OBSERVE_ONLY":
            return False
        assessments = policy.get("assessments")
        verified = verification.get("assessments")
        if not isinstance(assessments, list) or not isinstance(verified, list):
            return False
        p = [row for row in assessments if isinstance(row, dict) and row.get("incident_id") == request.incident_id]
        v = [row for row in verified if isinstance(row, dict) and row.get("incident_id") == request.incident_id]
        if len(p) != 1 or len(v) != 1:
            return False
        if str(p[0].get("requested_action", "")).upper() != "QUARANTINE":
            return False
        if str(v[0].get("requested_action", "")).upper() != "QUARANTINE":
            return False
        if p[0].get("decision_digest") != request.decision_digest:
            return False
        if v[0].get("decision_digest") != request.decision_digest:
            return False
        return p[0].get("decision_digest") == v[0].get("decision_digest")

    @staticmethod
    def _safety_attestation(request: QuarantineRequest, safety: Any) -> bool:
        if safety is None:
            return False
        health = getattr(safety, "health_snapshot", None)
        attest = getattr(safety, "authorize_lab_quarantine", None)
        if not callable(health) or not callable(attest):
            return False
        snapshot = health()
        if not isinstance(snapshot, dict) or snapshot.get("safe_mode") or snapshot.get("shutdown_requested"):
            return False
        result = attest(request.scope())
        if not isinstance(result, dict) or result.get("allowed") is not True or result.get("mode") != LAB_CANARY_EXECUTION:
            return False
        supplied_digest = result.get("scope_digest")
        expected_digest = canonical_scope_digest(request.scope())
        return isinstance(supplied_digest, str) and hmac.compare_digest(supplied_digest, expected_digest)

    def issue(self, request: QuarantineRequest | dict[str, Any], *, policy_result: dict[str, Any],
              verification_result: dict[str, Any], safety: Any, operator_approved: bool = False) -> dict[str, Any]:
        try:
            req = request if isinstance(request, QuarantineRequest) else QuarantineRequest.from_mapping(request)
            if req.mode != LAB_CANARY_EXECUTION:
                raise QuarantineContractError("real containment requires LAB_CANARY_EXECUTION")
            if operator_approved is not True:
                raise QuarantineContractError("explicit operator approval required")
            if not self._policy_and_verification_match(req, policy_result, verification_result):
                raise QuarantineContractError("policy or independent verification evidence invalid")
            if not self._safety_attestation(req, safety):
                raise QuarantineContractError("lab safety attestation unavailable")
            with self._lock:
                now = time.time()
                self._tokens = {key: row for key, row in self._tokens.items() if float(row["expires_at"]) > now and not row["used"]}
                if len(self._tokens) >= self.max_outstanding:
                    raise QuarantineContractError("capability budget exceeded")
                capability_id = secrets.token_urlsafe(18)
                expires_at = now + self.ttl_seconds
                scope = req.scope()
                scope_digest = canonical_scope_digest(scope)
                mac = hmac.new(self._secret, f"{capability_id}|{scope_digest}|{expires_at:.6f}".encode(), hashlib.sha256).hexdigest()
                self._tokens[capability_id] = {"scope": scope, "scope_digest": scope_digest, "expires_at": expires_at, "mac": mac, "used": False}
                self.issued += 1
                return {
                    "schema": "cd.quarantine.capability.v2",
                    "capability_id": capability_id,
                    "action": "QUARANTINE",
                    "authorization": "QUARANTINE_CAPABILITY",
                    "mode": LAB_CANARY_EXECUTION,
                    "scope": dict(scope),
                    "scope_digest": scope_digest,
                    "issued_at": now,
                    "expires_at": expires_at,
                    "single_use": True,
                    "token_mac": mac,
                }
        except QuarantineContractError:
            with self._lock:
                self.denied += 1
            raise

    def consume(self, capability: Any, request: QuarantineRequest | dict[str, Any]) -> dict[str, Any]:
        req = request if isinstance(request, QuarantineRequest) else QuarantineRequest.from_mapping(request)
        if not isinstance(capability, dict):
            raise QuarantineContractError("capability required")
        capability_id = _text(capability.get("capability_id"), "capability_id", 128)
        supplied_mac = _text(capability.get("token_mac"), "token_mac", 128)
        with self._lock:
            row = self._tokens.get(capability_id)
            if row is None or row.get("used"):
                self.replays += 1
                raise QuarantineContractError("capability unknown or replayed")
            if time.time() >= float(row["expires_at"]):
                self._tokens.pop(capability_id, None)
                raise QuarantineContractError("capability expired")
            expected = hmac.new(self._secret, f"{capability_id}|{row['scope_digest']}|{float(row['expires_at']):.6f}".encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, str(row["mac"])) or not hmac.compare_digest(supplied_mac, str(row["mac"])):
                raise QuarantineContractError("capability integrity failure")
            if row["scope"] != req.scope():
                raise QuarantineContractError("capability scope mismatch")
            row["used"] = True
            self._tokens.pop(capability_id, None)
            self.consumed += 1
            return {
                "accepted": True,
                "capability_id": capability_id,
                "scope": dict(row["scope"]),
                "scope_digest": row["scope_digest"],
                "mode": req.mode,
            }

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": "QuarantineCapabilityIssuer", "version": self.VERSION,
                "status": "HEALTHY", "issued": self.issued, "consumed": self.consumed,
                "denied": self.denied, "replays": self.replays, "outstanding": len(self._tokens),
                "fail_closed": True, "secrets_exported": False,
            }
