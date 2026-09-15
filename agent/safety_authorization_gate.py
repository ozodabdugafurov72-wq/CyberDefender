from __future__ import annotations

"""CyberDefender Safety Core Authorization Gate v1.

This gate is intentionally DRY-RUN only. It creates a short-lived, single-use
capability record for the Action Gateway but can never authorize a real OS
mutation in v1. The existing SafetyCore remains the final safety boundary.
"""

import hashlib
import hmac
import secrets
import time
from threading import RLock
from typing import Any


class SafetyAuthorizationError(Exception):
    """Authorization contract violation."""


class SafetyAuthorizationGate:
    VERSION = "1.0"
    DEFAULT_TTL_SECONDS = 30.0
    DEFAULT_MAX_OUTSTANDING = 128
    MAX_REQUEST_BYTES = 16_384
    MAX_ID_LENGTH = 128
    MAX_ACTION_LENGTH = 64
    MAX_TARGET_LENGTH = 256
    MAX_EVIDENCE_LENGTH = 256
    MAX_REQUESTER_LENGTH = 128

    L6_ACTIONS = frozenset({
        "SYSTEM_MODIFY", "DRIVER_INSTALL", "DRIVER_MODIFY",
        "SECURITY_POLICY_MODIFY", "BOOT_MODIFY",
    })

    PRIVILEGED_ACTIONS = frozenset({
        "SYSTEM_MODIFY", "FIREWALL_MODIFY", "REGISTRY_MODIFY",
        "SERVICE_MODIFY", "PROCESS_TERMINATE", "PROCESS_SUSPEND",
        "DRIVER_INSTALL", "DRIVER_MODIFY", "SECURITY_POLICY_MODIFY",
        "BOOT_MODIFY", "NETWORK_BLOCK", "QUARANTINE", "ISOLATE_DEVICE",
    })

    # v1 deliberately allows only simulation capability. No real-world action.
    def __init__(self, *, ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 max_outstanding: int = DEFAULT_MAX_OUTSTANDING) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if isinstance(max_outstanding, bool) or not isinstance(max_outstanding, int) or max_outstanding < 1:
            raise ValueError("max_outstanding must be >= 1")
        self.name = "SafetyAuthorizationGate"
        self.ttl_seconds = float(ttl_seconds)
        self.max_outstanding = max_outstanding
        self._secret = secrets.token_bytes(32)
        self._lock = RLock()
        self._tokens: dict[str, dict[str, Any]] = {}
        self.requests_run = 0
        self.authorizations_issued = 0
        self.denials = 0
        self.replays_rejected = 0
        self.scope_rejections = 0
        self.expired_rejected = 0
        self.invalid_operations = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_result: dict[str, Any] | None = None

    @staticmethod
    def _text(value: Any, name: str, maximum: int) -> str:
        if not isinstance(value, str):
            raise SafetyAuthorizationError(f"{name} must be string")
        value = value.strip()
        if not value or len(value) > maximum:
            raise SafetyAuthorizationError(f"invalid {name}")
        return value

    @classmethod
    def _request_action(cls, value: Any) -> str:
        action = cls._text(value, "requested_action", cls.MAX_ACTION_LENGTH).upper()
        if action not in cls.PRIVILEGED_ACTIONS:
            raise SafetyAuthorizationError("unsupported privileged action")
        return action

    @staticmethod
    def _safe_state(safety: Any) -> tuple[bool, bool]:
        if safety is None:
            raise SafetyAuthorizationError("SafetyCore required")
        health = getattr(safety, "health_snapshot", None)
        if not callable(health):
            raise SafetyAuthorizationError("SafetyCore health_snapshot unavailable")
        snapshot = health()
        if not isinstance(snapshot, dict):
            raise SafetyAuthorizationError("invalid SafetyCore health")
        return bool(snapshot.get("safe_mode")), bool(snapshot.get("shutdown_requested"))

    @staticmethod
    def _canonical_scope(request: dict[str, Any]) -> str:
        parts = [
            str(request["incident_id"]), str(request["requested_action"]),
            str(request["target"]), str(request["requester"]),
            str(request["evidence_ref"]), str(request["decision_digest"]),
        ]
        return "|".join(parts)

    def _mac(self, token_id: str, scope_digest: str, expires_at: float) -> str:
        material = f"{token_id}|{scope_digest}|{expires_at:.6f}".encode()
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()

    def _purge_expired_locked(self, now: float) -> None:
        expired = [k for k, v in self._tokens.items() if float(v["expires_at"]) <= now]
        for key in expired:
            self._tokens.pop(key, None)

    def authorize_dry_run(self, request: dict[str, Any], *, policy_result: dict[str, Any],
                          verification_result: dict[str, Any], safety: Any) -> dict[str, Any]:
        """Issue a non-executable, single-use dry-run capability after all gates pass."""
        try:
            if not isinstance(request, dict) or not isinstance(policy_result, dict) or not isinstance(verification_result, dict):
                raise SafetyAuthorizationError("request/policy/verification must be dict")
            if request.get("execution_mode") != "DRY_RUN":
                raise SafetyAuthorizationError("v1 requires execution_mode=DRY_RUN")
            if len(repr(request)) > self.MAX_REQUEST_BYTES:
                raise SafetyAuthorizationError("request budget exceeded")

            incident_id = self._text(request.get("incident_id"), "incident_id", self.MAX_ID_LENGTH)
            requester = self._text(request.get("requester"), "requester", self.MAX_REQUESTER_LENGTH)
            target = self._text(request.get("target"), "target", self.MAX_TARGET_LENGTH)
            evidence_ref = self._text(request.get("evidence_ref"), "evidence_ref", self.MAX_EVIDENCE_LENGTH)
            action = self._request_action(request.get("requested_action"))
            if action in self.L6_ACTIONS:
                raise SafetyAuthorizationError("L6_ACTION_REQUIRES_EXPLICIT_HUMAN_APPROVAL")
            digest = self._text(request.get("decision_digest"), "decision_digest", 128)

            safe_mode, shutdown = self._safe_state(safety)
            if safe_mode:
                raise SafetyAuthorizationError("SAFETY_CORE_SAFE_MODE")
            if shutdown:
                raise SafetyAuthorizationError("SAFETY_CORE_SHUTDOWN_REQUESTED")

            if policy_result.get("accepted") is not True:
                raise SafetyAuthorizationError("policy not accepted")
            if policy_result.get("authorization") != "NOT_GRANTED":
                raise SafetyAuthorizationError("policy authorization leakage")
            if policy_result.get("action") != "OBSERVE_ONLY":
                raise SafetyAuthorizationError("policy action leakage")
            if policy_result.get("policy_outcome") != "REQUIRE_VERIFICATION":
                raise SafetyAuthorizationError("policy outcome not eligible")

            assessments = policy_result.get("assessments")
            if not isinstance(assessments, list):
                raise SafetyAuthorizationError("policy assessments missing")
            matches = [x for x in assessments if isinstance(x, dict) and x.get("incident_id") == incident_id]
            if len(matches) != 1:
                raise SafetyAuthorizationError("incident policy scope mismatch")
            assessment = matches[0]
            if str(assessment.get("requested_action", "")).strip().upper() != action:
                raise SafetyAuthorizationError("requested action scope mismatch")

            if verification_result.get("accepted") is not True or verification_result.get("verified") is not True:
                raise SafetyAuthorizationError("independent verification failed")
            if verification_result.get("authorization") != "NOT_GRANTED" or verification_result.get("action") != "OBSERVE_ONLY":
                raise SafetyAuthorizationError("verification authority leakage")
            verified = [x for x in verification_result.get("assessments", []) if isinstance(x, dict) and x.get("incident_id") == incident_id]
            if len(verified) != 1:
                raise SafetyAuthorizationError("incident verification scope mismatch")
            if verified[0].get("decision_digest") != digest:
                raise SafetyAuthorizationError("decision digest mismatch")
            if str(verified[0].get("requested_action", "")).strip().upper() != action:
                raise SafetyAuthorizationError("verified action scope mismatch")

            # v1 hard invariant: the existing SafetyCore's legacy privileged evaluator must still deny.
            legacy = safety.evaluate(action, path=None)
            if not isinstance(legacy, dict) or legacy.get("decision") != "DENY":
                raise SafetyAuthorizationError("legacy SafetyCore privileged path did not remain denied")

            with self._lock:
                self._purge_expired_locked(time.time())
                if len(self._tokens) >= self.max_outstanding:
                    raise SafetyAuthorizationError("authorization budget exceeded")
                token_id = secrets.token_urlsafe(18)
                scope = {
                    "incident_id": incident_id,
                    "requested_action": action,
                    "target": target,
                    "requester": requester,
                    "evidence_ref": evidence_ref,
                    "decision_digest": digest,
                    "execution_mode": "DRY_RUN",
                }
                scope_digest = hashlib.sha256(self._canonical_scope(scope).encode()).hexdigest()
                issued_at = time.time()
                expires_at = issued_at + self.ttl_seconds
                mac = self._mac(token_id, scope_digest, expires_at)
                self._tokens[token_id] = {
                    "scope": scope,
                    "scope_digest": scope_digest,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "mac": mac,
                    "used": False,
                }
                self.requests_run += 1
                self.authorizations_issued += 1
                result = {
                    "component": self.name,
                    "version": self.VERSION,
                    "accepted": True,
                    "authorized": True,
                    "authorization": "DRY_RUN_ONLY",
                    "execution_mode": "DRY_RUN",
                    "token_id": token_id,
                    "token_mac": mac,
                    "scope": dict(scope),
                    "scope_digest": scope_digest,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "single_use": True,
                    "real_world_effect": False,
                    "post_action_verification": False,
                }
                self.last_result = result
                return result
        except SafetyAuthorizationError as exc:
            with self._lock:
                self.requests_run += 1
                self.denials += 1
                self.invalid_operations += 1
            return self._deny(type(exc).__name__, str(exc))
        except Exception as exc:
            with self._lock:
                self.requests_run += 1
                self.denials += 1
                self.failed += 1
                self.last_error = str(exc)
            return self._deny("ENGINE_ERROR", type(exc).__name__)

    def consume(self, token_id: Any, *, request: dict[str, Any], token_mac: Any = None) -> dict[str, Any]:
        """Consume exactly one dry-run capability with exact scope and valid MAC/TTL."""
        try:
            token = self._text(token_id, "token_id", 128)
            if not isinstance(request, dict):
                raise SafetyAuthorizationError("request must be dict")
            with self._lock:
                record = self._tokens.get(token)
                if record is None:
                    self.replays_rejected += 1
                    return self._deny("TOKEN_UNKNOWN_OR_REPLAYED", "unknown or already consumed token")
                now = time.time()
                if record["used"]:
                    self.replays_rejected += 1
                    return self._deny("TOKEN_REPLAY", "single-use token already consumed")
                if now >= float(record["expires_at"]):
                    self.expired_rejected += 1
                    self._tokens.pop(token, None)
                    return self._deny("TOKEN_EXPIRED", "authorization expired")
                scope = record["scope"]
                supplied = {
                    "incident_id": self._text(request.get("incident_id"), "incident_id", self.MAX_ID_LENGTH),
                    "requested_action": self._request_action(request.get("requested_action")),
                    "target": self._text(request.get("target"), "target", self.MAX_TARGET_LENGTH),
                    "requester": self._text(request.get("requester"), "requester", self.MAX_REQUESTER_LENGTH),
                    "evidence_ref": self._text(request.get("evidence_ref"), "evidence_ref", self.MAX_EVIDENCE_LENGTH),
                    "decision_digest": self._text(request.get("decision_digest"), "decision_digest", 128),
                    "execution_mode": request.get("execution_mode"),
                }
                if supplied != scope:
                    self.scope_rejections += 1
                    return self._deny("TOKEN_SCOPE_MISMATCH", "authorization scope mismatch")
                supplied_mac = self._text(token_mac, "token_mac", 128)
                expected = self._mac(token, record["scope_digest"], float(record["expires_at"]))
                if not hmac.compare_digest(expected, record["mac"]) or not hmac.compare_digest(supplied_mac, record["mac"]):
                    self.scope_rejections += 1
                    return self._deny("TOKEN_INTEGRITY_FAILURE", "authorization integrity failure")
                record["used"] = True
                self._tokens.pop(token, None)
                return {
                    "component": self.name,
                    "version": self.VERSION,
                    "accepted": True,
                    "consumed": True,
                    "execution_mode": "DRY_RUN",
                    "real_world_effect": False,
                    "scope": dict(scope),
                    "token_id": token,
                }
        except SafetyAuthorizationError as exc:
            return self._deny(type(exc).__name__, str(exc))
        except Exception as exc:
            with self._lock:
                self.failed += 1
                self.last_error = str(exc)
            return self._deny("ENGINE_ERROR", type(exc).__name__)

    def _deny(self, code: str, detail: str) -> dict[str, Any]:
        return {
            "component": self.name, "version": self.VERSION, "accepted": False,
            "authorized": False, "authorization": "NOT_GRANTED", "execution_mode": "DRY_RUN",
            "reason": code, "detail": detail, "real_world_effect": False, "fail_closed": True,
        }

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": self.name, "version": self.VERSION,
                "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                "requests_run": self.requests_run,
                "authorizations_issued": self.authorizations_issued,
                "outstanding_tokens": len(self._tokens),
                "denials": self.denials,
                "replays_rejected": self.replays_rejected,
                "scope_rejections": self.scope_rejections,
                "expired_rejected": self.expired_rejected,
                "invalid_operations": self.invalid_operations,
                "failed": self.failed,
                "last_error": self.last_error,
                "fail_closed": True,
                "dry_run_only": True,
                "real_world_effect": False,
            }

    get_stats = health_check
