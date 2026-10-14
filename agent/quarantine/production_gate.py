from __future__ import annotations

"""Fail-closed authorization gate for autonomous production quarantine.

The gate does not observe or classify threats.  It accepts only an exact
high-confidence request already produced by the trusted detection, policy and
independent-verification pipeline, and only under an offline Ed25519-signed
deployment policy.  A short-lived single-use capability is the only output.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.quarantine.contracts import (
    PRODUCTION_AUTONOMOUS_EXECUTION,
    QuarantineContractError,
    QuarantineRequest,
    canonical_scope_digest,
)


class ProductionCapabilityIssuer:
    SCHEMA = "cd.production-quarantine-policy.v1"
    VERSION = "1.0"

    def __init__(self, public_key: bytes, *, clock: Callable[[], float] = time.time,
                 ttl_seconds: float = 15.0, max_outstanding: int = 32) -> None:
        if len(public_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        if not 1 <= float(ttl_seconds) <= 60 or not 1 <= int(max_outstanding) <= 128:
            raise ValueError("invalid production capability bounds")
        self.public_key = Ed25519PublicKey.from_public_bytes(public_key)
        self.clock = clock
        self.ttl_seconds = float(ttl_seconds)
        self.max_outstanding = int(max_outstanding)
        self._secret = secrets.token_bytes(32)
        self._tokens: dict[str, dict[str, Any]] = {}
        self._lock = RLock()
        self.issued = 0
        self.consumed = 0
        self.denied = 0
        self.replays = 0

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise QuarantineContractError("production policy is not canonical") from exc

    def _verify_policy(self, signed_policy: Any) -> dict[str, Any]:
        if not isinstance(signed_policy, dict) or set(signed_policy) != {"payload", "signature"}:
            raise QuarantineContractError("signed production policy required")
        payload = signed_policy.get("payload")
        signature_text = signed_policy.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature_text, str) or len(signature_text) > 256:
            raise QuarantineContractError("invalid signed production policy")
        try:
            signature = base64.b64decode(signature_text.encode("ascii"), validate=True)
            self.public_key.verify(signature, self._canonical(payload))
        except (InvalidSignature, ValueError, UnicodeError) as exc:
            raise QuarantineContractError("production policy signature invalid") from exc
        required = {
            "schema", "policy_id", "issued_at", "expires_at", "allowed_roots",
            "min_risk_score", "min_detection_count", "min_detection_confidence",
            "allow_executable_targets", "endpoint_ids",
        }
        if set(payload) != required or payload.get("schema") != self.SCHEMA:
            raise QuarantineContractError("production policy schema invalid")
        now = float(self.clock())
        issued_at = payload.get("issued_at")
        expires_at = payload.get("expires_at")
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in (issued_at, expires_at)):
            raise QuarantineContractError("production policy time invalid")
        if not float(issued_at) <= now < float(expires_at) or float(expires_at) - float(issued_at) > 31 * 86400:
            raise QuarantineContractError("production policy expired or overlong")
        policy_id = payload.get("policy_id")
        roots = payload.get("allowed_roots")
        endpoint_ids = payload.get("endpoint_ids")
        if not isinstance(policy_id, str) or not 1 <= len(policy_id) <= 128:
            raise QuarantineContractError("production policy id invalid")
        if not isinstance(roots, list) or not 1 <= len(roots) <= 16:
            raise QuarantineContractError("production policy roots invalid")
        if (
            not isinstance(endpoint_ids, list)
            or not 1 <= len(endpoint_ids) <= 128
            or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in endpoint_ids)
            or len(set(endpoint_ids)) != len(endpoint_ids)
        ):
            raise QuarantineContractError("production policy endpoints invalid")
        normalized_roots = []
        for value in roots:
            if not isinstance(value, str) or len(value) > 512:
                raise QuarantineContractError("production policy root invalid")
            root = Path(value).expanduser()
            if not root.is_absolute():
                raise QuarantineContractError("production policy root must be absolute")
            normalized_roots.append(str(root.resolve(strict=True)))
        for name, minimum, maximum in (
            ("min_risk_score", 80, 100),
            ("min_detection_count", 2, 16),
        ):
            value = payload.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise QuarantineContractError(f"production policy {name} invalid")
        confidence = payload.get("min_detection_confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0.8 <= float(confidence) <= 1.0:
            raise QuarantineContractError("production policy confidence invalid")
        if payload.get("allow_executable_targets") is not True:
            raise QuarantineContractError("production executable containment is not authorized")
        return dict(payload, allowed_roots=normalized_roots)

    @staticmethod
    def _health_admitted(health: Any) -> bool:
        return bool(
            isinstance(health, dict)
            and health.get("runtime_health_admitted") is True
            and isinstance(health.get("healthy_cycle_streak"), int)
            and health["healthy_cycle_streak"] >= 3
            and health.get("component_failures") == 0
            and health.get("resource_state") == "NORMAL"
        )

    @staticmethod
    def _request_eligible(request: QuarantineRequest, policy: dict[str, Any]) -> bool:
        try:
            root = str(Path(request.approved_root).expanduser().resolve(strict=True))
            target = Path(request.target).expanduser().resolve(strict=True)
            target.relative_to(Path(root))
        except (OSError, RuntimeError, ValueError):
            return False
        return bool(
            root in policy["allowed_roots"]
            and request.endpoint_id in policy["endpoint_ids"]
            and request.risk_score is not None
            and request.risk_score >= policy["min_risk_score"]
            and request.detection_count is not None
            and request.detection_count >= policy["min_detection_count"]
            and request.detection_confidence is not None
            and request.detection_confidence >= float(policy["min_detection_confidence"])
            and len(set(request.detection_types)) >= policy["min_detection_count"]
            and request.policy_outcome == "AUTHORIZED_AUTONOMOUS_QUARANTINE"
            and request.verifier_outcome == "VERIFIED"
        )

    def issue(self, request: QuarantineRequest | dict[str, Any], *, signed_policy: dict[str, Any],
              runtime_health: dict[str, Any]) -> dict[str, Any]:
        try:
            req = request if isinstance(request, QuarantineRequest) else QuarantineRequest.from_mapping(request)
            if req.mode != PRODUCTION_AUTONOMOUS_EXECUTION:
                raise QuarantineContractError("production mode required")
            policy = self._verify_policy(signed_policy)
            if not self._health_admitted(runtime_health):
                raise QuarantineContractError("runtime health gate not admitted")
            if not self._request_eligible(req, policy):
                raise QuarantineContractError("production response evidence insufficient")
            with self._lock:
                now = float(self.clock())
                self._tokens = {
                    key: row for key, row in self._tokens.items()
                    if float(row["expires_at"]) > now and not row["used"]
                }
                if len(self._tokens) >= self.max_outstanding:
                    raise QuarantineContractError("production capability budget exceeded")
                capability_id = secrets.token_urlsafe(18)
                expires_at = now + self.ttl_seconds
                scope = req.scope()
                scope_digest = canonical_scope_digest(scope)
                binding = f"{capability_id}|{scope_digest}|{policy['policy_id']}|{expires_at:.6f}".encode()
                mac = hmac.new(self._secret, binding, hashlib.sha256).hexdigest()
                self._tokens[capability_id] = {
                    "scope": scope, "scope_digest": scope_digest, "policy_id": policy["policy_id"],
                    "expires_at": expires_at, "mac": mac, "used": False,
                }
                self.issued += 1
                return {
                    "schema": "cd.production-quarantine-capability.v1",
                    "capability_id": capability_id,
                    "scope_digest": scope_digest,
                    "policy_id": policy["policy_id"],
                    "expires_at": expires_at,
                    "single_use": True,
                    "mode": PRODUCTION_AUTONOMOUS_EXECUTION,
                    "production_authorization": "SIGNED_POLICY_CAPABILITY",
                    "lab_authorization": "NOT_APPLICABLE",
                    "token_mac": mac,
                }
        except QuarantineContractError:
            with self._lock:
                self.denied += 1
            raise

    def consume(self, capability: Any, request: QuarantineRequest | dict[str, Any]) -> dict[str, Any]:
        req = request if isinstance(request, QuarantineRequest) else QuarantineRequest.from_mapping(request)
        if not isinstance(capability, dict):
            raise QuarantineContractError("production capability required")
        capability_id = str(capability.get("capability_id") or "")
        supplied_mac = str(capability.get("token_mac") or "")
        with self._lock:
            row = self._tokens.get(capability_id)
            if row is None or row.get("used"):
                self.replays += 1
                raise QuarantineContractError("production capability unknown or replayed")
            expires_at = float(row["expires_at"])
            binding = f"{capability_id}|{row['scope_digest']}|{row['policy_id']}|{expires_at:.6f}".encode()
            expected = hmac.new(self._secret, binding, hashlib.sha256).hexdigest()
            if float(self.clock()) >= expires_at or row["scope"] != req.scope():
                raise QuarantineContractError("production capability expired or scope mismatch")
            if not hmac.compare_digest(expected, row["mac"]) or not hmac.compare_digest(expected, supplied_mac):
                raise QuarantineContractError("production capability integrity failure")
            row["used"] = True
            self._tokens.pop(capability_id, None)
            self.consumed += 1
            return {
                "accepted": True,
                "capability_id": capability_id,
                "scope_digest": row["scope_digest"],
                "policy_id": row["policy_id"],
                "mode": PRODUCTION_AUTONOMOUS_EXECUTION,
                "production_authorization": "SIGNED_POLICY_CAPABILITY_CONSUMED",
                "lab_authorization": "NOT_APPLICABLE",
            }
