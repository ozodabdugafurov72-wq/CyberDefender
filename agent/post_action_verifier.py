from __future__ import annotations

"""CyberDefender Post-Action Verifier v1 foundation.

The current product still has no real privileged executor. This verifier
therefore proves the dry-run response receipt is internally consistent and,
most importantly, proves that the current gateway reported *no real-world
effect*. Any evidence of actual execution or uncertainty is fail-closed and
requires escalation/recovery planning.

Future real-action verifiers must use independent authoritative evidence
collectors; this v1 intentionally refuses to verify real execution.
"""

from hashlib import sha256
from threading import RLock
from typing import Any
import json


class PostActionVerificationError(Exception):
    """Invalid or unverifiable response outcome."""


class PostActionVerifier:
    VERSION = "1.0"
    MAX_TEXT = 256

    def __init__(self) -> None:
        self.name = "PostActionVerifier"
        self._lock = RLock()
        self.verifications = 0
        self.verified = 0
        self.rejected = 0
        self.uncertain = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_result: dict[str, Any] | None = None

    @classmethod
    def _text(cls, value: Any, field: str) -> str:
        if not isinstance(value, str):
            raise PostActionVerificationError(f"{field} must be string")
        value = value.strip()
        if not value or len(value) > cls.MAX_TEXT:
            raise PostActionVerificationError(f"invalid {field}")
        return value

    @staticmethod
    def _digest(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return sha256(raw.encode("utf-8")).hexdigest()

    def _reject(self, reason: str, *, observed_effect: bool | None) -> dict[str, Any]:
        result = {
            "component": self.name,
            "version": self.VERSION,
            "accepted": False,
            "verified": False,
            "verification_outcome": "UNVERIFIED",
            "reason": reason,
            "real_world_effect_observed": observed_effect,
            "recovery_required": True,
            "escalation_required": True,
            "authorization": "NOT_GRANTED",
            "action": "OBSERVE_ONLY",
            "fail_closed": True,
            "real_execution_supported": False,
        }
        with self._lock:
            self.rejected += 1
            if observed_effect is None:
                self.uncertain += 1
            self.last_result = result
        return result

    def verify(
        self,
        action_result: dict[str, Any],
        *,
        request: dict[str, Any],
        authorization: dict[str, Any],
    ) -> dict[str, Any]:
        """Verify a response outcome independently of the ActionGateway."""
        try:
            with self._lock:
                self.verifications += 1

            if not isinstance(action_result, dict) or not isinstance(request, dict) or not isinstance(authorization, dict):
                raise PostActionVerificationError("action_result/request/authorization must be dict")

            # Any indication of actual execution is outside the current safety
            # envelope. Refuse to bless it and force recovery/escalation.
            if action_result.get("executed") is True or action_result.get("real_world_effect") is True:
                return self._reject("REAL_ACTION_UNSUPPORTED", observed_effect=True)

            if action_result.get("accepted") is not True:
                return self._reject("ACTION_NOT_ACCEPTED", observed_effect=None)
            if action_result.get("simulated") is not True:
                return self._reject("SIMULATION_NOT_PROVEN", observed_effect=None)
            if action_result.get("executed") is not False:
                return self._reject("NON_EXECUTION_NOT_PROVEN", observed_effect=None)
            if action_result.get("real_world_effect") is not False:
                return self._reject("NO_EFFECT_NOT_PROVEN", observed_effect=None)
            if action_result.get("execution_mode") != "DRY_RUN":
                return self._reject("EXECUTION_MODE_MISMATCH", observed_effect=None)

            incident_id = self._text(request.get("incident_id"), "incident_id")
            action = self._text(request.get("requested_action"), "requested_action").upper()
            target = self._text(request.get("target"), "target")
            token_id = self._text(authorization.get("token_id"), "token_id")

            if self._text(action_result.get("incident_id"), "action incident_id") != incident_id:
                return self._reject("INCIDENT_SCOPE_MISMATCH", observed_effect=None)
            if self._text(action_result.get("action"), "action") .upper() != action:
                return self._reject("ACTION_SCOPE_MISMATCH", observed_effect=None)
            if self._text(action_result.get("target"), "target") != target:
                return self._reject("TARGET_SCOPE_MISMATCH", observed_effect=None)
            if self._text(action_result.get("authorization_token_id"), "authorization_token_id") != token_id:
                return self._reject("AUTHORIZATION_TOKEN_MISMATCH", observed_effect=None)
            if authorization.get("authorization") != "DRY_RUN_ONLY" or authorization.get("real_world_effect") is not False:
                return self._reject("AUTHORIZATION_CONTRACT_MISMATCH", observed_effect=None)

            receipt = {
                "incident_id": incident_id,
                "requested_action": action,
                "target": target,
                "authorization_token_id": token_id,
                "execution_mode": "DRY_RUN",
                "executed": False,
                "simulated": True,
                "real_world_effect": False,
            }
            result = {
                "component": self.name,
                "version": self.VERSION,
                "accepted": True,
                "verified": True,
                "verification_outcome": "DRY_RUN_VERIFIED",
                "incident_id": incident_id,
                "requested_action": action,
                "target": target,
                "receipt_digest": self._digest(receipt),
                "real_world_effect_observed": False,
                "recovery_required": False,
                "escalation_required": False,
                "authorization": "NOT_GRANTED",
                "action": "OBSERVE_ONLY",
                "fail_closed": True,
                "real_execution_supported": False,
            }
            with self._lock:
                self.verified += 1
                self.last_result = result
            return result

        except PostActionVerificationError as exc:
            return self._reject(type(exc).__name__, observed_effect=None)
        except Exception as exc:
            with self._lock:
                self.failed += 1
                self.last_error = str(exc)
            return self._reject("ENGINE_ERROR", observed_effect=None)

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": self.name,
                "version": self.VERSION,
                "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                "verifications": self.verifications,
                "verified": self.verified,
                "rejected": self.rejected,
                "uncertain": self.uncertain,
                "failed": self.failed,
                "last_error": self.last_error,
                "fail_closed": True,
                "real_execution_supported": False,
            }

    get_stats = health_check
