from __future__ import annotations

"""CyberDefender Independent Verifier v1.

Pre-authorization verification boundary. This component independently checks
RiskEngine/PolicyEngine outputs and SafetyCore state before any future action
authorization path exists. It never grants authorization and never executes
an action. Full post-action verification remains a later, separate capability.
"""

from hashlib import sha256
from threading import RLock
from typing import Any
import json
import time


class IndependentVerifierError(Exception):
    """Verifier contract violation caused by invalid/untrusted input."""


class IndependentVerifier:
    VERSION = "1.0"
    DEFAULT_MAX_ASSESSMENTS = 128
    MAX_ID_LENGTH = 256
    MAX_REASON_LENGTH = 128

    ALLOWED_LEVELS = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
    LEVEL_MINIMUMS = {
        "INFO": 0,
        "LOW": 20,
        "MEDIUM": 40,
        "HIGH": 60,
        "CRITICAL": 80,
    }
    ALLOWED_POLICY_OUTCOMES = frozenset(
        {"DENY", "REQUIRE_VERIFICATION", "REVIEW", "OBSERVE_ONLY"}
    )
    PRIVILEGED_ACTIONS = frozenset(
        {
            "SYSTEM_MODIFY", "FIREWALL_MODIFY", "REGISTRY_MODIFY",
            "SERVICE_MODIFY", "PROCESS_TERMINATE", "PROCESS_SUSPEND",
            "DRIVER_INSTALL", "DRIVER_MODIFY", "SECURITY_POLICY_MODIFY",
            "BOOT_MODIFY", "NETWORK_BLOCK", "QUARANTINE", "ISOLATE_DEVICE",
        }
    )

    def __init__(self, *, max_assessments: int = DEFAULT_MAX_ASSESSMENTS) -> None:
        if isinstance(max_assessments, bool) or not isinstance(max_assessments, int):
            raise TypeError("max_assessments integer bo'lishi kerak")
        if max_assessments < 1:
            raise ValueError("max_assessments >= 1 bo'lishi kerak")

        self.name = "IndependentVerifier"
        self.max_assessments = max_assessments
        self._lock = RLock()
        self.verifications_run = 0
        self.assessments_verified = 0
        self.assessments_rejected = 0
        self.invalid_operations = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_error_type: str | None = None
        self.last_error_at: float | None = None
        self.last_result: dict[str, Any] | None = None

    @staticmethod
    def _bounded_score(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise IndependentVerifierError("risk_score integer/float bo'lishi kerak")
        if value != value or value in (float("inf"), float("-inf")):
            raise IndependentVerifierError("risk_score finite bo'lishi kerak")
        score = int(round(value))
        if score < 0 or score > 100:
            raise IndependentVerifierError("risk_score 0..100 oralig'ida bo'lishi kerak")
        return score

    @classmethod
    def _normalize_id(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise IndependentVerifierError("incident_id string bo'lishi kerak")
        value = value.strip()
        if not value or len(value) > cls.MAX_ID_LENGTH:
            raise IndependentVerifierError("incident_id invalid")
        return value

    @classmethod
    def _normalize_action(cls, value: Any) -> str:
        if value is None:
            return "OBSERVE_ONLY"
        if not isinstance(value, str):
            raise IndependentVerifierError("requested_action string bo'lishi kerak")
        value = value.strip().upper()
        if not value or len(value) > cls.MAX_REASON_LENGTH:
            raise IndependentVerifierError("requested_action invalid")
        return value

    @classmethod
    def _expected_level(cls, score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFO"

    @classmethod
    def _safety_state(cls, safety: Any) -> tuple[bool, bool, str]:
        if safety is None:
            return False, False, "UNAVAILABLE"
        if isinstance(safety, dict):
            return bool(safety.get("safe_mode")), bool(safety.get("shutdown_requested")), "PROVIDED"
        method = getattr(safety, "health_snapshot", None)
        if not callable(method):
            raise IndependentVerifierError("SafetyCore health_snapshot mavjud emas")
        snapshot = method()
        if not isinstance(snapshot, dict):
            raise IndependentVerifierError("SafetyCore health_snapshot dict bo'lishi kerak")
        return bool(snapshot.get("safe_mode")), bool(snapshot.get("shutdown_requested")), "PROVIDED"

    @staticmethod
    def _canonical_digest(payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return sha256(encoded).hexdigest()

    def _verify_one(self, risk_item: dict[str, Any], policy_item: dict[str, Any], *, safety: Any) -> dict[str, Any]:
        if not isinstance(risk_item, dict) or not isinstance(policy_item, dict):
            raise IndependentVerifierError("risk/policy assessment dict bo'lishi kerak")

        risk_id = self._normalize_id(risk_item.get("incident_id"))
        policy_id = self._normalize_id(policy_item.get("incident_id"))
        if risk_id != policy_id:
            raise IndependentVerifierError("risk/policy incident_id mismatch")

        score = self._bounded_score(risk_item.get("risk_score"))
        risk_level = risk_item.get("risk_level")
        if not isinstance(risk_level, str) or risk_level.strip().upper() not in self.ALLOWED_LEVELS:
            raise IndependentVerifierError("invalid risk_level")
        risk_level = risk_level.strip().upper()
        if self._expected_level(score) != risk_level:
            raise IndependentVerifierError("risk_level inconsistent with risk_score")

        policy_score = self._bounded_score(policy_item.get("risk_score"))
        if policy_score != score:
            raise IndependentVerifierError("risk/policy score mismatch")

        policy_level = str(policy_item.get("risk_level", "")).strip().upper()
        if policy_level != risk_level:
            raise IndependentVerifierError("risk/policy level mismatch")

        requested_action = self._normalize_action(risk_item.get("requested_action", policy_item.get("requested_action")))
        policy_action = self._normalize_action(policy_item.get("requested_action"))
        if requested_action != policy_action:
            raise IndependentVerifierError("risk/policy requested_action mismatch")

        authorization = policy_item.get("authorization")
        action = policy_item.get("action")
        if authorization != "NOT_GRANTED":
            raise IndependentVerifierError("authorization leakage detected")
        if action != "OBSERVE_ONLY":
            raise IndependentVerifierError("action leakage detected")

        outcome = policy_item.get("policy_outcome")
        if outcome not in self.ALLOWED_POLICY_OUTCOMES:
            raise IndependentVerifierError("invalid policy_outcome")

        recommendation = policy_item.get("recommendation")
        if not isinstance(recommendation, str) or not recommendation.strip():
            raise IndependentVerifierError("policy recommendation missing")

        safe_mode, shutdown_requested, safety_state = self._safety_state(safety)
        policy_safe_mode = bool(policy_item.get("safe_mode"))
        policy_shutdown = bool(policy_item.get("shutdown_requested"))
        if policy_safe_mode != safe_mode or policy_shutdown != shutdown_requested:
            raise IndependentVerifierError("SafetyCore state mismatch")

        if safe_mode or shutdown_requested:
            if outcome != "DENY" or policy_item.get("policy_reason") not in {
                "SAFETY_CORE_SAFE_MODE", "SAFETY_CORE_SHUTDOWN_REQUESTED"
            }:
                raise IndependentVerifierError("SafetyCore fail-closed invariant violated")
        elif requested_action in self.PRIVILEGED_ACTIONS or score >= 80:
            if outcome != "REQUIRE_VERIFICATION":
                raise IndependentVerifierError("verification gate bypass detected")
            if not bool(policy_item.get("requires_independent_verification")):
                raise IndependentVerifierError("verification requirement missing")
        elif score >= 60:
            if outcome not in {"REVIEW", "REQUIRE_VERIFICATION"}:
                raise IndependentVerifierError("elevated-risk policy inconsistency")
        else:
            if outcome not in {"OBSERVE_ONLY", "REVIEW", "REQUIRE_VERIFICATION"}:
                raise IndependentVerifierError("low-risk policy inconsistency")

        digest_input = {
            "incident_id": risk_id,
            "risk_score": score,
            "risk_level": risk_level,
            "requested_action": requested_action,
            "policy_outcome": outcome,
            "policy_reason": str(policy_item.get("policy_reason", ""))[: self.MAX_REASON_LENGTH],
            "recommendation": recommendation[: self.MAX_REASON_LENGTH],
            "authorization": authorization,
            "action": action,
            "safe_mode": safe_mode,
            "shutdown_requested": shutdown_requested,
        }
        return {
            "incident_id": risk_id,
            "verified": True,
            "verification_outcome": "VERIFIED",
            "risk_score": score,
            "risk_level": risk_level,
            "policy_outcome": outcome,
            "requested_action": requested_action,
            "authorization": "NOT_GRANTED",
            "action": "OBSERVE_ONLY",
            "safety_state": safety_state,
            "safe_mode": safe_mode,
            "shutdown_requested": shutdown_requested,
            "decision_digest": self._canonical_digest(digest_input),
        }

    def verify(self, risk_result: dict[str, Any], policy_result: dict[str, Any], *, safety: Any = None) -> dict[str, Any]:
        """Independently verify bounded Risk/Policy decisions. Never authorizes or executes."""
        try:
            if not isinstance(risk_result, dict) or not isinstance(policy_result, dict):
                raise IndependentVerifierError("risk_result/policy_result dict bo'lishi kerak")
            risk_items = risk_result.get("assessments")
            policy_items = policy_result.get("assessments")
            if not isinstance(risk_items, list) or not isinstance(policy_items, list):
                raise IndependentVerifierError("risk/policy assessments list bo'lishi kerak")
            if len(risk_items) > self.max_assessments or len(policy_items) > self.max_assessments:
                raise IndependentVerifierError("assessment budget exceeded")

            risk_map: dict[str, dict[str, Any]] = {}
            policy_map: dict[str, dict[str, Any]] = {}
            for item in risk_items:
                if isinstance(item, dict) and isinstance(item.get("incident_id"), str):
                    incident_id = item["incident_id"].strip()
                    if incident_id and incident_id not in risk_map:
                        risk_map[incident_id] = item
            for item in policy_items:
                if isinstance(item, dict) and isinstance(item.get("incident_id"), str):
                    incident_id = item["incident_id"].strip()
                    if incident_id and incident_id not in policy_map:
                        policy_map[incident_id] = item

            if set(risk_map) != set(policy_map):
                raise IndependentVerifierError("risk/policy incident set mismatch")

            results: list[dict[str, Any]] = []
            rejected = 0
            for incident_id in sorted(risk_map):
                try:
                    results.append(self._verify_one(risk_map[incident_id], policy_map[incident_id], safety=safety))
                except IndependentVerifierError:
                    rejected += 1

            if rejected:
                # A partially verified batch is not a verified batch.
                with self._lock:
                    self.assessments_rejected += rejected
                raise IndependentVerifierError("one or more assessments failed independent verification")

            if not results:
                overall = "VERIFIED_EMPTY"
            elif all(item["verified"] for item in results):
                overall = "VERIFIED"
            else:
                overall = "REJECTED"

            result = {
                "component": self.name,
                "version": self.VERSION,
                "accepted": True,
                "verification_outcome": overall,
                "verified": overall == "VERIFIED" or overall == "VERIFIED_EMPTY",
                "assessments_verified": len(results),
                "assessments_rejected": 0,
                "assessments": results,
                "authorization": "NOT_GRANTED",
                "action": "OBSERVE_ONLY",
                "fail_closed": True,
            }
            with self._lock:
                self.verifications_run += 1
                self.assessments_verified += len(results)
                self.last_result = result
            return result
        except IndependentVerifierError as exc:
            with self._lock:
                self.invalid_operations += 1
            return {
                "component": self.name,
                "version": self.VERSION,
                "accepted": False,
                "verification_outcome": "REJECTED",
                "verified": False,
                "reason": "INDEPENDENT_VERIFICATION_FAILED",
                "error": type(exc).__name__,
                "authorization": "NOT_GRANTED",
                "action": "OBSERVE_ONLY",
                "fail_closed": True,
            }
        except Exception as exc:
            with self._lock:
                self.failed += 1
                self.last_error = str(exc)
                self.last_error_type = type(exc).__name__
                self.last_error_at = time.time()
            return {
                "component": self.name,
                "version": self.VERSION,
                "accepted": False,
                "verification_outcome": "REJECTED",
                "verified": False,
                "reason": "VERIFIER_ERROR",
                "error": type(exc).__name__,
                "authorization": "NOT_GRANTED",
                "action": "OBSERVE_ONLY",
                "fail_closed": True,
            }

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": self.name,
                "version": self.VERSION,
                "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                "verifications_run": self.verifications_run,
                "assessments_verified": self.assessments_verified,
                "assessments_rejected": self.assessments_rejected,
                "invalid_operations": self.invalid_operations,
                "failed": self.failed,
                "last_error": self.last_error,
                "fail_closed": True,
                "authorization": "NOT_GRANTED",
                "post_action_verification": False,
            }

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()
