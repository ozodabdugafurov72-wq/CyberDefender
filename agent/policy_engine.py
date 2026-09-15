from __future__ import annotations

"""CyberDefender deterministic Policy Engine v1.

Security boundary:
- consumes RiskEngine output only as advisory risk context
- never grants privileged authorization
- never executes an action
- fail-closed for malformed policy inputs
- bounded request/rule evaluation
- SafetyCore state can only tighten the result

Policy != Authorization.  Independent verification and SafetyCore remain
mandatory before any future privileged action gateway can authorize work.
"""

from threading import RLock
from typing import Any
import time


class PolicyEngineError(Exception):
    """Policy Engine contract violation."""


class PolicyEngine:
    VERSION = "1.0"
    DEFAULT_MAX_INCIDENTS = 128
    MAX_ACTION_NAME = 64

    PRIVILEGED_ACTIONS = frozenset(
        {
            "SYSTEM_MODIFY",
            "FIREWALL_MODIFY",
            "REGISTRY_MODIFY",
            "SERVICE_MODIFY",
            "PROCESS_TERMINATE",
            "PROCESS_SUSPEND",
            "DRIVER_INSTALL",
            "DRIVER_MODIFY",
            "SECURITY_POLICY_MODIFY",
            "BOOT_MODIFY",
            "NETWORK_BLOCK",
            "QUARANTINE",
            "ISOLATE_DEVICE",
        }
    )

    def __init__(self, *, max_incidents: int = DEFAULT_MAX_INCIDENTS) -> None:
        if isinstance(max_incidents, bool) or not isinstance(max_incidents, int):
            raise TypeError("max_incidents integer bo'lishi kerak")
        if max_incidents < 1:
            raise ValueError("max_incidents >= 1 bo'lishi kerak")

        self.name = "PolicyEngine"
        self.max_incidents = max_incidents
        self._lock = RLock()
        self.evaluations_run = 0
        self.incidents_evaluated = 0
        self.incidents_rejected = 0
        self.invalid_operations = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_error_type: str | None = None
        self.last_error_at: float | None = None
        self.last_result: dict[str, Any] | None = None

    @staticmethod
    def _score(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0
        return max(0, min(100, int(round(value))))

    @classmethod
    def _action(cls, value: Any) -> str:
        if value is None:
            return "OBSERVE_ONLY"
        if not isinstance(value, str):
            raise PolicyEngineError("requested_action string bo'lishi kerak")
        value = value.strip().upper()
        if not value:
            return "OBSERVE_ONLY"
        if len(value) > cls.MAX_ACTION_NAME:
            raise PolicyEngineError("requested_action juda uzun")
        return value

    @staticmethod
    def _safety_flags(safety: Any) -> tuple[bool, bool]:
        if safety is None:
            return False, False
        if isinstance(safety, dict):
            return bool(safety.get("safe_mode")), bool(safety.get("shutdown_requested"))
        health = getattr(safety, "health_snapshot", None)
        if not callable(health):
            raise PolicyEngineError("SafetyCore health_snapshot mavjud emas")
        snapshot = health()
        if not isinstance(snapshot, dict):
            raise PolicyEngineError("SafetyCore health_snapshot dict bo'lishi kerak")
        return bool(snapshot.get("safe_mode")), bool(snapshot.get("shutdown_requested"))

    def _evaluate_one(self, item: dict[str, Any], *, safety: Any) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise PolicyEngineError("risk assessment dict bo'lishi kerak")
        incident_id = item.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise PolicyEngineError("incident_id kerak")

        score = self._score(item.get("risk_score"))
        level = item.get("risk_level")
        if not isinstance(level, str) or not level.strip():
            level = "INFO"
        level = level.strip().upper()
        requested_action = self._action(item.get("requested_action"))
        safe_mode, shutdown_requested = self._safety_flags(safety)

        if safe_mode:
            outcome = "DENY"
            reason = "SAFETY_CORE_SAFE_MODE"
            recommendation = "NO_ACTION"
        elif shutdown_requested:
            outcome = "DENY"
            reason = "SAFETY_CORE_SHUTDOWN_REQUESTED"
            recommendation = "NO_ACTION"
        elif requested_action in self.PRIVILEGED_ACTIONS:
            outcome = "REQUIRE_VERIFICATION"
            reason = "PRIVILEGED_ACTION_REQUIRES_VERIFICATION"
            recommendation = "ESCALATE_TO_INDEPENDENT_VERIFICATION"
        elif score >= 80:
            outcome = "REQUIRE_VERIFICATION"
            reason = "HIGH_RISK_REQUIRES_VERIFICATION"
            recommendation = "ESCALATE_TO_INDEPENDENT_VERIFICATION"
        elif score >= 60:
            outcome = "REVIEW"
            reason = "ELEVATED_RISK_REQUIRES_REVIEW"
            recommendation = "ESCALATE_TO_HUMAN_REVIEW"
        else:
            outcome = "OBSERVE_ONLY"
            reason = "NO_PRIVILEGED_AUTHORIZATION_PATH"
            recommendation = "OBSERVE"

        return {
            "incident_id": incident_id.strip(),
            "risk_score": score,
            "risk_level": level,
            "requested_action": requested_action,
            "policy_outcome": outcome,
            "policy_reason": reason,
            "recommendation": recommendation,
            "authorization": "NOT_GRANTED",
            "action": "OBSERVE_ONLY",
            "requires_independent_verification": outcome == "REQUIRE_VERIFICATION",
            "safe_mode": safe_mode,
            "shutdown_requested": shutdown_requested,
        }

    def evaluate(self, risk_result: dict[str, Any], *, safety: Any = None) -> dict[str, Any]:
        """Evaluate risk against deterministic policy. Never authorizes or executes."""
        try:
            if not isinstance(risk_result, dict):
                raise PolicyEngineError("risk_result dict bo'lishi kerak")
            assessments = risk_result.get("assessments", [])
            if not isinstance(assessments, list):
                raise PolicyEngineError("risk_result assessments list bo'lishi kerak")

            results: list[dict[str, Any]] = []
            rejected = 0
            for item in assessments[: self.max_incidents]:
                try:
                    results.append(self._evaluate_one(item, safety=safety))
                except PolicyEngineError:
                    rejected += 1
                    with self._lock:
                        self.incidents_rejected += 1

            order = {"DENY": 4, "REQUIRE_VERIFICATION": 3, "REVIEW": 2, "OBSERVE_ONLY": 1}
            results.sort(key=lambda x: (-order.get(x["policy_outcome"], 0), -x["risk_score"], x["incident_id"]))
            highest = results[0] if results else None
            result = {
                "component": self.name,
                "version": self.VERSION,
                "accepted": True,
                "policy_outcome": highest["policy_outcome"] if highest else "OBSERVE_ONLY",
                "policy_reason": highest["policy_reason"] if highest else "NO_RISK_ASSESSMENTS",
                "recommendation": highest["recommendation"] if highest else "OBSERVE",
                "incidents_evaluated": len(results),
                "incidents_rejected": rejected,
                "assessments": results,
                "authorization": "NOT_GRANTED",
                "action": "OBSERVE_ONLY",
            }
            with self._lock:
                self.evaluations_run += 1
                self.incidents_evaluated += len(results)
                self.last_result = result
            return result
        except PolicyEngineError as exc:
            with self._lock:
                self.invalid_operations += 1
            return {
                "component": self.name,
                "version": self.VERSION,
                "accepted": False,
                "reason": "INVALID_INPUT",
                "error": type(exc).__name__,
                "authorization": "NOT_GRANTED",
                "action": "OBSERVE_ONLY",
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
                "reason": "ENGINE_ERROR",
                "error": type(exc).__name__,
                "authorization": "NOT_GRANTED",
                "action": "OBSERVE_ONLY",
            }

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": self.name,
                "version": self.VERSION,
                "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                "evaluations_run": self.evaluations_run,
                "incidents_evaluated": self.incidents_evaluated,
                "incidents_rejected": self.incidents_rejected,
                "invalid_operations": self.invalid_operations,
                "failed": self.failed,
                "last_error": self.last_error,
                "fail_closed": True,
                "authorization": "NOT_GRANTED",
            }

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()
