from __future__ import annotations

"""CyberDefender Recovery Planner v1 foundation.

Recovery is a security function, but this component is intentionally plan-only.
It never invokes OS mutation, rollback commands, subprocesses, registry,
firewall, services, drivers, or networking changes.

It consumes post-action verification and returns a bounded deterministic plan.
Actual recovery execution remains blocked until a future independently verified
recovery executor exists.
"""

from threading import RLock
from typing import Any


class RecoveryPlanningError(Exception):
    """Recovery planning contract violation."""


class RecoveryPlanner:
    VERSION = "1.0"
    DEFAULT_MAX_STEPS = 8

    FAILURE_PLAN = (
        "STOP_AUTONOMOUS_RESPONSE",
        "PRESERVE_EVIDENCE",
        "ESCALATE_HUMAN",
        "VERIFY_AUTHORITATIVE_STATE",
        "PREPARE_BOUNDED_ROLLBACK",
        "REVERIFY_AFTER_RECOVERY",
    )

    def __init__(self, *, max_steps: int = DEFAULT_MAX_STEPS) -> None:
        if isinstance(max_steps, bool) or not isinstance(max_steps, int):
            raise TypeError("max_steps must be int")
        if max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        self.name = "RecoveryPlanner"
        self.max_steps = max_steps
        self._lock = RLock()
        self.plans = 0
        self.no_recovery_required = 0
        self.recovery_required = 0
        self.invalid_operations = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_result: dict[str, Any] | None = None

    def _store(self, result: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.plans += 1
            if result.get("recovery_required"):
                self.recovery_required += 1
            else:
                self.no_recovery_required += 1
            self.last_result = result
        return result

    def plan(
        self,
        verification_result: dict[str, Any],
        *,
        request: dict[str, Any] | None = None,
        action_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a bounded recovery plan. Never executes recovery."""
        try:
            if not isinstance(verification_result, dict):
                raise RecoveryPlanningError("verification_result must be dict")
            if request is not None and not isinstance(request, dict):
                raise RecoveryPlanningError("request must be dict")
            if action_result is not None and not isinstance(action_result, dict):
                raise RecoveryPlanningError("action_result must be dict")

            verified = verification_result.get("accepted") is True and verification_result.get("verified") is True
            no_effect = verification_result.get("real_world_effect_observed") is False
            recovery_required = bool(verification_result.get("recovery_required"))

            if verified and no_effect and not recovery_required:
                return self._store({
                    "component": self.name,
                    "version": self.VERSION,
                    "accepted": True,
                    "recovery_required": False,
                    "recovery_outcome": "NO_RECOVERY_REQUIRED",
                    "steps": [],
                    "step_count": 0,
                    "recovery_executed": False,
                    "execution_supported": False,
                    "real_world_effect": False,
                    "authorization": "NOT_GRANTED",
                    "fail_closed": True,
                })

            steps = list(self.FAILURE_PLAN[: self.max_steps])
            return self._store({
                "component": self.name,
                "version": self.VERSION,
                "accepted": True,
                "recovery_required": True,
                "recovery_outcome": "RECOVERY_REQUIRED_BLOCKED",
                "steps": steps,
                "step_count": len(steps),
                "recovery_executed": False,
                "execution_supported": False,
                "real_world_effect": False,
                "authorization": "NOT_GRANTED",
                "escalation_required": True,
                "fail_closed": True,
            })

        except RecoveryPlanningError as exc:
            with self._lock:
                self.invalid_operations += 1
            return self._store({
                "component": self.name,
                "version": self.VERSION,
                "accepted": False,
                "recovery_required": True,
                "recovery_outcome": "RECOVERY_STATE_UNCERTAIN",
                "reason": type(exc).__name__,
                "steps": list(self.FAILURE_PLAN[: self.max_steps]),
                "step_count": min(len(self.FAILURE_PLAN), self.max_steps),
                "recovery_executed": False,
                "execution_supported": False,
                "real_world_effect": False,
                "authorization": "NOT_GRANTED",
                "escalation_required": True,
                "fail_closed": True,
            })
        except Exception as exc:
            with self._lock:
                self.failed += 1
                self.last_error = str(exc)
            return self._store({
                "component": self.name,
                "version": self.VERSION,
                "accepted": False,
                "recovery_required": True,
                "recovery_outcome": "RECOVERY_ENGINE_ERROR",
                "steps": list(self.FAILURE_PLAN[: self.max_steps]),
                "step_count": min(len(self.FAILURE_PLAN), self.max_steps),
                "recovery_executed": False,
                "execution_supported": False,
                "real_world_effect": False,
                "authorization": "NOT_GRANTED",
                "escalation_required": True,
                "fail_closed": True,
            })

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": self.name,
                "version": self.VERSION,
                "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                "plans": self.plans,
                "no_recovery_required": self.no_recovery_required,
                "recovery_required": self.recovery_required,
                "invalid_operations": self.invalid_operations,
                "failed": self.failed,
                "last_error": self.last_error,
                "max_steps": self.max_steps,
                "fail_closed": True,
                "plan_only": True,
                "real_execution_supported": False,
            }

    get_stats = health_check
