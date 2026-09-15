from __future__ import annotations

"""CyberDefender Blast Radius Guard v1.

Pre-response scope boundary for future autonomous defense.

This component is deliberately non-executing. It validates that a requested
response is narrowly scoped before the existing dry-run authorization path is
allowed to continue. It never grants privileged OS authority.
"""

from threading import RLock
from typing import Any


class BlastRadiusError(Exception):
    """Invalid or unsafe response scope."""


class BlastRadiusGuard:
    VERSION = "1.0"
    DEFAULT_MAX_TARGETS = 1
    MAX_TEXT = 256
    MAX_ACTION = 64

    PRIVILEGED_ACTIONS = frozenset({
        "SYSTEM_MODIFY", "FIREWALL_MODIFY", "REGISTRY_MODIFY",
        "SERVICE_MODIFY", "PROCESS_TERMINATE", "PROCESS_SUSPEND",
        "DRIVER_INSTALL", "DRIVER_MODIFY", "SECURITY_POLICY_MODIFY",
        "BOOT_MODIFY", "NETWORK_BLOCK", "QUARANTINE", "ISOLATE_DEVICE",
    })

    # These remain blocked even for dry-run authorization in the current
    # SafetyAuthorizationGate contract. Keeping the rule here is defense in depth.
    L6_ACTIONS = frozenset({
        "SYSTEM_MODIFY", "DRIVER_INSTALL", "DRIVER_MODIFY",
        "SECURITY_POLICY_MODIFY", "BOOT_MODIFY",
    })

    def __init__(self, *, max_targets: int = DEFAULT_MAX_TARGETS) -> None:
        if isinstance(max_targets, bool) or not isinstance(max_targets, int):
            raise TypeError("max_targets must be int")
        if max_targets < 1:
            raise ValueError("max_targets must be >= 1")
        self.name = "BlastRadiusGuard"
        self.max_targets = max_targets
        self._lock = RLock()
        self.evaluations = 0
        self.allowed = 0
        self.denied = 0
        self.invalid_operations = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_result: dict[str, Any] | None = None

    @classmethod
    def _text(cls, value: Any, field: str, *, maximum: int | None = None) -> str:
        if not isinstance(value, str):
            raise BlastRadiusError(f"{field} must be string")
        value = value.strip()
        limit = cls.MAX_TEXT if maximum is None else maximum
        if not value or len(value) > limit:
            raise BlastRadiusError(f"invalid {field}")
        return value

    @staticmethod
    def _target_count(value: Any) -> int:
        if value is None:
            return 1
        if isinstance(value, bool) or not isinstance(value, int):
            raise BlastRadiusError("target_count must be int")
        if value < 1:
            raise BlastRadiusError("target_count must be >= 1")
        return value

    def _deny(self, reason: str, *, action: str = "UNKNOWN", target_count: int = 0) -> dict[str, Any]:
        result = {
            "component": self.name,
            "version": self.VERSION,
            "accepted": False,
            "allowed": False,
            "reason": reason,
            "requested_action": action,
            "target_count": target_count,
            "max_targets": self.max_targets,
            "authorization": "NOT_GRANTED",
            "execution_mode": "DRY_RUN",
            "real_world_effect": False,
            "fail_closed": True,
        }
        with self._lock:
            self.denied += 1
            self.last_result = result
        return result

    def evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        """Validate response scope. Never grants real authority."""
        try:
            if not isinstance(request, dict):
                raise BlastRadiusError("request must be dict")

            execution_mode = request.get("execution_mode")
            if execution_mode != "DRY_RUN":
                return self._deny("REAL_EXECUTION_NOT_SUPPORTED")

            incident_id = self._text(request.get("incident_id"), "incident_id")
            action = self._text(
                request.get("requested_action"),
                "requested_action",
                maximum=self.MAX_ACTION,
            ).upper()
            target = self._text(request.get("target"), "target")
            target_count = self._target_count(request.get("target_count"))

            if action not in self.PRIVILEGED_ACTIONS:
                return self._deny(
                    "UNSUPPORTED_ACTION",
                    action=action,
                    target_count=target_count,
                )
            if action in self.L6_ACTIONS:
                return self._deny(
                    "L6_ACTION_BLOCKED",
                    action=action,
                    target_count=target_count,
                )
            if target_count > self.max_targets:
                return self._deny(
                    "BLAST_RADIUS_EXCEEDED",
                    action=action,
                    target_count=target_count,
                )

            result = {
                "component": self.name,
                "version": self.VERSION,
                "accepted": True,
                "allowed": True,
                "reason": "BOUNDED_DRY_RUN_SCOPE",
                "incident_id": incident_id,
                "requested_action": action,
                "target": target,
                "target_count": target_count,
                "max_targets": self.max_targets,
                "authorization": "NOT_GRANTED",
                "execution_mode": "DRY_RUN",
                "real_world_effect": False,
                "fail_closed": True,
            }
            with self._lock:
                self.evaluations += 1
                self.allowed += 1
                self.last_result = result
            return result

        except BlastRadiusError as exc:
            with self._lock:
                self.evaluations += 1
                self.invalid_operations += 1
            return self._deny(type(exc).__name__)
        except Exception as exc:
            with self._lock:
                self.evaluations += 1
                self.failed += 1
                self.last_error = str(exc)
            return self._deny("ENGINE_ERROR")

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": self.name,
                "version": self.VERSION,
                "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                "evaluations": self.evaluations,
                "allowed": self.allowed,
                "denied": self.denied,
                "invalid_operations": self.invalid_operations,
                "failed": self.failed,
                "last_error": self.last_error,
                "max_targets": self.max_targets,
                "fail_closed": True,
                "real_execution_supported": False,
            }

    get_stats = health_check
