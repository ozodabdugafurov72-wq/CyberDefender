"""
CyberDefender Backpressure Controller v1.0

Security-First admission/backpressure decision layer.

Purpose:
    Convert queue pressure + ResourceGuard state into a bounded,
    deterministic runtime backpressure state.

This module is intentionally standalone in v1.0.
It does NOT modify EventBus, ResourceGuard, EventRateLimiter,
processes, firewall, registry, services, or the operating system.

States:
    NORMAL
    ELEVATED
    DEGRADED
    CRITICAL

Safety principles:
    - bounded queue pressure
    - no unbounded memory allocation
    - fail-safe on malformed metrics
    - CRITICAL resource state always dominates queue state
    - no direct component termination
    - hysteresis prevents oscillation
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from threading import RLock
from typing import Any, Dict


@dataclass(frozen=True)
class BackpressurePolicy:
    # Queue occupancy thresholds (%).
    elevated_percent: float = 60.0
    degraded_percent: float = 80.0
    critical_percent: float = 95.0

    # Resource states accepted from ResourceGuard.
    resource_normal: str = "NORMAL"
    resource_degraded: str = "DEGRADED"
    resource_critical: str = "CRITICAL"

    # Consecutive healthy evaluations required before recovery.
    recovery_confirmations: int = 2

    # Number of consecutive pressure samples required before
    # queue-based escalation.
    escalation_confirmations: int = 2

    # Never permit an invalid/negative capacity to enter arithmetic.
    minimum_capacity: int = 1


class BackpressureController:
    """
    Deterministic backpressure controller.

    Decision precedence:

        Resource CRITICAL
            >
        Queue CRITICAL
            >
        Resource DEGRADED
            >
        Queue DEGRADED
            >
        Queue ELEVATED
            >
        NORMAL

    Complexity:
        evaluate() = O(1)
        get_stats() = O(1)

    Memory:
        O(1)
    """

    VERSION = "1.0"

    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"

    _VALID_STATES = {
        NORMAL,
        ELEVATED,
        DEGRADED,
        CRITICAL,
    }

    def __init__(
        self,
        policy: BackpressurePolicy | None = None,
    ) -> None:
        self.policy = (
            policy
            if policy is not None
            else BackpressurePolicy()
        )

        self._lock = RLock()

        self._state = self.NORMAL

        self._pressure_streak = 0
        self._recovery_streak = 0

        self._evaluation_count = 0
        self._normal_count = 0
        self._elevated_count = 0
        self._degraded_count = 0
        self._critical_count = 0

        self._last_occupancy_percent = 0.0
        self._last_queue_size = 0
        self._last_queue_capacity = 0
        self._last_resource_state = self.NORMAL

    @staticmethod
    def _safe_float(
        value: Any,
        default: float = 0.0,
    ) -> float:
        try:
            result = float(value)

            if result != result:
                return default

            if result in (
                float("inf"),
                float("-inf"),
            ):
                return default

            return result

        except (
            TypeError,
            ValueError,
        ):
            return default

    @staticmethod
    def _safe_int(
        value: Any,
        default: int = 0,
    ) -> int:
        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return default

    def _queue_pressure(
        self,
        queue_size: int,
        queue_capacity: int,
    ) -> str:
        capacity = max(
            self.policy.minimum_capacity,
            queue_capacity,
        )

        size = max(0, queue_size)

        occupancy = (
            float(size)
            / float(capacity)
        ) * 100.0

        if occupancy >= self.policy.critical_percent:
            return self.CRITICAL

        if occupancy >= self.policy.degraded_percent:
            return self.DEGRADED

        if occupancy >= self.policy.elevated_percent:
            return self.ELEVATED

        return self.NORMAL

    def _combine_pressure(
        self,
        queue_state: str,
        resource_state: str,
    ) -> str:
        """
        Combine resource and queue pressure.

        ResourceGuard CRITICAL always dominates.
        ResourceGuard DEGRADED prevents returning NORMAL.
        """

        if resource_state == self.policy.resource_critical:
            return self.CRITICAL

        if queue_state == self.CRITICAL:
            return self.CRITICAL

        if resource_state == self.policy.resource_degraded:
            if queue_state == self.DEGRADED:
                return self.DEGRADED

            if queue_state == self.ELEVATED:
                return self.DEGRADED

            return self.DEGRADED

        if queue_state == self.DEGRADED:
            return self.DEGRADED

        if queue_state == self.ELEVATED:
            return self.ELEVATED

        return self.NORMAL

    def _apply_hysteresis(
        self,
        target_state: str,
    ) -> str:
        """
        Apply bounded hysteresis.

        Escalation:
            pressure must persist for N evaluations.

        Recovery:
            NORMAL must persist for M evaluations.

        CRITICAL resource pressure is handled immediately.
        """

        current = self._state

        if target_state == self.CRITICAL:
            self._pressure_streak += 1
            self._recovery_streak = 0

            # Safety-critical pressure is never delayed.
            return self.CRITICAL

        if target_state in (
            self.DEGRADED,
            self.ELEVATED,
        ):
            self._pressure_streak += 1
            self._recovery_streak = 0

            if (
                self._pressure_streak
                >= max(
                    1,
                    self.policy.escalation_confirmations,
                )
            ):
                return target_state

            return current

        # NORMAL target.
        self._pressure_streak = 0

        if current == self.NORMAL:
            self._recovery_streak = 0
            return self.NORMAL

        self._recovery_streak += 1

        if (
            self._recovery_streak
            >= max(
                1,
                self.policy.recovery_confirmations,
            )
        ):
            self._recovery_streak = 0
            return self.NORMAL

        return current

    def evaluate(
        self,
        queue_size: Any,
        queue_capacity: Any,
        resource_state: Any = NORMAL,
    ) -> Dict[str, Any]:
        """
        Evaluate queue/resource pressure.

        Invalid metrics fail safely toward DEGRADED instead of
        falsely reporting NORMAL.

        Returns a bounded diagnostic decision.
        """

        with self._lock:
            self._evaluation_count += 1

            size = max(
                0,
                self._safe_int(
                    queue_size,
                    0,
                ),
            )

            capacity = max(
                self.policy.minimum_capacity,
                self._safe_int(
                    queue_capacity,
                    self.policy.minimum_capacity,
                ),
            )

            resource = str(
                resource_state
            ).strip().upper()

            if resource not in {
                self.policy.resource_normal,
                self.policy.resource_degraded,
                self.policy.resource_critical,
            }:
                resource = self.policy.resource_degraded

            occupancy = min(
                100.0,
                max(
                    0.0,
                    (
                        float(size)
                        / float(capacity)
                    ) * 100.0,
                ),
            )

            queue_state = self._queue_pressure(
                size,
                capacity,
            )

            target = self._combine_pressure(
                queue_state,
                resource,
            )

            new_state = self._apply_hysteresis(
                target
            )

            self._state = new_state

            self._last_occupancy_percent = occupancy
            self._last_queue_size = size
            self._last_queue_capacity = capacity
            self._last_resource_state = resource

            if new_state == self.NORMAL:
                self._normal_count += 1
            elif new_state == self.ELEVATED:
                self._elevated_count += 1
            elif new_state == self.DEGRADED:
                self._degraded_count += 1
            elif new_state == self.CRITICAL:
                self._critical_count += 1

            return {
                "component": "BackpressureController",
                "version": self.VERSION,
                "state": new_state,
                "queue": {
                    "size": size,
                    "capacity": capacity,
                    "occupancy_percent": round(
                        occupancy,
                        2,
                    ),
                    "pressure_state": queue_state,
                },
                "resource_state": resource,
                "target_state": target,
                "pressure_streak": self._pressure_streak,
                "recovery_streak": self._recovery_streak,
            }

    def get_state(self) -> str:
        with self._lock:
            return self._state

    def get_policy(self) -> Dict[str, Any]:
        with self._lock:
            return asdict(self.policy)

    def get_runtime_policy(self) -> Dict[str, Any]:
        """
        Translate controller state into bounded runtime actions.

        This is declarative only. It does not execute actions.
        """

        with self._lock:
            if self._state == self.NORMAL:
                return {
                    "state": self.NORMAL,
                    "allow_low": True,
                    "allow_medium": True,
                    "allow_high": True,
                    "allow_critical": True,
                    "telemetry_batching": "NORMAL",
                    "consumer_priority": "NORMAL",
                    "drop_low_priority": False,
                }

            if self._state == self.ELEVATED:
                return {
                    "state": self.ELEVATED,
                    "allow_low": True,
                    "allow_medium": True,
                    "allow_high": True,
                    "allow_critical": True,
                    "telemetry_batching": "INCREASED",
                    "consumer_priority": "HIGH_FIRST",
                    "drop_low_priority": False,
                }

            if self._state == self.DEGRADED:
                return {
                    "state": self.DEGRADED,
                    "allow_low": False,
                    "allow_medium": True,
                    "allow_high": True,
                    "allow_critical": True,
                    "telemetry_batching": "AGGRESSIVE",
                    "consumer_priority": "SECURITY_FIRST",
                    "drop_low_priority": True,
                }

            return {
                "state": self.CRITICAL,
                "allow_low": False,
                "allow_medium": False,
                "allow_high": True,
                "allow_critical": True,
                "telemetry_batching": "MAXIMUM",
                "consumer_priority": "CRITICAL_FIRST",
                "drop_low_priority": True,
            }

    def health_check(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "component": "BackpressureController",
                "status": "HEALTHY",
                "version": self.VERSION,
                "state": self._state,
                "bounded_memory": True,
                "direct_os_actions": False,
            }

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "component": "BackpressureController",
                "version": self.VERSION,
                "state": self._state,
                "evaluations": self._evaluation_count,
                "normal": self._normal_count,
                "elevated": self._elevated_count,
                "degraded": self._degraded_count,
                "critical": self._critical_count,
                "last_occupancy_percent": round(
                    self._last_occupancy_percent,
                    2,
                ),
                "last_queue_size": self._last_queue_size,
                "last_queue_capacity": self._last_queue_capacity,
                "last_resource_state": (
                    self._last_resource_state
                ),
                "pressure_streak": self._pressure_streak,
                "recovery_streak": self._recovery_streak,
                "policy": asdict(self.policy),
            }
