"""
CyberDefender Priority-Based Evidence Retention v1.0

Security-first retention policy for event/evidence admission.

Design goals:
    - Preserve CRITICAL/HIGH security evidence under pressure.
    - Allow MEDIUM evidence to be retained while capacity permits.
    - Defer/drop LOW evidence first under pressure.
    - Never allocate unbounded memory.
    - O(1) decision time.
    - Declarative only: this module never deletes files or events itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict


class EvidencePriority(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


class RetentionAction:
    KEEP = "KEEP"
    BATCH = "BATCH"
    DEFER = "DEFER"
    DROP = "DROP"


@dataclass(frozen=True)
class RetentionPolicy:
    # Maximum occupancy before lower-priority evidence is reduced.
    batch_threshold_percent: float = 60.0
    defer_threshold_percent: float = 80.0
    drop_threshold_percent: float = 95.0

    # Security evidence is protected independently of queue pressure.
    protect_high: bool = True
    protect_critical: bool = True

    # MEDIUM remains available longer than LOW.
    medium_batch_at_degraded: bool = True
    low_drop_at_degraded: bool = False


@dataclass(frozen=True)
class RetentionDecision:
    priority: str
    pressure_state: str
    action: str
    protected: bool
    reason: str


class EvidenceRetentionPolicy:
    """
    O(1) priority-based evidence retention decision engine.

    This component makes a decision only. It does not mutate the
    EventBus, Durable Spool, filesystem, or operating system.
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
        policy: RetentionPolicy | None = None,
    ) -> None:
        self.policy = policy or RetentionPolicy()

        self._decisions = 0
        self._kept = 0
        self._batched = 0
        self._deferred = 0
        self._dropped = 0
        self._protected = 0

        self._last_decision: RetentionDecision | None = None

    @staticmethod
    def _priority(priority: Any) -> EvidencePriority:
        if isinstance(priority, EvidencePriority):
            return priority

        if isinstance(priority, str):
            try:
                return EvidencePriority[
                    priority.strip().upper()
                ]
            except KeyError:
                return EvidencePriority.MEDIUM

        try:
            return EvidencePriority(int(priority))
        except (TypeError, ValueError):
            return EvidencePriority.MEDIUM

    @staticmethod
    def _state(state: Any) -> str:
        value = str(state).strip().upper()

        if value in {
            EvidenceRetentionPolicy.NORMAL,
            EvidenceRetentionPolicy.ELEVATED,
            EvidenceRetentionPolicy.DEGRADED,
            EvidenceRetentionPolicy.CRITICAL,
        }:
            return value

        # Unknown pressure is fail-safe.
        return EvidenceRetentionPolicy.DEGRADED

    @staticmethod
    def _occupancy(value: Any) -> float:
        try:
            value = float(value)
        except (TypeError, ValueError):
            return 100.0

        if value != value:
            return 100.0

        if value == float("inf"):
            return 100.0

        if value == float("-inf"):
            return 0.0

        return min(100.0, max(0.0, value))

    def decide(
        self,
        priority: Any,
        pressure_state: Any = NORMAL,
        occupancy_percent: Any = 0.0,
    ) -> RetentionDecision:
        """
        Return a bounded retention decision.

        Security precedence:

            CRITICAL evidence -> KEEP
            HIGH evidence     -> KEEP
            then pressure-dependent MEDIUM/LOW handling.
        """

        p = self._priority(priority)
        state = self._state(pressure_state)
        occupancy = self._occupancy(occupancy_percent)

        protected = (
            (p == EvidencePriority.CRITICAL
             and self.policy.protect_critical)
            or
            (p == EvidencePriority.HIGH
             and self.policy.protect_high)
        )

        if protected:
            action = RetentionAction.KEEP
            reason = "SECURITY_EVIDENCE_PROTECTED"

        elif p == EvidencePriority.MEDIUM:
            if (
                state == self.CRITICAL
                or occupancy >= self.policy.drop_threshold_percent
            ):
                action = RetentionAction.DEFER
                reason = "MEDIUM_DEFERRED_UNDER_CRITICAL_PRESSURE"

            elif (
                state == self.DEGRADED
                or occupancy >= self.policy.defer_threshold_percent
            ):
                action = RetentionAction.BATCH
                reason = "MEDIUM_BATCHED_UNDER_PRESSURE"

            elif (
                state == self.ELEVATED
                or occupancy >= self.policy.batch_threshold_percent
            ):
                action = RetentionAction.BATCH
                reason = "MEDIUM_BATCHED"

            else:
                action = RetentionAction.KEEP
                reason = "MEDIUM_WITHIN_BUDGET"

        else:
            # LOW priority.
            if state == self.CRITICAL:
                action = RetentionAction.DROP
                reason = "LOW_DROPPED_UNDER_CRITICAL_PRESSURE"

            elif (
                state == self.DEGRADED
                and self.policy.low_drop_at_degraded
            ):
                action = RetentionAction.DROP
                reason = "LOW_DROPPED_UNDER_DEGRADED_PRESSURE"

            elif occupancy >= self.policy.drop_threshold_percent:
                action = RetentionAction.DROP
                reason = "LOW_DROPPED_AT_QUEUE_LIMIT"

            elif (
                state == self.DEGRADED
                or occupancy >= self.policy.defer_threshold_percent
            ):
                action = RetentionAction.DEFER
                reason = "LOW_DEFERRED_UNDER_PRESSURE"

            elif (
                state == self.ELEVATED
                or occupancy >= self.policy.batch_threshold_percent
            ):
                action = RetentionAction.BATCH
                reason = "LOW_BATCHED"

            else:
                action = RetentionAction.KEEP
                reason = "LOW_WITHIN_BUDGET"

        decision = RetentionDecision(
            priority=p.name,
            pressure_state=state,
            action=action,
            protected=protected,
            reason=reason,
        )

        self._decisions += 1

        if protected:
            self._protected += 1

        if action == RetentionAction.KEEP:
            self._kept += 1
        elif action == RetentionAction.BATCH:
            self._batched += 1
        elif action == RetentionAction.DEFER:
            self._deferred += 1
        elif action == RetentionAction.DROP:
            self._dropped += 1

        self._last_decision = decision
        return decision

    def should_keep(
        self,
        priority: Any,
        pressure_state: Any = NORMAL,
        occupancy_percent: Any = 0.0,
    ) -> bool:
        return self.decide(
            priority,
            pressure_state,
            occupancy_percent,
        ).action == RetentionAction.KEEP

    def is_security_protected(
        self,
        priority: Any,
    ) -> bool:
        p = self._priority(priority)

        return (
            p == EvidencePriority.CRITICAL
            and self.policy.protect_critical
        ) or (
            p == EvidencePriority.HIGH
            and self.policy.protect_high
        )

    def get_runtime_policy(
        self,
        pressure_state: Any,
    ) -> Dict[str, Any]:
        """
        Declarative runtime policy.

        No direct action is performed.
        """

        state = self._state(pressure_state)

        if state == self.NORMAL:
            return {
                "state": state,
                "critical": RetentionAction.KEEP,
                "high": RetentionAction.KEEP,
                "medium": RetentionAction.KEEP,
                "low": RetentionAction.KEEP,
            }

        if state == self.ELEVATED:
            return {
                "state": state,
                "critical": RetentionAction.KEEP,
                "high": RetentionAction.KEEP,
                "medium": RetentionAction.BATCH,
                "low": RetentionAction.BATCH,
            }

        if state == self.DEGRADED:
            return {
                "state": state,
                "critical": RetentionAction.KEEP,
                "high": RetentionAction.KEEP,
                "medium": RetentionAction.BATCH,
                "low": (
                    RetentionAction.DROP
                    if self.policy.low_drop_at_degraded
                    else RetentionAction.DEFER
                ),
            }

        return {
            "state": state,
            "critical": RetentionAction.KEEP,
            "high": RetentionAction.KEEP,
            "medium": RetentionAction.DEFER,
            "low": RetentionAction.DROP,
        }

    def health_check(self) -> Dict[str, Any]:
        return {
            "component": "EvidenceRetentionPolicy",
            "status": "HEALTHY",
            "version": self.VERSION,
            "bounded_memory": True,
            "security_protection": True,
            "direct_os_actions": False,
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "component": "EvidenceRetentionPolicy",
            "version": self.VERSION,
            "decisions": self._decisions,
            "kept": self._kept,
            "batched": self._batched,
            "deferred": self._deferred,
            "dropped": self._dropped,
            "protected": self._protected,
            "last_decision": (
                None
                if self._last_decision is None
                else {
                    "priority": self._last_decision.priority,
                    "pressure_state": (
                        self._last_decision.pressure_state
                    ),
                    "action": self._last_decision.action,
                    "protected": self._last_decision.protected,
                    "reason": self._last_decision.reason,
                }
            ),
        }
