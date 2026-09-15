"""
CyberDefender EventBus Resource Safety Gate v1.1

P0.3B additions
----------------
- detailed delivery result: PUBLISHED / DEFERRED / REJECTED
- optional authoritative ResourceGuard snapshot requirement
- when snapshot mode is enabled, event publication never calls
  ResourceGuard.check(); event volume cannot advance hysteresis
- HIGH/CRITICAL security events remain protected

The existing EventBus implementation is not modified.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Dict

from agent.bus.event_bus import EventBus
from agent.core.event_rate_limiter import EventPriority
from agent.core.resource_safety_plane import (
    ResourceSafetyPlane,
    SafetyPlaneState,
)


@dataclass(frozen=True)
class GatePublishResult:
    delivered: bool
    disposition: str
    reason: str
    priority: str
    safety_state: str
    retryable: bool
    fail_closed: bool = True
    component: str = "EventBusResourceSafetyGate"
    version: str = "1.1"


class EventBusResourceSafetyGate:
    """Resource-aware delivery wrapper around the existing EventBus."""

    VERSION = "1.1"
    RUNTIME_CONTRACT_VERSION = "P0.4-1"

    DISPOSITION_PUBLISHED = "PUBLISHED"
    DISPOSITION_DEFERRED = "DEFERRED"
    DISPOSITION_REJECTED = "REJECTED"

    def __init__(
        self,
        event_bus: EventBus,
        safety_plane: ResourceSafetyPlane,
        *,
        require_committed_snapshot: bool = False,
        enforce_cycle_binding: bool = False,
    ) -> None:
        if event_bus is None:
            raise ValueError("event_bus is required")

        if safety_plane is None:
            raise ValueError("safety_plane is required")

        self.event_bus = event_bus
        self.safety_plane = safety_plane
        self.require_committed_snapshot = bool(require_committed_snapshot)
        self.enforce_cycle_binding = bool(enforce_cycle_binding)

        self._lock = RLock()
        self._required_cycle_id: int | None = None
        self._cycle_bindings = 0
        self._cycle_bind_rejected = 0
        self._attempted = 0
        self._admitted = 0
        self._deferred = 0
        self._rejected = 0
        self._publish_failed = 0
        self._policy_deferred = 0
        self._rate_limited = 0
        self._snapshot_deferred = 0
        self._failures = 0
        self._last_reason: str | None = None

    def bind_cycle(self, cycle_id: int) -> bool:
        """Bind delivery decisions to one exact runtime cycle.

        P0.4 production wiring calls this once at the start of each cycle,
        before the ResourceGuard sample is committed.  A previous cycle's
        snapshot is therefore never silently reused after a sampling failure.
        """
        if not self.enforce_cycle_binding:
            return True

        if (
            not isinstance(cycle_id, int)
            or isinstance(cycle_id, bool)
            or cycle_id < 0
        ):
            with self._lock:
                self._cycle_bind_rejected += 1
            return False

        with self._lock:
            current = self._required_cycle_id
            if current is not None and cycle_id < current:
                self._cycle_bind_rejected += 1
                return False

            self._required_cycle_id = cycle_id
            self._cycle_bindings += 1
            return True

    def required_cycle_id(self) -> int | None:
        with self._lock:
            return self._required_cycle_id

    def _snapshot_ready(self) -> bool:
        if not self.require_committed_snapshot:
            return True

        if self.enforce_cycle_binding:
            cycle_id = self.required_cycle_id()
            if cycle_id is None:
                return False
            return self.safety_plane.has_committed_snapshot(cycle_id)

        return self.safety_plane.has_committed_snapshot()

    @staticmethod
    def _severity(event: Any) -> str:
        if isinstance(event, dict):
            value = event.get("severity", "")
            if isinstance(value, str):
                return value.strip().upper()

            data = event.get("data")
            if isinstance(data, dict):
                value = data.get("severity", "")
                if isinstance(value, str):
                    return value.strip().upper()

        value = getattr(event, "severity", "")
        if isinstance(value, str):
            return value.strip().upper()

        return ""

    @staticmethod
    def _event_type(event: Any) -> str:
        if isinstance(event, dict):
            value = event.get("event_type", "")
            return value.strip().upper() if isinstance(value, str) else ""

        value = getattr(event, "event_type", "")
        return value.strip().upper() if isinstance(value, str) else ""

    @staticmethod
    def _producer(event: Any) -> str:
        if isinstance(event, dict):
            value = event.get("source", "unknown")
            if isinstance(value, str) and value.strip():
                return value.strip()[:128]

            data = event.get("data")
            if isinstance(data, dict):
                value = data.get("source", "unknown")
                if isinstance(value, str) and value.strip():
                    return value.strip()[:128]

        value = getattr(event, "source", "unknown")
        if isinstance(value, str) and value.strip():
            return value.strip()[:128]

        return "unknown"

    @classmethod
    def _priority(cls, event: Any) -> EventPriority:
        event_type = cls._event_type(event)
        severity = cls._severity(event)

        if event_type == "RESOURCE_STATUS":
            data = event.get("data") if isinstance(event, dict) else None
            if isinstance(data, dict):
                resource = data.get("state", "")
                if isinstance(resource, str):
                    resource = resource.strip().upper()
                    if resource == SafetyPlaneState.CRITICAL:
                        return EventPriority.CRITICAL
                    if resource == SafetyPlaneState.DEGRADED:
                        return EventPriority.HIGH

        if severity == "CRITICAL":
            return EventPriority.CRITICAL
        if severity in {"HIGH", "ALERT"}:
            return EventPriority.HIGH
        if severity in {"WARNING", "MEDIUM"}:
            return EventPriority.MEDIUM

        return EventPriority.LOW

    @staticmethod
    def _result(
        *,
        delivered: bool,
        disposition: str,
        reason: str,
        priority: EventPriority,
        safety_state: str,
        retryable: bool,
    ) -> GatePublishResult:
        return GatePublishResult(
            delivered=delivered,
            disposition=disposition,
            reason=reason,
            priority=priority.name,
            safety_state=safety_state,
            retryable=retryable,
        )

    def publish_detailed(self, event: Any) -> GatePublishResult:
        """Return a delivery decision without conflating deferral with reject."""

        with self._lock:
            self._attempted += 1

        if event is None:
            with self._lock:
                self._rejected += 1
                self._last_reason = "INVALID_EVENT"
            return self._result(
                delivered=False,
                disposition=self.DISPOSITION_REJECTED,
                reason="INVALID_EVENT",
                priority=EventPriority.LOW,
                safety_state=SafetyPlaneState.DEGRADED,
                retryable=False,
            )

        priority = self._priority(event)

        try:
            # P0.3B production-safe snapshot contract.  If a committed
            # snapshot is required but absent, low-value work is deferred;
            # HIGH/CRITICAL evidence remains allowed.
            if (
                self.require_committed_snapshot
                and not self._snapshot_ready()
                and priority in {EventPriority.LOW, EventPriority.MEDIUM}
            ):
                with self._lock:
                    self._deferred += 1
                    self._snapshot_deferred += 1
                    self._last_reason = "RESOURCE_SNAPSHOT_UNAVAILABLE"
                return self._result(
                    delivered=False,
                    disposition=self.DISPOSITION_DEFERRED,
                    reason="RESOURCE_SNAPSHOT_UNAVAILABLE",
                    priority=priority,
                    safety_state=SafetyPlaneState.DEGRADED,
                    retryable=True,
                )

            stats = self.event_bus.get_stats()
            queue_size = int(stats.get("queue_size", 0))
            queue_capacity = int(stats.get("queue_capacity", 1))

            expected_cycle_id = (
                self.required_cycle_id()
                if self.enforce_cycle_binding
                else None
            )

            decision = self.safety_plane.evaluate(
                queue_size=queue_size,
                queue_capacity=queue_capacity,
                use_committed_snapshot=self.require_committed_snapshot,
                expected_cycle_id=expected_cycle_id,
            )

            state = str(
                decision.get("state", SafetyPlaneState.DEGRADED)
            ).strip().upper()

            producer = self._producer(event)
            policy = self.safety_plane.get_runtime_policy()

            allowed_by_policy = True

            if state == SafetyPlaneState.CRITICAL:
                if priority == EventPriority.LOW:
                    allowed_by_policy = bool(policy.get("allow_low", False))
                elif priority == EventPriority.MEDIUM:
                    allowed_by_policy = bool(policy.get("allow_medium", False))
                else:
                    allowed_by_policy = True

            elif state == SafetyPlaneState.DEGRADED:
                if priority == EventPriority.LOW:
                    allowed_by_policy = bool(policy.get("allow_low", True))

            if not allowed_by_policy:
                with self._lock:
                    self._deferred += 1
                    self._policy_deferred += 1
                    self._last_reason = "RESOURCE_POLICY_THROTTLE"
                return self._result(
                    delivered=False,
                    disposition=self.DISPOSITION_DEFERRED,
                    reason="RESOURCE_POLICY_THROTTLE",
                    priority=priority,
                    safety_state=state,
                    retryable=True,
                )

            limiter = self.safety_plane.event_rate_limiter
            if limiter is not None:
                admission = limiter.admit(
                    producer=producer,
                    priority=priority,
                )
                if not admission.admitted:
                    with self._lock:
                        self._deferred += 1
                        self._rate_limited += 1
                        self._last_reason = admission.reason
                    return self._result(
                        delivered=False,
                        disposition=self.DISPOSITION_DEFERRED,
                        reason=admission.reason,
                        priority=priority,
                        safety_state=state,
                        retryable=True,
                    )

            published = self.event_bus.publish(event)

            if not published:
                with self._lock:
                    self._deferred += 1
                    self._publish_failed += 1
                    self._last_reason = "EVENTBUS_DEFERRED"
                return self._result(
                    delivered=False,
                    disposition=self.DISPOSITION_DEFERRED,
                    reason="EVENTBUS_DEFERRED",
                    priority=priority,
                    safety_state=state,
                    retryable=True,
                )

            with self._lock:
                self._admitted += 1
                self._last_reason = "ADMITTED"

            return self._result(
                delivered=True,
                disposition=self.DISPOSITION_PUBLISHED,
                reason="ADMITTED",
                priority=priority,
                safety_state=state,
                retryable=False,
            )

        except Exception as exc:
            # Delivery boundary failures are retryable.  Upstream durable
            # storage decides whether this becomes PERSISTED_DEFERRED.
            with self._lock:
                self._deferred += 1
                self._failures += 1
                self._last_reason = f"GATE_FAILURE:{type(exc).__name__}"
            return self._result(
                delivered=False,
                disposition=self.DISPOSITION_DEFERRED,
                reason=f"GATE_FAILURE:{type(exc).__name__}",
                priority=priority,
                safety_state=SafetyPlaneState.DEGRADED,
                retryable=True,
            )

    def publish(self, event: Any) -> bool:
        """Backward-compatible boolean API."""
        return self.publish_detailed(event).delivered

    def health_check(self) -> Dict[str, Any]:
        snapshot_missing = (
            self.require_committed_snapshot
            and not self._snapshot_ready()
        )

        # In cycle-bound production mode, bootstrap is not unhealthy merely
        # because the first runtime cycle has not started yet.  Once a cycle
        # is bound, the exact-cycle snapshot becomes mandatory.
        cycle_id = self.required_cycle_id()
        bootstrap_wait = (
            self.enforce_cycle_binding
            and cycle_id is None
        )

        with self._lock:
            return {
                "component": "EventBusResourceSafetyGate",
                "status": (
                    "HEALTHY"
                    if (
                        self._failures == 0
                        and (not snapshot_missing or bootstrap_wait)
                    )
                    else "DEGRADED"
                ),
                "version": self.VERSION,
                "runtime_contract_version": self.RUNTIME_CONTRACT_VERSION,
                "bounded": True,
                "direct_os_actions": False,
                "critical_security_preservation": True,
                "detailed_delivery_contract": True,
                "require_committed_snapshot": self.require_committed_snapshot,
                "enforce_cycle_binding": self.enforce_cycle_binding,
                "required_cycle_id": cycle_id,
                "snapshot_available": self._snapshot_ready(),
                "event_bus_version": getattr(self.event_bus, "VERSION", "UNKNOWN"),
                "safety_plane_version": getattr(
                    self.safety_plane, "VERSION", "UNKNOWN"
                ),
            }

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "component": "EventBusResourceSafetyGate",
                "version": self.VERSION,
                "attempted": self._attempted,
                "admitted": self._admitted,
                "deferred": self._deferred,
                "rejected": self._rejected,
                # Legacy key retained for compatibility; policy deferral is
                # no longer a hard rejection in the detailed contract.
                "policy_rejected": self._policy_deferred,
                "policy_deferred": self._policy_deferred,
                "snapshot_deferred": self._snapshot_deferred,
                "rate_limited": self._rate_limited,
                "publish_failed": self._publish_failed,
                "failures": self._failures,
                "runtime_contract_version": self.RUNTIME_CONTRACT_VERSION,
                "enforce_cycle_binding": self.enforce_cycle_binding,
                "required_cycle_id": self._required_cycle_id,
                "cycle_bindings": self._cycle_bindings,
                "cycle_bind_rejected": self._cycle_bind_rejected,
                "last_reason": self._last_reason,
            }
