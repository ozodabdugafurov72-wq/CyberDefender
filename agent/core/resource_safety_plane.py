"""
CyberDefender Resource Safety Plane v1.1.0 - Authoritative Snapshot Contract

Purpose
-------
Coordinate bounded resource-safety decisions without taking OS actions or
owning the EventBus queue.

P0.3B addition
--------------
Production resource decisions may be driven by one authoritative
ResourceGuard snapshot per runtime cycle.  Event volume must never advance
ResourceGuard hysteresis.

Compatibility
-------------
Legacy callers that invoke evaluate() directly still use the historical
ResourceGuard.check() path unless use_committed_snapshot=True is requested.
P0.4 runtime wiring will commit one snapshot per cycle and configure the
EventBus resource gate to require committed snapshots.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import RLock
from typing import Any, Dict, Optional


class SafetyPlaneState:
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SafetyPlaneDecision:
    state: str
    resource_state: str
    backpressure_state: str
    event_rate_state: str
    allow_security_pipeline: bool
    reason: str


@dataclass(frozen=True)
class ResourceCycleSnapshot:
    """Immutable, O(1) resource state committed for one runtime cycle."""

    cycle_id: int
    state: str
    generated_at_monotonic: float
    source: str = "ResourceGuard"


class ResourceSafetyPlane:
    VERSION = "1.1.0"
    RUNTIME_CONTRACT_VERSION = "P0.4-1"

    _VALID_STATES = {
        SafetyPlaneState.NORMAL,
        SafetyPlaneState.DEGRADED,
        SafetyPlaneState.CRITICAL,
    }

    _STATE_RANK = {
        SafetyPlaneState.NORMAL: 0,
        SafetyPlaneState.DEGRADED: 1,
        SafetyPlaneState.CRITICAL: 2,
    }

    def __init__(
        self,
        resource_guard: Any | None = None,
        event_rate_limiter: Any | None = None,
        backpressure_controller: Any | None = None,
        evidence_retention: Any | None = None,
        bounded_spool: Any | None = None,
    ) -> None:
        self.resource_guard = resource_guard
        self.event_rate_limiter = event_rate_limiter
        self.backpressure_controller = backpressure_controller
        self.evidence_retention = evidence_retention
        self.bounded_spool = bounded_spool

        self._lock = RLock()
        self._state = SafetyPlaneState.NORMAL
        self._evaluations = 0
        self._failures = 0
        self._last_decision: Optional[SafetyPlaneDecision] = None

        # P0.3B authoritative resource snapshot state.  Only the latest
        # snapshot is retained, so memory usage is O(1).
        self._resource_snapshot: ResourceCycleSnapshot | None = None
        self._snapshot_commits = 0
        self._snapshot_duplicate_rejected = 0
        self._snapshot_stale_rejected = 0
        self._snapshot_invalid_rejected = 0
        self._snapshot_reads = 0
        self._legacy_resource_samples = 0

    @classmethod
    def _normalize_state(cls, value: Any) -> str:
        state = str(value).strip().upper()
        return (
            state
            if state in cls._VALID_STATES
            else SafetyPlaneState.DEGRADED
        )

    @classmethod
    def _stronger(cls, left: str, right: str) -> str:
        left = cls._normalize_state(left)
        right = cls._normalize_state(right)
        return (
            left
            if cls._STATE_RANK[left] >= cls._STATE_RANK[right]
            else right
        )

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    # ==================================================================
    # P0.3B AUTHORITATIVE RESOURCE SNAPSHOT
    # ==================================================================

    def commit_resource_snapshot(
        self,
        result: Dict[str, Any],
        cycle_id: int,
    ) -> bool:
        """Commit exactly one authoritative ResourceGuard result per cycle.

        Duplicate and stale cycle ids are rejected.  No history is retained.
        A caller can therefore prove that event bursts do not advance the
        ResourceGuard hysteresis state machine.
        """

        if not isinstance(result, dict):
            with self._lock:
                self._snapshot_invalid_rejected += 1
            return False

        if not isinstance(cycle_id, int) or isinstance(cycle_id, bool) or cycle_id < 0:
            with self._lock:
                self._snapshot_invalid_rejected += 1
            return False

        raw_state = result.get("state")
        state = str(raw_state).strip().upper() if isinstance(raw_state, str) else ""
        if state not in self._VALID_STATES:
            with self._lock:
                self._snapshot_invalid_rejected += 1
            return False

        with self._lock:
            current = self._resource_snapshot
            if current is not None:
                if cycle_id == current.cycle_id:
                    self._snapshot_duplicate_rejected += 1
                    return False
                if cycle_id < current.cycle_id:
                    self._snapshot_stale_rejected += 1
                    return False

            self._resource_snapshot = ResourceCycleSnapshot(
                cycle_id=cycle_id,
                state=state,
                generated_at_monotonic=time.monotonic(),
            )
            self._snapshot_commits += 1
            return True

    def has_committed_snapshot(
        self,
        cycle_id: int | None = None,
    ) -> bool:
        """Return whether an authoritative snapshot is available.

        When cycle_id is supplied the snapshot must belong to that exact
        runtime cycle.  This prevents a failed ResourceGuard sample from
        silently reusing an older cycle's resource state.
        """
        with self._lock:
            snapshot = self._resource_snapshot

        if snapshot is None:
            return False

        if cycle_id is None:
            return True

        if not isinstance(cycle_id, int) or isinstance(cycle_id, bool):
            return False

        return snapshot.cycle_id == cycle_id

    def get_resource_snapshot(self) -> Dict[str, Any] | None:
        with self._lock:
            snapshot = self._resource_snapshot
            if snapshot is None:
                return None
            return {
                "cycle_id": snapshot.cycle_id,
                "state": snapshot.state,
                "generated_at_monotonic": snapshot.generated_at_monotonic,
                "source": snapshot.source,
            }

    def _committed_resource_state(
        self,
        expected_cycle_id: int | None = None,
    ) -> tuple[str, str]:
        with self._lock:
            snapshot = self._resource_snapshot
            self._snapshot_reads += 1

        if snapshot is None:
            # Fail-safe, but do not claim CRITICAL resource pressure without
            # evidence. DEGRADED keeps the security pipeline alive while
            # reducing confidence in resource state.
            return SafetyPlaneState.DEGRADED, "RESOURCE_SNAPSHOT_UNAVAILABLE"

        if expected_cycle_id is not None:
            if (
                not isinstance(expected_cycle_id, int)
                or isinstance(expected_cycle_id, bool)
                or snapshot.cycle_id != expected_cycle_id
            ):
                return (
                    SafetyPlaneState.DEGRADED,
                    "RESOURCE_SNAPSHOT_STALE_OR_WRONG_CYCLE",
                )

        return snapshot.state, "AUTHORITATIVE_RESOURCE_SNAPSHOT"

    # ==================================================================
    # LEGACY RESOURCE SAMPLE
    # ==================================================================

    def _resource_state(self) -> str:
        if self.resource_guard is None:
            return SafetyPlaneState.NORMAL

        try:
            result = self.resource_guard.check()
            with self._lock:
                self._legacy_resource_samples += 1

            if isinstance(result, dict):
                return self._normalize_state(
                    result.get("state", SafetyPlaneState.NORMAL)
                )

            return SafetyPlaneState.NORMAL

        except Exception:
            with self._lock:
                self._failures += 1
            return SafetyPlaneState.DEGRADED

    def _queue_metrics(self) -> tuple[int, int]:
        if self.bounded_spool is not None:
            try:
                stats = self.bounded_spool.get_stats()

                if isinstance(stats, dict):
                    # Support both legacy BoundedDurableSpool and production
                    # DurableEventSpool v2.3 names.
                    size = max(
                        0,
                        self._safe_int(
                            stats.get("events", stats.get("pending", 0))
                        ),
                    )
                    capacity = max(
                        1,
                        self._safe_int(
                            stats.get(
                                "max_events",
                                stats.get("max_pending_events", 1),
                            ),
                            1,
                        ),
                    )
                    return size, capacity

            except Exception:
                with self._lock:
                    self._failures += 1

        return 0, 1

    def evaluate(
        self,
        queue_size: int | None = None,
        queue_capacity: int | None = None,
        *,
        use_committed_snapshot: bool = False,
        expected_cycle_id: int | None = None,
    ) -> Dict[str, Any]:
        """Evaluate the safety plane in O(1) with respect to event count.

        use_committed_snapshot=True is the P0.3B/P0.4 production-safe path:
        it never calls ResourceGuard.check() and therefore event volume cannot
        influence ResourceGuard hysteresis.
        """

        if use_committed_snapshot:
            resource_state, resource_reason = self._committed_resource_state(
                expected_cycle_id=expected_cycle_id,
            )
        else:
            resource_state = self._resource_state()
            resource_reason = "LEGACY_DIRECT_RESOURCE_SAMPLE"

        if queue_size is None or queue_capacity is None:
            spool_size, spool_capacity = self._queue_metrics()

            if queue_size is None:
                queue_size = spool_size

            if queue_capacity is None:
                queue_capacity = spool_capacity

        queue_size = max(0, self._safe_int(queue_size))
        queue_capacity = max(1, self._safe_int(queue_capacity, 1))

        backpressure_state = SafetyPlaneState.NORMAL

        if self.backpressure_controller is not None:
            try:
                result = self.backpressure_controller.evaluate(
                    queue_size,
                    queue_capacity,
                    resource_state,
                )

                if isinstance(result, dict):
                    backpressure_state = self._normalize_state(
                        result.get("state", SafetyPlaneState.NORMAL)
                    )

            except Exception:
                with self._lock:
                    self._failures += 1
                backpressure_state = SafetyPlaneState.DEGRADED

        final_state = self._stronger(resource_state, backpressure_state)

        if self.event_rate_limiter is not None:
            try:
                accepted = self.event_rate_limiter.set_state(final_state)

                if accepted is False:
                    with self._lock:
                        self._failures += 1
                    final_state = self._stronger(
                        final_state,
                        SafetyPlaneState.DEGRADED,
                    )

            except Exception:
                with self._lock:
                    self._failures += 1
                final_state = self._stronger(
                    final_state,
                    SafetyPlaneState.DEGRADED,
                )

        # SECURITY INVARIANT: resource pressure never disables the security
        # pipeline.  Downstream components only shed low-value work.
        allow_security_pipeline = True

        if final_state == SafetyPlaneState.NORMAL:
            reason = "SAFETY_PLANE_NORMAL"
        elif final_state == SafetyPlaneState.DEGRADED:
            reason = "CONTROLLED_DEGRADATION"
        else:
            reason = "CRITICAL_RESOURCE_PROTECTION"

        decision = SafetyPlaneDecision(
            state=final_state,
            resource_state=resource_state,
            backpressure_state=backpressure_state,
            event_rate_state=final_state,
            allow_security_pipeline=allow_security_pipeline,
            reason=reason,
        )

        with self._lock:
            self._state = final_state
            self._evaluations += 1
            self._last_decision = decision

        return {
            "component": "ResourceSafetyPlane",
            "version": self.VERSION,
            "state": decision.state,
            "resource_state": decision.resource_state,
            "resource_state_source": resource_reason,
            "backpressure_state": decision.backpressure_state,
            "event_rate_state": decision.event_rate_state,
            "queue": {
                "size": queue_size,
                "capacity": queue_capacity,
                "occupancy_percent": round(
                    (queue_size / queue_capacity) * 100.0,
                    2,
                ),
            },
            "allow_security_pipeline": True,
            "reason": decision.reason,
            "authoritative_snapshot": (
                self.get_resource_snapshot()
                if use_committed_snapshot
                else None
            ),
        }

    def get_runtime_policy(self) -> Dict[str, Any]:
        with self._lock:
            state = self._state

        if state == SafetyPlaneState.NORMAL:
            return {
                "state": "NORMAL",
                "allow_low": True,
                "allow_medium": True,
                "allow_high": True,
                "allow_critical": True,
                "telemetry_batching": "NORMAL",
                "deep_analysis": True,
                "ai_inference": True,
                "graph_processing": True,
                "security_evidence": "KEEP",
            }

        if state == SafetyPlaneState.DEGRADED:
            return {
                "state": "DEGRADED",
                "allow_low": True,
                "allow_medium": True,
                "allow_high": True,
                "allow_critical": True,
                "telemetry_batching": "REDUCED",
                "deep_analysis": True,
                "ai_inference": True,
                "graph_processing": True,
                "security_evidence": "KEEP",
            }

        return {
            "state": "CRITICAL",
            "allow_low": False,
            "allow_medium": False,
            "allow_high": True,
            "allow_critical": True,
            "telemetry_batching": "MAXIMUM",
            "deep_analysis": False,
            "ai_inference": False,
            "graph_processing": False,
            "security_evidence": "KEEP",
        }

    def health_check(self) -> Dict[str, Any]:
        with self._lock:
            snapshot = self._resource_snapshot
            failures = self._failures

        return {
            "component": "ResourceSafetyPlane",
            "status": "HEALTHY" if failures == 0 else "DEGRADED",
            "version": self.VERSION,
            "bounded_decision": True,
            "direct_os_actions": False,
            "event_iteration": False,
            "security_pipeline_survives_critical": True,
            "authoritative_snapshot_contract": True,
            "runtime_contract_version": self.RUNTIME_CONTRACT_VERSION,
            "snapshot_available": snapshot is not None,
            "snapshot_cycle_id": None if snapshot is None else snapshot.cycle_id,
            "components": {
                "resource_guard": self.resource_guard is not None,
                "event_rate_limiter": self.event_rate_limiter is not None,
                "backpressure_controller": self.backpressure_controller is not None,
                "evidence_retention": self.evidence_retention is not None,
                "bounded_spool": self.bounded_spool is not None,
            },
        }

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            decision = self._last_decision
            snapshot = self._resource_snapshot

            return {
                "component": "ResourceSafetyPlane",
                "version": self.VERSION,
                "runtime_contract_version": self.RUNTIME_CONTRACT_VERSION,
                "state": self._state,
                "evaluations": self._evaluations,
                "failures": self._failures,
                "snapshot_commits": self._snapshot_commits,
                "snapshot_duplicate_rejected": self._snapshot_duplicate_rejected,
                "snapshot_stale_rejected": self._snapshot_stale_rejected,
                "snapshot_invalid_rejected": self._snapshot_invalid_rejected,
                "snapshot_reads": self._snapshot_reads,
                "legacy_resource_samples": self._legacy_resource_samples,
                "snapshot_cycle_id": None if snapshot is None else snapshot.cycle_id,
                "snapshot_state": None if snapshot is None else snapshot.state,
                "last_decision": (
                    None
                    if decision is None
                    else {
                        "state": decision.state,
                        "resource_state": decision.resource_state,
                        "backpressure_state": decision.backpressure_state,
                        "event_rate_state": decision.event_rate_state,
                        "allow_security_pipeline": decision.allow_security_pipeline,
                        "reason": decision.reason,
                    }
                ),
            }
