"""
CyberDefender Event Rate Limiter v1.2

Security-First event admission control with reserved security capacity.

v1.2 changes:
    - Separate normal/global capacity from protected security reserve.
    - HIGH and CRITICAL events use the security reserve.
    - LOW/MEDIUM events cannot consume the security reserve.
    - Producer tokens are checked before global tokens so a rejected
      global admission does not consume producer budget.
    - State transitions immediately update existing producer buckets.
    - All capacities remain bounded.

Non-responsibilities:
    - No EventBus publishing.
    - No persistence.
    - No process termination.
    - No OS modification.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict


class EventPriority(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


@dataclass(frozen=True)
class RatePolicy:
    max_producers: int = 256

    # Per-producer budgets: NORMAL
    normal_low_rate: float = 20.0
    normal_low_burst: float = 20.0
    normal_medium_rate: float = 50.0
    normal_medium_burst: float = 50.0
    normal_high_rate: float = 100.0
    normal_high_burst: float = 100.0
    normal_critical_rate: float = 200.0
    normal_critical_burst: float = 200.0

    # Per-producer budgets: DEGRADED
    degraded_low_rate: float = 5.0
    degraded_low_burst: float = 5.0
    degraded_medium_rate: float = 25.0
    degraded_medium_burst: float = 25.0
    degraded_high_rate: float = 75.0
    degraded_high_burst: float = 75.0
    degraded_critical_rate: float = 150.0
    degraded_critical_burst: float = 150.0

    # Per-producer budgets: CRITICAL
    critical_low_rate: float = 1.0
    critical_low_burst: float = 1.0
    critical_medium_rate: float = 10.0
    critical_medium_burst: float = 10.0
    critical_high_rate: float = 50.0
    critical_high_burst: float = 50.0
    critical_critical_rate: float = 100.0
    critical_critical_burst: float = 100.0

    # Global normal pool. LOW/MEDIUM only.
    normal_global_rate: float = 400.0
    normal_global_burst: float = 400.0

    # Protected security reserve. HIGH/CRITICAL only.
    security_reserve_rate: float = 100.0
    security_reserve_burst: float = 100.0


@dataclass
class TokenBucket:
    rate: float
    capacity: float
    tokens: float
    updated_at: float

    def refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated_at)
        if elapsed <= 0.0:
            return

        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate,
        )
        self.updated_at = now

    def available(self, now: float, amount: float = 1.0) -> bool:
        self.refill(now)
        return self.tokens >= amount

    def consume(self, now: float, amount: float = 1.0) -> bool:
        if not self.available(now, amount):
            return False

        self.tokens -= amount
        return True

    def retry_after(self, now: float, amount: float = 1.0) -> float:
        self.refill(now)
        if self.tokens >= amount:
            return 0.0
        return max(
            0.0,
            (amount - self.tokens) / max(self.rate, 0.001),
        )


@dataclass(frozen=True)
class AdmissionDecision:
    admitted: bool
    producer: str
    priority: str
    reason: str
    state: str
    retry_after_seconds: float
    producer_tokens: float
    global_tokens: float


class EventRateLimiter:
    """
    CyberDefender Event Rate Limiter v1.2.

    HIGH/CRITICAL security traffic is isolated from the normal
    LOW/MEDIUM global pool.

    Complexity:
        Normal admission: O(1)
        State transition: O(B)
        Statistics: O(P)

    B = active producer/priority buckets.
    P = bounded producer count.
    """

    VERSION = "1.2"

    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"

    _VALID_STATES = {
        NORMAL,
        DEGRADED,
        CRITICAL,
    }

    def __init__(self, policy: RatePolicy | None = None) -> None:
        self.policy = policy or RatePolicy()
        self._lock = threading.RLock()
        self._state = self.NORMAL

        self._buckets: Dict[
            tuple[str, EventPriority],
            TokenBucket,
        ] = {}

        self._known_producers: Dict[str, float] = {}

        now = time.monotonic()

        self._normal_global_bucket = TokenBucket(
            rate=max(0.0, float(self.policy.normal_global_rate)),
            capacity=max(1.0, float(self.policy.normal_global_burst)),
            tokens=max(1.0, float(self.policy.normal_global_burst)),
            updated_at=now,
        )

        self._security_reserve_bucket = TokenBucket(
            rate=max(0.0, float(self.policy.security_reserve_rate)),
            capacity=max(1.0, float(self.policy.security_reserve_burst)),
            tokens=max(1.0, float(self.policy.security_reserve_burst)),
            updated_at=now,
        )

        self._total_requests = 0
        self._total_admitted = 0
        self._total_limited = 0
        self._total_invalid = 0

        self._admitted_by_priority = {
            priority.name: 0 for priority in EventPriority
        }
        self._limited_by_priority = {
            priority.name: 0 for priority in EventPriority
        }

        self._limited_by_producer: Dict[str, int] = {}
        self._last_decision: AdmissionDecision | None = None

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            result = float(value)
            if not math.isfinite(result):
                return default
            return max(0.0, result)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _normalize_producer(producer: Any) -> str:
        if producer is None:
            return "unknown"

        try:
            value = str(producer).strip()
        except Exception:
            return "unknown"

        if not value:
            return "unknown"

        return value[:128]

    @staticmethod
    def _normalize_priority(priority: Any) -> EventPriority:
        if isinstance(priority, EventPriority):
            return priority

        if isinstance(priority, str):
            try:
                return EventPriority[priority.strip().upper()]
            except KeyError:
                return EventPriority.MEDIUM

        try:
            return EventPriority(int(priority))
        except (TypeError, ValueError):
            return EventPriority.MEDIUM

    def _limits_for(
        self,
        priority: EventPriority,
    ) -> tuple[float, float]:
        if self._state == self.NORMAL:
            values = {
                EventPriority.LOW: (
                    self.policy.normal_low_rate,
                    self.policy.normal_low_burst,
                ),
                EventPriority.MEDIUM: (
                    self.policy.normal_medium_rate,
                    self.policy.normal_medium_burst,
                ),
                EventPriority.HIGH: (
                    self.policy.normal_high_rate,
                    self.policy.normal_high_burst,
                ),
                EventPriority.CRITICAL: (
                    self.policy.normal_critical_rate,
                    self.policy.normal_critical_burst,
                ),
            }
        elif self._state == self.DEGRADED:
            values = {
                EventPriority.LOW: (
                    self.policy.degraded_low_rate,
                    self.policy.degraded_low_burst,
                ),
                EventPriority.MEDIUM: (
                    self.policy.degraded_medium_rate,
                    self.policy.degraded_medium_burst,
                ),
                EventPriority.HIGH: (
                    self.policy.degraded_high_rate,
                    self.policy.degraded_high_burst,
                ),
                EventPriority.CRITICAL: (
                    self.policy.degraded_critical_rate,
                    self.policy.degraded_critical_burst,
                ),
            }
        else:
            values = {
                EventPriority.LOW: (
                    self.policy.critical_low_rate,
                    self.policy.critical_low_burst,
                ),
                EventPriority.MEDIUM: (
                    self.policy.critical_medium_rate,
                    self.policy.critical_medium_burst,
                ),
                EventPriority.HIGH: (
                    self.policy.critical_high_rate,
                    self.policy.critical_high_burst,
                ),
                EventPriority.CRITICAL: (
                    self.policy.critical_critical_rate,
                    self.policy.critical_critical_burst,
                ),
            }

        rate, burst = values[priority]
        return (
            self._safe_float(rate),
            max(1.0, self._safe_float(burst)),
        )

    def _ensure_producer_capacity(
        self,
        producer: str,
        now: float,
    ) -> None:
        if producer in self._known_producers:
            self._known_producers[producer] = now
            return

        maximum = max(1, int(self.policy.max_producers))

        if len(self._known_producers) >= maximum:
            oldest = min(
                self._known_producers,
                key=self._known_producers.get,
            )
            self._known_producers.pop(oldest, None)

            stale = [
                key for key in self._buckets
                if key[0] == oldest
            ]
            for key in stale:
                self._buckets.pop(key, None)

        self._known_producers[producer] = now

    def _get_bucket(
        self,
        producer: str,
        priority: EventPriority,
        now: float,
    ) -> TokenBucket:
        key = (producer, priority)
        bucket = self._buckets.get(key)

        if bucket is not None:
            return bucket

        rate, burst = self._limits_for(priority)

        bucket = TokenBucket(
            rate=rate,
            capacity=burst,
            tokens=burst,
            updated_at=now,
        )
        self._buckets[key] = bucket
        return bucket

    @staticmethod
    def _is_security_priority(priority: EventPriority) -> bool:
        return priority in (
            EventPriority.HIGH,
            EventPriority.CRITICAL,
        )

    def _global_bucket_for(
        self,
        priority: EventPriority,
    ) -> TokenBucket:
        if self._is_security_priority(priority):
            return self._security_reserve_bucket
        return self._normal_global_bucket

    def _limited(
        self,
        producer: str,
        priority: EventPriority,
        reason: str,
        state: str,
        retry_after: float,
        producer_tokens: float,
        global_tokens: float,
    ) -> AdmissionDecision:
        self._total_limited += 1

        priority_name = priority.name
        self._limited_by_priority[priority_name] += 1
        self._limited_by_producer[producer] = (
            self._limited_by_producer.get(producer, 0) + 1
        )

        decision = AdmissionDecision(
            admitted=False,
            producer=producer,
            priority=priority_name,
            reason=reason,
            state=state,
            retry_after_seconds=round(max(0.0, retry_after), 4),
            producer_tokens=round(max(0.0, producer_tokens), 4),
            global_tokens=round(max(0.0, global_tokens), 4),
        )

        self._last_decision = decision
        return decision

    def set_state(self, state: str) -> bool:
        """
        Change state and immediately reconfigure active producer buckets.

        Complexity: O(B)
        """
        normalized = str(state).strip().upper()

        if normalized not in self._VALID_STATES:
            return False

        with self._lock:
            if normalized == self._state:
                return True

            now = time.monotonic()
            self._state = normalized

            for (_, priority), bucket in self._buckets.items():
                bucket.refill(now)

                rate, burst = self._limits_for(priority)

                bucket.rate = rate
                bucket.capacity = burst
                bucket.tokens = min(bucket.tokens, bucket.capacity)
                bucket.updated_at = now

        return True

    def get_state(self) -> str:
        with self._lock:
            return self._state

    def admit(
        self,
        producer: Any,
        priority: Any = EventPriority.MEDIUM,
        cost: float = 1.0,
    ) -> AdmissionDecision:
        """
        Admit or rate-limit an event.

        Accounting rule:
            Neither global nor producer tokens are consumed unless
            both admission checks can succeed.

        HIGH/CRITICAL consume only the security reserve.
        LOW/MEDIUM consume only the normal global pool.
        """
        normalized_producer = self._normalize_producer(producer)
        normalized_priority = self._normalize_priority(priority)
        normalized_cost = self._safe_float(cost, 1.0)

        if normalized_cost <= 0.0:
            normalized_cost = 1.0

        with self._lock:
            self._total_requests += 1
            now = time.monotonic()

            self._ensure_producer_capacity(
                normalized_producer,
                now,
            )

            producer_bucket = self._get_bucket(
                normalized_producer,
                normalized_priority,
                now,
            )

            global_bucket = self._global_bucket_for(
                normalized_priority
            )

            # Refill/check first. No tokens are consumed yet.
            producer_ok = producer_bucket.available(
                now,
                normalized_cost,
            )
            global_ok = global_bucket.available(
                now,
                normalized_cost,
            )

            if not producer_ok:
                return self._limited(
                    producer=normalized_producer,
                    priority=normalized_priority,
                    reason="PRODUCER_RATE_LIMIT",
                    state=self._state,
                    retry_after=producer_bucket.retry_after(
                        now,
                        normalized_cost,
                    ),
                    producer_tokens=producer_bucket.tokens,
                    global_tokens=global_bucket.tokens,
                )

            if not global_ok:
                reason = (
                    "SECURITY_RESERVE_EXHAUSTED"
                    if self._is_security_priority(
                        normalized_priority
                    )
                    else "GLOBAL_RATE_LIMIT"
                )

                return self._limited(
                    producer=normalized_producer,
                    priority=normalized_priority,
                    reason=reason,
                    state=self._state,
                    retry_after=global_bucket.retry_after(
                        now,
                        normalized_cost,
                    ),
                    producer_tokens=producer_bucket.tokens,
                    global_tokens=global_bucket.tokens,
                )

            # Both buckets are known to have enough capacity and
            # execution is protected by the lock, so consumption is
            # atomic with respect to other limiter calls.
            producer_bucket.tokens -= normalized_cost
            global_bucket.tokens -= normalized_cost

            self._total_admitted += 1

            priority_name = normalized_priority.name
            self._admitted_by_priority[priority_name] += 1

            decision = AdmissionDecision(
                admitted=True,
                producer=normalized_producer,
                priority=priority_name,
                reason="EVENT_ADMITTED",
                state=self._state,
                retry_after_seconds=0.0,
                producer_tokens=round(
                    producer_bucket.tokens,
                    4,
                ),
                global_tokens=round(
                    global_bucket.tokens,
                    4,
                ),
            )

            self._last_decision = decision
            return decision

    def allow(
        self,
        producer: Any,
        priority: Any = EventPriority.MEDIUM,
    ) -> bool:
        return self.admit(
            producer,
            priority,
        ).admitted

    def allow_critical(self, producer: Any) -> bool:
        return self.allow(
            producer,
            EventPriority.CRITICAL,
        )

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            now = time.monotonic()

            self._normal_global_bucket.refill(now)
            self._security_reserve_bucket.refill(now)

            return {
                "component": "EventRateLimiter",
                "version": self.VERSION,
                "state": self._state,
                "producers": len(self._known_producers),
                "max_producers": max(
                    1,
                    int(self.policy.max_producers),
                ),
                "buckets": len(self._buckets),
                "total_requests": self._total_requests,
                "total_admitted": self._total_admitted,
                "total_limited": self._total_limited,
                "total_invalid": self._total_invalid,
                "admitted_by_priority": dict(
                    self._admitted_by_priority
                ),
                "limited_by_priority": dict(
                    self._limited_by_priority
                ),
                "limited_by_producer": dict(
                    list(
                        self._limited_by_producer.items()
                    )[:64]
                ),
                "normal_global": {
                    "tokens": round(
                        self._normal_global_bucket.tokens,
                        4,
                    ),
                    "capacity": round(
                        self._normal_global_bucket.capacity,
                        4,
                    ),
                    "rate": round(
                        self._normal_global_bucket.rate,
                        4,
                    ),
                },
                "security_reserve": {
                    "tokens": round(
                        self._security_reserve_bucket.tokens,
                        4,
                    ),
                    "capacity": round(
                        self._security_reserve_bucket.capacity,
                        4,
                    ),
                    "rate": round(
                        self._security_reserve_bucket.rate,
                        4,
                    ),
                },
                "last_decision": (
                    None
                    if self._last_decision is None
                    else {
                        "admitted": (
                            self._last_decision.admitted
                        ),
                        "producer": (
                            self._last_decision.producer
                        ),
                        "priority": (
                            self._last_decision.priority
                        ),
                        "reason": (
                            self._last_decision.reason
                        ),
                        "state": (
                            self._last_decision.state
                        ),
                    }
                ),
            }

    def health_check(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "component": "EventRateLimiter",
                "status": "HEALTHY",
                "version": self.VERSION,
                "state": self._state,
                "producer_registry": len(
                    self._known_producers
                ),
                "producer_capacity": max(
                    1,
                    int(self.policy.max_producers),
                ),
                "security_reserve": True,
            }

    def reset_statistics(self) -> None:
        with self._lock:
            self._total_requests = 0
            self._total_admitted = 0
            self._total_limited = 0
            self._total_invalid = 0

            self._admitted_by_priority = {
                priority.name: 0
                for priority in EventPriority
            }

            self._limited_by_priority = {
                priority.name: 0
                for priority in EventPriority
            }

            self._limited_by_producer.clear()
