from __future__ import annotations

from collections import deque
from threading import Condition, Lock
from typing import Any, Optional


class _PriorityBoundedQueue:
    """
    Internal bounded priority queue used by EventBus v2.4.

    Security contract:
    - Total memory is strictly bounded by maxsize.
    - LOW/MEDIUM traffic cannot consume security-reserved capacity.
    - HIGH/CRITICAL traffic may use both general and security capacity.
    - CRITICAL/HIGH receive strict preference while bounded aging prevents LOW/MEDIUM starvation.
    - FIFO ordering is preserved within each priority tier.
    - put/get are non-blocking at the EventBus API boundary.
    """

    _CRITICAL = "CRITICAL"
    _HIGH = "HIGH"
    _MEDIUM = "MEDIUM"
    _LOW = "LOW"

    # Bounded fairness: under sustained CRITICAL/HIGH traffic, an already
    # queued MEDIUM item is serviced within 8 dispatches and LOW within 16.
    # These are service bounds, not admission guarantees. Security-reserved
    # capacity remains unchanged.
    _MEDIUM_MAX_WAIT_DISPATCHES = 8
    _LOW_MAX_WAIT_DISPATCHES = 16

    def __init__(self, maxsize: int, security_reserve: int) -> None:
        if not isinstance(maxsize, int):
            raise TypeError("maxsize integer bo'lishi kerak")
        if maxsize <= 0:
            raise ValueError("maxsize 0 dan katta bo'lishi kerak")
        if not isinstance(security_reserve, int):
            raise TypeError("security_reserve integer bo'lishi kerak")
        if security_reserve < 0 or security_reserve > maxsize:
            raise ValueError(
                "security_reserve 0..maxsize oralig'ida bo'lishi kerak"
            )

        self.maxsize = maxsize
        self.security_reserve = security_reserve
        self.general_capacity = maxsize - security_reserve

        self._queues = {
            self._CRITICAL: deque(),
            self._HIGH: deque(),
            self._MEDIUM: deque(),
            self._LOW: deque(),
        }
        self._size = 0
        self._unfinished_tasks = 0
        self._condition = Condition(Lock())

        self._medium_wait_dispatches = 0
        self._low_wait_dispatches = 0
        self._fairness_promotions = {
            self._MEDIUM: 0,
            self._LOW: 0,
        }

    @staticmethod
    def priority_of(event: Any) -> str:
        """Normalize an event severity into a bounded priority tier."""
        try:
            if isinstance(event, dict):
                raw = event.get("severity", "LOW")
            else:
                raw = getattr(event, "severity", "LOW")

            if not isinstance(raw, str):
                return _PriorityBoundedQueue._LOW

            value = raw.upper().strip()

            if value == _PriorityBoundedQueue._CRITICAL:
                return _PriorityBoundedQueue._CRITICAL
            if value in {_PriorityBoundedQueue._HIGH, "ALERT"}:
                return _PriorityBoundedQueue._HIGH
            if value in {_PriorityBoundedQueue._MEDIUM, "WARNING"}:
                return _PriorityBoundedQueue._MEDIUM
            return _PriorityBoundedQueue._LOW
        except Exception:
            # Unknown/uninspectable events never gain security priority.
            return _PriorityBoundedQueue._LOW

    def _security_size(self) -> int:
        return len(self._queues[self._CRITICAL]) + len(
            self._queues[self._HIGH]
        )

    def _general_size(self) -> int:
        return (
            len(self._queues[self._MEDIUM])
            + len(self._queues[self._LOW])
        )

    def put_nowait(self, event: Any) -> str:
        """
        Admit an event or raise queue.Full-compatible exception.

        Returns the normalized priority on success.
        """
        from queue import Full

        priority = self.priority_of(event)

        with self._condition:
            if self._size >= self.maxsize:
                raise Full

            # LOW/MEDIUM are restricted to general capacity.
            if priority in {self._LOW, self._MEDIUM}:
                if self._general_size() >= self.general_capacity:
                    raise Full

            # HIGH/CRITICAL may consume general free capacity first and
            # security reserve when general capacity is unavailable.
            self._queues[priority].append(event)
            self._size += 1
            self._unfinished_tasks += 1
            self._condition.notify()
            return priority

    def _select_priority_locked(self) -> str | None:
        """Choose one priority while preserving bounded starvation freedom."""
        medium_ready = bool(self._queues[self._MEDIUM])
        low_ready = bool(self._queues[self._LOW])

        if (
            medium_ready
            and self._medium_wait_dispatches >= self._MEDIUM_MAX_WAIT_DISPATCHES
        ):
            self._fairness_promotions[self._MEDIUM] += 1
            return self._MEDIUM

        if (
            low_ready
            and self._low_wait_dispatches >= self._LOW_MAX_WAIT_DISPATCHES
        ):
            self._fairness_promotions[self._LOW] += 1
            return self._LOW

        for priority in (
            self._CRITICAL,
            self._HIGH,
            self._MEDIUM,
            self._LOW,
        ):
            if self._queues[priority]:
                return priority

        return None

    def _record_dispatch_locked(self, priority: str) -> None:
        if self._queues[self._MEDIUM]:
            if priority == self._MEDIUM:
                self._medium_wait_dispatches = 0
            else:
                self._medium_wait_dispatches += 1
        else:
            self._medium_wait_dispatches = 0

        if self._queues[self._LOW]:
            if priority == self._LOW:
                self._low_wait_dispatches = 0
            else:
                self._low_wait_dispatches += 1
        else:
            self._low_wait_dispatches = 0

    def get(self, timeout: Optional[float] = None) -> Any:
        from queue import Empty
        import time

        with self._condition:
            if self._size == 0:
                if timeout == 0:
                    raise Empty

                if timeout is None:
                    while self._size == 0:
                        self._condition.wait()
                else:
                    if timeout < 0:
                        raise ValueError("timeout manfiy bo'lishi mumkin emas")
                    deadline = time.monotonic() + timeout
                    while self._size == 0:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise Empty
                        self._condition.wait(remaining)

            priority = self._select_priority_locked()
            if priority is not None:
                queue = self._queues[priority]
                event = queue.popleft()
                self._size -= 1
                self._record_dispatch_locked(priority)
                return event

            # Defensive invariant failure: size said non-zero but no queue
            # contained an event. Treat as empty rather than corrupting state.
            raise Empty

    def get_nowait(self) -> Any:
        return self.get(timeout=0)

    def task_done(self) -> None:
        with self._condition:
            if self._unfinished_tasks <= 0:
                raise ValueError("task_done() called too many times")
            self._unfinished_tasks -= 1
            if self._unfinished_tasks == 0:
                self._condition.notify_all()

    def join(self) -> None:
        with self._condition:
            while self._unfinished_tasks:
                self._condition.wait()

    def qsize(self) -> int:
        with self._condition:
            return self._size

    def empty(self) -> bool:
        with self._condition:
            return self._size == 0

    def full(self) -> bool:
        with self._condition:
            return self._size >= self.maxsize

    def clear_nowait(self) -> int:
        """Clear queued items and balance their unfinished-task count."""
        with self._condition:
            cleared = self._size
            for queue in self._queues.values():
                queue.clear()
            self._size = 0
            self._unfinished_tasks = 0
            self._medium_wait_dispatches = 0
            self._low_wait_dispatches = 0
            self._condition.notify_all()
            return cleared

    def stats(self) -> dict[str, int]:
        with self._condition:
            critical = len(self._queues[self._CRITICAL])
            high = len(self._queues[self._HIGH])
            medium = len(self._queues[self._MEDIUM])
            low = len(self._queues[self._LOW])
            return {
                "queue_size": self._size,
                "queue_capacity": self.maxsize,
                "queue_full": self._size >= self.maxsize,
                "security_reserve": self.security_reserve,
                "general_capacity": self.general_capacity,
                "security_size": critical + high,
                "general_size": medium + low,
                "critical_size": critical,
                "high_size": high,
                "medium_size": medium,
                "low_size": low,
                "unfinished_tasks": self._unfinished_tasks,
                "medium_wait_dispatches": self._medium_wait_dispatches,
                "low_wait_dispatches": self._low_wait_dispatches,
                "medium_max_wait_dispatches": self._MEDIUM_MAX_WAIT_DISPATCHES,
                "low_max_wait_dispatches": self._LOW_MAX_WAIT_DISPATCHES,
                "fairness_promotions": dict(self._fairness_promotions),
            }


class EventBus:
    """
    CyberDefender Internal Event Bus v2.4

    Priority-aware bounded admission with security-reserved capacity.

    v2.4 fairness + lifecycle hardening:
    - shutdown state transition and queue admission share a lifecycle lock
    - once request_shutdown() returns, no later publish() can admit an event
    - an already-in-flight publish may complete before shutdown returns
    - queue admission remains O(1) and bounded

    Security / reliability principles:
    - publish() faqat queue'ga event qabul qiladi
    - subscriber callback publish() ichida chaqirilmaydi
    - queue total memory strictly bounded
    - LOW/MEDIUM security reserve'ni iste'mol qila olmaydi
    - HIGH/CRITICAL lower-priority saturation sharoitida protected
    - CRITICAL/HIGH priority-aware dispatch qilinadi
    - same-priority eventlar FIFO tartibida qoladi
    - bounded aging LOW/MEDIUM starvation'ni oldini oladi
    - subscriber xatosi EventBus'ni yiqitmaydi
    - invalid input agentni yiqitmaydi
    - counters thread-safe
    - health_check() mavjud
    - shutdown holatida yangi event qabul qilinmaydi
    - mavjud queue eventlari shutdown'da o'chirilmaydi
    """

    VERSION = "2.4"

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    SHUTDOWN = "SHUTDOWN"

    DEFAULT_SECURITY_RESERVE_RATIO = 0.20

    def __init__(
        self,
        max_size: int = 1000,
        security_reserve: Optional[int] = None,
    ):
        if not isinstance(max_size, int):
            raise TypeError("max_size integer bo'lishi kerak")
        if max_size <= 0:
            raise ValueError("max_size 0 dan katta bo'lishi kerak")

        if security_reserve is None:
            security_reserve = max(1, int(max_size * self.DEFAULT_SECURITY_RESERVE_RATIO))
            security_reserve = min(security_reserve, max_size)

        if not isinstance(security_reserve, int):
            raise TypeError("security_reserve integer bo'lishi kerak")
        if security_reserve < 0 or security_reserve > max_size:
            raise ValueError(
                "security_reserve 0..max_size oralig'ida bo'lishi kerak"
            )

        self._queue = _PriorityBoundedQueue(
            maxsize=max_size,
            security_reserve=security_reserve,
        )

        self._subscribers: list = []
        self._lock = Lock()

        # Lifecycle admission lock. This lock makes the shutdown transition
        # atomic with respect to queue admission without holding the general
        # metrics/subscriber lock during queue operations.
        self._lifecycle_lock = Lock()

        # Counters
        self._published_count = 0
        self._dispatched_count = 0
        self._dropped_count = 0
        self._failed_dispatch_count = 0
        self._invalid_publish_count = 0
        self._publish_exception_count = 0
        self._dispatch_exception_count = 0
        self._empty_dispatch_count = 0
        self._task_done_errors = 0
        self._clear_count = 0

        # v2.2 admission telemetry
        self._low_medium_capacity_reject_count = 0
        self._security_capacity_reject_count = 0
        self._priority_admission_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        # Health
        self._health_checks = 0
        self._health_failures = 0
        self._last_error: Optional[str] = None
        self._last_error_component: Optional[str] = None

        # Lifecycle
        self._shutdown_requested = False

    def _record_error(self, component: str, exc: BaseException) -> None:
        with self._lock:
            self._last_error = f"{type(exc).__name__}: {exc}"
            self._last_error_component = component

    def publish(self, event: Any) -> bool:
        # Lifecycle invariant: the shutdown check and queue admission MUST be
        # serialized. Otherwise a publisher can observe shutdown=False, yield,
        # request_shutdown() can return, and the publisher can admit afterwards.
        # The lifecycle lock closes that race window.
        with self._lifecycle_lock:
            with self._lock:
                if self._shutdown_requested:
                    self._dropped_count += 1
                    return False

            if event is None:
                with self._lock:
                    self._dropped_count += 1
                    self._invalid_publish_count += 1
                return False

            priority = self._queue.priority_of(event)

            try:
                self._queue.put_nowait(event)
            except Exception as exc:
                from queue import Full

                with self._lock:
                    self._dropped_count += 1
                    if isinstance(exc, Full):
                        if priority in {"LOW", "MEDIUM"}:
                            self._low_medium_capacity_reject_count += 1
                        else:
                            self._security_capacity_reject_count += 1
                    else:
                        self._publish_exception_count += 1
                    self._last_error = f"{type(exc).__name__}: {exc}"
                    self._last_error_component = "EventBus.publish"
                return False

            with self._lock:
                self._published_count += 1
                self._priority_admission_count[priority] += 1
            return True

    def dispatch_once(self, timeout: Optional[float] = 0) -> bool:
        if timeout is not None:
            if not isinstance(timeout, (int, float)):
                with self._lock:
                    self._dispatch_exception_count += 1
                return False
            if timeout < 0:
                with self._lock:
                    self._dispatch_exception_count += 1
                return False

        try:
            event = self._queue.get(timeout=timeout)
        except Exception as exc:
            from queue import Empty

            if isinstance(exc, Empty):
                with self._lock:
                    self._empty_dispatch_count += 1
                return False

            with self._lock:
                self._dispatch_exception_count += 1
            self._record_error("EventBus.dispatch_once.get", exc)
            return False

        try:
            self._dispatch_event(event)
        except Exception as exc:
            with self._lock:
                self._dispatch_exception_count += 1
            self._record_error("EventBus.dispatch_once.dispatch", exc)
        finally:
            try:
                self._queue.task_done()
            except ValueError as exc:
                with self._lock:
                    self._task_done_errors += 1
                self._record_error("EventBus.dispatch_once.task_done", exc)

        return True

    def dispatch_all(self, max_events: Optional[int] = None) -> int:
        if max_events is not None:
            if not isinstance(max_events, int):
                raise TypeError("max_events integer bo'lishi kerak")
            if max_events < 0:
                raise ValueError("max_events manfiy bo'lishi mumkin emas")

        dispatched = 0
        while True:
            if max_events is not None and dispatched >= max_events:
                break
            if not self.dispatch_once():
                break
            dispatched += 1
        return dispatched

    def _dispatch_event(self, event: Any) -> None:
        with self._lock:
            subscribers = list(self._subscribers)

        for callback in subscribers:
            try:
                callback(event)
            except Exception as exc:
                with self._lock:
                    self._failed_dispatch_count += 1
                self._record_error("EventBus.subscriber", exc)
                continue

        with self._lock:
            self._dispatched_count += 1

    def get(self, timeout: Optional[float] = None) -> Any:
        try:
            return self._queue.get(timeout=timeout)
        except Exception as exc:
            from queue import Empty

            if isinstance(exc, Empty):
                with self._lock:
                    self._empty_dispatch_count += 1
                return None

            with self._lock:
                self._dispatch_exception_count += 1
            self._record_error("EventBus.get", exc)
            return None

    def task_done(self) -> None:
        try:
            self._queue.task_done()
        except ValueError as exc:
            with self._lock:
                self._task_done_errors += 1
            self._record_error("EventBus.task_done", exc)

    def subscribe(self, callback) -> None:
        if not callable(callback):
            raise TypeError("Subscriber callable bo'lishi kerak")
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback) -> None:
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def size(self) -> int:
        return self._queue.qsize()

    def is_empty(self) -> bool:
        return self._queue.empty()

    def is_full(self) -> bool:
        return self._queue.full()

    def join(self) -> None:
        try:
            self._queue.join()
        except Exception as exc:
            self._record_error("EventBus.join", exc)

    def request_shutdown(self) -> None:
        # Serialize shutdown transition with publish admission. If a publish
        # is already inside its admission critical section, shutdown waits for
        # that admission to finish; after this method returns, no new publish
        # can pass the lifecycle gate.
        with self._lifecycle_lock:
            with self._lock:
                self._shutdown_requested = True

    def is_shutdown_requested(self) -> bool:
        with self._lock:
            return self._shutdown_requested

    def health_check(self) -> dict:
        try:
            with self._lock:
                self._health_checks += 1
                published = self._published_count
                dispatched = self._dispatched_count
                dropped = self._dropped_count
                failed_dispatch = self._failed_dispatch_count
                invalid_publish = self._invalid_publish_count
                publish_exceptions = self._publish_exception_count
                dispatch_exceptions = self._dispatch_exception_count
                task_done_errors = self._task_done_errors
                subscriber_count = len(self._subscribers)
                shutdown_requested = self._shutdown_requested
                last_error = self._last_error
                last_error_component = self._last_error_component
                health_checks = self._health_checks
                health_failures = self._health_failures

            queue_stats = self._queue.stats()
            queue_full = queue_stats["queue_full"]

            if shutdown_requested:
                status = self.SHUTDOWN
            elif (
                queue_full
                or dropped > 0
                or failed_dispatch > 0
                or publish_exceptions > 0
                or dispatch_exceptions > 0
                or task_done_errors > 0
            ):
                status = self.DEGRADED
            else:
                status = self.HEALTHY

            if status != self.HEALTHY:
                with self._lock:
                    self._health_failures += 1
                    health_failures = self._health_failures

            return {
                "component": "EventBus",
                "status": status,
                "version": self.VERSION,
                **queue_stats,
                "published": published,
                "dispatched": dispatched,
                "dropped": dropped,
                "failed_dispatch": failed_dispatch,
                "invalid_publish": invalid_publish,
                "publish_exceptions": publish_exceptions,
                "dispatch_exceptions": dispatch_exceptions,
                "task_done_errors": task_done_errors,
                "subscriber_count": subscriber_count,
                "shutdown_requested": shutdown_requested,
                "health_checks": health_checks,
                "health_failures": health_failures,
                "last_error": last_error,
                "last_error_component": last_error_component,
                "low_medium_capacity_rejects": self._low_medium_capacity_reject_count,
                "security_capacity_rejects": self._security_capacity_reject_count,
                "priority_admissions": dict(self._priority_admission_count),
                "critical_security_preservation": True,
            }
        except Exception as exc:
            try:
                with self._lock:
                    self._health_failures += 1
                    self._last_error = f"{type(exc).__name__}: {exc}"
                    self._last_error_component = "EventBus.health_check"
            except Exception:
                pass

            return {
                "component": "EventBus",
                "status": self.FAILED,
                "version": self.VERSION,
                "error": "HEALTH_CHECK_EXCEPTION",
                "error_type": type(exc).__name__,
            }

    def get_stats(self) -> dict:
        with self._lock:
            subscriber_count = len(self._subscribers)
            stats = {
                "bus": "EventBus",
                "version": self.VERSION,
                "published": self._published_count,
                "dispatched": self._dispatched_count,
                "dropped": self._dropped_count,
                "failed_dispatch": self._failed_dispatch_count,
                "subscriber_count": subscriber_count,
                "invalid_publish": self._invalid_publish_count,
                "publish_exceptions": self._publish_exception_count,
                "dispatch_exceptions": self._dispatch_exception_count,
                "empty_dispatch": self._empty_dispatch_count,
                "task_done_errors": self._task_done_errors,
                "clear_count": self._clear_count,
                "health_checks": self._health_checks,
                "health_failures": self._health_failures,
                "shutdown_requested": self._shutdown_requested,
                "last_error": self._last_error,
                "last_error_component": self._last_error_component,
                "low_medium_capacity_rejects": self._low_medium_capacity_reject_count,
                "security_capacity_rejects": self._security_capacity_reject_count,
                "priority_admissions": dict(self._priority_admission_count),
                "critical_security_preservation": True,
            }

        stats.update(self._queue.stats())
        return stats

    def clear(self) -> None:
        try:
            cleared = self._queue.clear_nowait()
            if cleared > 0:
                with self._lock:
                    self._clear_count += 1
        except Exception as exc:
            self._record_error("EventBus.clear", exc)
