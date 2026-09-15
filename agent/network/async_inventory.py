from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable


class AsyncPassiveNetworkInventory:
    """Bounded background wrapper for passive network inventory collection.

    Security / reliability contract:
      * one daemon worker only;
      * at most one pending refresh request (coalesced Event semantics);
      * runtime callers never wait for collection completion;
      * collection failure preserves the last good snapshot;
      * deadline expiry is observable but cannot authorize or mutate anything;
      * close() is bounded and never blocks the security runtime indefinitely.
    """

    VERSION = "0.1.4"
    MODE = "PASSIVE_ONLY"
    AUTHORITY = "NONE"

    def __init__(
        self,
        collector: Any,
        *,
        deadline_seconds: float = 5.0,
        close_join_seconds: float = 0.5,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if collector is None or not callable(getattr(collector, "collect", None)):
            raise ValueError("NETWORK_ASYNC_COLLECTOR_REQUIRED")

        self.collector = collector
        self.deadline_seconds = max(0.25, min(float(deadline_seconds), 60.0))
        self.close_join_seconds = max(0.0, min(float(close_join_seconds), 5.0))
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock

        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._closed = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="CyberDefenderPassiveNetworkInventory",
            daemon=True,
        )

        self._latest: dict[str, Any] | None = None
        self._in_flight = False
        self._started_monotonic: float | None = None
        self._started_at: float | None = None
        self._last_completed_at: float | None = None
        self._last_success_at: float | None = None
        self._last_duration_ms: float | None = None
        self._last_error: str | None = None
        self._last_failure_at: float | None = None
        self._last_failure_type: str | None = None
        self._last_failure_reason: str | None = None
        self._last_failure_duration_ms: float | None = None
        self._consecutive_failures = 0
        self.stale_after_seconds = max(30.0, self.deadline_seconds * 12.0)

        self.requests = 0
        self.starts = 0
        self.completed = 0
        self.failures = 0
        self.coalesced = 0
        self.deadline_exceeded_count = 0
        self.close_incomplete = False

        self._thread.start()

    def request_sample(self) -> bool:
        """Request one refresh without waiting for network collection.

        Returns True when this call made a pending request visible to the worker.
        Returns False when a request was already pending and this call was coalesced.
        """
        if self._closed.is_set():
            return False

        with self._lock:
            self.requests += 1
            already_pending = self._wake.is_set()
            if already_pending:
                self.coalesced += 1
            self._wake.set()
            return not already_pending

    def get_latest_snapshot(self) -> dict[str, Any] | None:
        """Return a defensive copy of the latest good bounded snapshot."""
        with self._lock:
            if self._latest is None:
                return None
            snapshot = copy.deepcopy(self._latest)
            snapshot["runtime_integration"] = self._integration_state_locked()
            return snapshot

    def _deadline_exceeded_locked(self) -> bool:
        if not self._in_flight or self._started_monotonic is None:
            return False
        age = self.monotonic_clock() - self._started_monotonic
        return age > self.deadline_seconds

    def _integration_state_locked(self) -> dict[str, Any]:
        deadline_exceeded = self._deadline_exceeded_locked()
        now = self.wall_clock()
        last_success_age = None
        if self._last_success_at is not None:
            last_success_age = max(0.0, now - self._last_success_at)
        stale = (
            self._last_success_at is not None
            and last_success_age is not None
            and last_success_age > self.stale_after_seconds
        )
        return {
            "schema": "cyberdefender.network-inventory-integration.v0.1.4",
            "version": self.VERSION,
            "mode": "ASYNC_BOUNDED",
            "authority": self.AUTHORITY,
            "authoritative": False,
            "worker_alive": self._thread.is_alive(),
            "in_flight": self._in_flight,
            "pending": self._wake.is_set(),
            "deadline_seconds": self.deadline_seconds,
            "deadline_exceeded": deadline_exceeded,
            "requests": self.requests,
            "starts": self.starts,
            "completed": self.completed,
            "failures": self.failures,
            "failures_total": self.failures,
            "consecutive_failures": self._consecutive_failures,
            "coalesced": self.coalesced,
            "deadline_exceeded_count": self.deadline_exceeded_count,
            "last_started_at": self._started_at,
            "last_completed_at": self._last_completed_at,
            "last_success_at": self._last_success_at,
            "last_success_age_seconds": (round(last_success_age, 3) if last_success_age is not None else None),
            "stale_after_seconds": self.stale_after_seconds,
            "stale": bool(stale),
            "last_duration_ms": self._last_duration_ms,
            "last_error": self._last_error,
            "last_failure_at": self._last_failure_at,
            "last_failure_type": self._last_failure_type,
            "last_failure_reason": self._last_failure_reason,
            "last_failure_duration_ms": self._last_failure_duration_ms,
            "close_incomplete": self.close_incomplete,
        }

    def integration_state(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._integration_state_locked())

    def _run(self) -> None:
        while not self._closed.is_set():
            self._wake.wait(0.25)
            if self._closed.is_set():
                break
            if not self._wake.is_set():
                continue

            # Clear the single pending slot before collection. A request that
            # arrives while collection is in-flight can set it again, creating
            # at most one follow-up refresh.
            self._wake.clear()

            with self._lock:
                self._in_flight = True
                self._started_monotonic = self.monotonic_clock()
                self._started_at = self.wall_clock()
                self.starts += 1

            started = self.monotonic_clock()
            error_name: str | None = None
            error_reason: str | None = None
            result: dict[str, Any] | None = None

            try:
                candidate = self.collector.collect()
                if not isinstance(candidate, dict):
                    raise RuntimeError("NETWORK_INVENTORY_INVALID_RESULT")
                result = copy.deepcopy(candidate)
            except Exception as exc:  # failure is isolated from core runtime
                error_name = type(exc).__name__
                error_reason = str(exc).replace("\r", " ").replace("\n", " ").strip()[:256]

            completed_at = self.wall_clock()
            duration_ms = round((self.monotonic_clock() - started) * 1000.0, 2)

            with self._lock:
                if (
                    self._started_monotonic is not None
                    and self.monotonic_clock() - self._started_monotonic > self.deadline_seconds
                ):
                    self.deadline_exceeded_count += 1

                self._in_flight = False
                self._started_monotonic = None
                self._last_completed_at = completed_at
                self._last_duration_ms = duration_ms
                self.completed += 1

                if result is not None:
                    self._latest = result
                    self._last_success_at = completed_at
                    self._last_error = None
                    self._consecutive_failures = 0
                else:
                    self.failures += 1
                    self._consecutive_failures += 1
                    self._last_error = error_name or "NETWORK_ASYNC_UNKNOWN_ERROR"
                    self._last_failure_at = completed_at
                    self._last_failure_type = error_name or "NETWORK_ASYNC_UNKNOWN_ERROR"
                    self._last_failure_reason = error_reason or self._last_failure_type
                    self._last_failure_duration_ms = duration_ms

    def health_check(self) -> dict[str, Any]:
        collector_health: dict[str, Any] = {}
        method = getattr(self.collector, "health_check", None)
        if callable(method):
            try:
                candidate = method()
                if isinstance(candidate, dict):
                    collector_health = copy.deepcopy(candidate)
            except Exception as exc:
                collector_health = {
                    "status": "DEGRADED",
                    "error": type(exc).__name__,
                }

        with self._lock:
            state = self._integration_state_locked()
            deadline_exceeded = bool(state["deadline_exceeded"])
            worker_alive = bool(state["worker_alive"])
            last_error = self._last_error
            stale = bool(state.get("stale", False))
            consecutive_failures = int(state.get("consecutive_failures", 0) or 0)

        if self._closed.is_set():
            status = "STOPPED"
        elif not worker_alive or deadline_exceeded or stale or last_error is not None or consecutive_failures > 0:
            status = "DEGRADED"
        elif int(state.get("completed", 0) or 0) == 0:
            status = "STARTING"
        else:
            status = "HEALTHY"

        return {
            "component": "AsyncPassiveNetworkInventory",
            "version": self.VERSION,
            "status": status,
            "mode": self.MODE,
            "integration_mode": "ASYNC_BOUNDED",
            "authority": self.AUTHORITY,
            "authoritative": False,
            "active_scan_enabled": False,
            "dashboard_direct_os_access": False,
            "packet_injection": False,
            "firewall_mutation": False,
            "hotspot_client_count_authoritative": False,
            "worker": state,
            "collector": collector_health,
        }

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._wake.set()
        self._thread.join(timeout=self.close_join_seconds)
        self.close_incomplete = self._thread.is_alive()
