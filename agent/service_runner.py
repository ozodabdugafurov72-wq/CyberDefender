from __future__ import annotations

import threading
import time
from typing import Callable, Any


class ServiceRunner:
    """Platform-neutral lifecycle wrapper used by the Windows Service host."""
    VERSION = "1.1"
    RUNTIME_FRESHNESS_SECONDS = 60.0

    def __init__(self, runtime_factory: Callable[[], Any], *, interval_seconds: float = 5.0,
                 telemetry_client: Any | None = None, lifecycle: Any | None = None,
                 stop_event: threading.Event | None = None,
                 primary_reachability_tracker: Any | None = None):
        self.runtime_factory = runtime_factory
        self.interval_seconds = max(0.1, float(interval_seconds))
        self.telemetry_client = telemetry_client
        self.stop_event = stop_event if stop_event is not None else threading.Event()
        self.lifecycle = lifecycle
        self.cleanup_verified = False
        self.exit_reason = "NOT_STARTED"
        self.exit_detail: str | None = None
        self.runtime = None
        self.cycles = 0
        self.failures = 0
        self.last_error: str | None = None
        self.telemetry_failures = 0
        self.last_telemetry_error: str | None = None
        self._telemetry_lock = threading.Lock()
        self._cycle_lock = threading.Lock()
        self._cycle_in_progress = False
        self._cycle_started_monotonic: float | None = None
        self._last_cycle_completed_monotonic: float | None = None
        self._cycle_error = False
        self._heartbeat_watchdog: threading.Thread | None = None

        # ACP primary reachability observer.
        # Evidence only; cannot affect authorization or local protection.
        self.primary_reachability_tracker = (
            primary_reachability_tracker
        )

    def _record_primary_reachability(
        self,
        reachable: bool | None,
        *,
        source: str,
    ) -> None:
        tracker = self.primary_reachability_tracker

        if tracker is None:
            return

        record = getattr(
            tracker,
            "record",
            None,
        )

        if not callable(record):
            return

        try:
            record(
                reachable,
                source=source,
            )
        except Exception:
            # Observability must never stop the protection loop.
            pass

    def stop(self) -> None:
        self.exit_reason = "SERVICE_STOP_EVENT_SET"
        self.stop_event.set()

    def _emit_heartbeat(self, runtime: Any, client: Any) -> None:
        """Send one bounded, non-authoritative heartbeat sample."""
        heartbeat_attempted = False
        try:
            if hasattr(runtime, "health_snapshot"):
                health = runtime.health_snapshot()
            elif hasattr(runtime, "health_check"):
                health = runtime.health_check()
            else:
                health = {}
            if not isinstance(health, dict):
                health = {}
            resource = health.get("resource_guard", {})
            if not isinstance(resource, dict):
                resource = {}
            runtime_health = health.get("runtime", {})
            if not isinstance(runtime_health, dict):
                runtime_health = {}

            with self._cycle_lock:
                cycle_in_progress = self._cycle_in_progress
                cycle_started = self._cycle_started_monotonic
                cycle_error = self._cycle_error
                completed = self._last_cycle_completed_monotonic
            now = time.monotonic()
            cycle_age = (
                max(0.0, now - cycle_started)
                if cycle_in_progress and cycle_started is not None
                else 0.0
            )
            stale = (
                cycle_in_progress
                and cycle_age >= self.RUNTIME_FRESHNESS_SECONDS
            ) or (
                completed is None
                and cycle_in_progress
                and cycle_age >= self.RUNTIME_FRESHNESS_SECONDS
            )
            health_state = str(runtime_health.get("status", "UNKNOWN"))
            last_error = (
                "RUNTIME_CYCLE_STALE"
                if stale
                else ("SERVICE_RUNTIME_ERROR" if cycle_error else None)
            )
            if stale:
                health_state = "DEGRADED"

            heartbeat_attempted = True
            with self._telemetry_lock:
                accepted = client.heartbeat(
                    runtime_version=str(getattr(runtime, "VERSION", "")),
                    health_state=health_state,
                    service_state="RUNNING",
                    resource_state=str(resource.get("state", "")),
                    last_error=last_error,
                )
            if accepted is True:
                self.last_telemetry_error = None
                self._record_primary_reachability(True, source="heartbeat")
            elif accepted is False:
                self._record_primary_reachability(False, source="heartbeat")
                raise RuntimeError("fleet heartbeat rejected")
            else:
                self._record_primary_reachability(None, source="heartbeat")
        except Exception as exc:
            self.telemetry_failures += 1
            self.last_telemetry_error = f"heartbeat:{type(exc).__name__}"
            if heartbeat_attempted:
                self._record_primary_reachability(False, source="heartbeat")

    def _heartbeat_watchdog_loop(self, runtime: Any, client: Any) -> None:
        """Keep fleet liveness independent from a slow managed cycle."""
        while not self.stop_event.wait(self.interval_seconds):
            with self._cycle_lock:
                in_progress = self._cycle_in_progress
            if in_progress:
                self._emit_heartbeat(runtime, client)

    def run(self, *, max_cycles: int | None = None) -> None:
        runtime = None
        self.exit_reason = "RUNNING"
        self.exit_detail = None
        try:
            if self.stop_event.is_set():
                self.exit_reason = "STOP_REQUESTED"
                self.cleanup_verified = True
                return
            runtime = self.runtime_factory()
            self.runtime = runtime
            if hasattr(runtime, "begin_managed_loop"):
                runtime.begin_managed_loop()
            elif hasattr(runtime, "running"):
                runtime.running = True
                if hasattr(runtime, "shutdown_requested"):
                    runtime.shutdown_requested = False

            client = self.telemetry_client
            if client is not None:
                try:
                    accepted = client.register(
                        runtime_version=str(getattr(runtime, "VERSION", "")),
                        service_state="RUNNING",
                    )
                    if accepted is True:
                        self._record_primary_reachability(
                            True,
                            source="register",
                        )

                    elif accepted is False:
                        self._record_primary_reachability(
                            False,
                            source="register",
                        )

                        raise RuntimeError(
                            "fleet registration rejected"
                        )

                    else:
                        self._record_primary_reachability(
                            None,
                            source="register",
                        )

                except Exception as exc:
                    self.telemetry_failures += 1
                    self.last_telemetry_error = f"register:{type(exc).__name__}"

                    self._record_primary_reachability(
                        False,
                        source="register",
                    )

            if client is not None:
                self._heartbeat_watchdog = threading.Thread(
                    target=self._heartbeat_watchdog_loop,
                    args=(runtime, client),
                    name="CyberDefender-FleetHeartbeatWatchdog",
                    daemon=True,
                )
                self._heartbeat_watchdog.start()

            while not self.stop_event.is_set():
                with self._cycle_lock:
                    self._cycle_in_progress = True
                    self._cycle_started_monotonic = time.monotonic()
                    self._cycle_error = False
                try:
                    runtime.run_cycle()
                    self.cycles += 1
                except Exception as exc:
                    self.failures += 1
                    with self._cycle_lock:
                        self._cycle_error = True
                    self.last_error = type(exc).__name__
                    try:
                        runtime.safety.enter_safe_mode(
                            "SERVICE_CYCLE_FAILURE"
                        )
                    except Exception:
                        pass
                finally:
                    with self._cycle_lock:
                        self._cycle_in_progress = False
                        self._last_cycle_completed_monotonic = time.monotonic()

                if self.lifecycle is not None:
                    try:
                        health = runtime.health_snapshot()
                        healthy = health.get("runtime", {}).get("status") == "HEALTHY"
                        self.lifecycle.progress(healthy=healthy)
                    except Exception:
                        # A store/observer failure cannot grant authority or
                        # kill a still functioning Python protection loop.
                        pass

                if client is not None:
                    self._emit_heartbeat(runtime, client)

                if max_cycles is not None and self.cycles >= max_cycles:
                    self.exit_reason = "TEST_CYCLE_LIMIT"
                    break
                self.stop_event.wait(self.interval_seconds)
            if self.exit_reason == "RUNNING":
                self.exit_reason = (
                    "SERVICE_STOP_EVENT_SET"
                    if self.stop_event.is_set()
                    else "RUNTIME_RETURNED"
                )
        except BaseException as exc:
            self.exit_reason = "UNHANDLED_EXCEPTION"
            self.exit_detail = type(exc).__name__
            raise
        finally:
            if self._heartbeat_watchdog is not None:
                self._heartbeat_watchdog.join(timeout=max(1.0, self.interval_seconds * 2.0))
            if runtime is None:
                self.cleanup_verified = True
            if runtime is not None:
                try:
                    runtime.stop("Windows service stop")
                except Exception:
                    pass
                try:
                    runtime.close()
                    self.cleanup_verified = getattr(runtime, "child_cleanup_verified", True)
                except Exception:
                    self.cleanup_verified = False
                if self.cleanup_verified:
                    self.runtime = None
