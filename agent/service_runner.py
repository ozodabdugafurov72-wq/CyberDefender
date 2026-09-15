from __future__ import annotations

import threading
from typing import Callable, Any


class ServiceRunner:
    """Platform-neutral lifecycle wrapper used by the Windows Service host."""
    VERSION = "1.1"

    def __init__(self, runtime_factory: Callable[[], Any], *, interval_seconds: float = 5.0,
                 telemetry_client: Any | None = None, lifecycle: Any | None = None,
                 stop_event: threading.Event | None = None):
        self.runtime_factory = runtime_factory
        self.interval_seconds = max(0.1, float(interval_seconds))
        self.telemetry_client = telemetry_client
        self.stop_event = stop_event if stop_event is not None else threading.Event()
        self.lifecycle = lifecycle
        self.cleanup_verified = False
        self.runtime = None
        self.cycles = 0
        self.failures = 0
        self.last_error: str | None = None
        self.telemetry_failures = 0
        self.last_telemetry_error: str | None = None

    def stop(self) -> None:
        self.stop_event.set()

    def run(self, *, max_cycles: int | None = None) -> None:
        runtime = None
        try:
            if self.stop_event.is_set():
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
                    if accepted is False:
                        raise RuntimeError("fleet registration rejected")
                except Exception as exc:
                    self.telemetry_failures += 1
                    self.last_telemetry_error = f"register:{type(exc).__name__}"

            while not self.stop_event.is_set():
                try:
                    runtime.run_cycle()
                    self.cycles += 1
                except Exception as exc:
                    self.failures += 1
                    self.last_error = type(exc).__name__
                    try:
                        runtime.safety.enter_safe_mode(
                            "SERVICE_CYCLE_FAILURE"
                        )
                    except Exception:
                        pass

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
                        accepted = client.heartbeat(
                            runtime_version=str(getattr(runtime, "VERSION", "")),
                            health_state=str(runtime_health.get("status", "UNKNOWN")),
                            service_state="RUNNING",
                            resource_state=str(resource.get("state", "")),
                            last_error="SERVICE_RUNTIME_ERROR" if getattr(runtime, "last_error", None) else None,
                        )
                        if accepted is False:
                            raise RuntimeError("fleet heartbeat rejected")
                    except Exception as exc:
                        self.telemetry_failures += 1
                        self.last_telemetry_error = f"heartbeat:{type(exc).__name__}"

                if max_cycles is not None and self.cycles >= max_cycles:
                    break
                self.stop_event.wait(self.interval_seconds)
        finally:
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
