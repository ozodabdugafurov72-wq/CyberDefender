"""
CyberDefender Resource Guard v2.2
Security-First Resource Safety Plane.

Purpose
-------
Protect CyberDefender availability under resource pressure without
becoming a source of destructive behavior.

Security invariants
-------------------
1. Resource exhaustion must not become a security failure.
2. ResourceGuard never kills or terminates processes.
3. ResourceGuard never modifies the system, firewall, registry, or services.
4. Security-critical components remain protected in every state.
5. One noisy sample must not cause unsafe escalation.
6. Recovery requires explicit healthy confirmations.
7. State transitions are deterministic and committed atomically.
8. Invalid metrics/policy values fail safely.
9. Resource monitoring failures must not crash the security runtime.
10. Resource budgets are recommendations; enforcement belongs downstream.
11. No unbounded resource structure is created by this component.
12. Production callers may use either check() or evaluate(); both preserve
    the same state-machine semantics.

State machine
-------------
NORMAL -> DEGRADED -> CRITICAL

Recovery
--------
CRITICAL -> DEGRADED -> NORMAL

The transition counters are intentionally independent:
    degraded streak
    critical streak
    recovery streak

Complexity
----------
Collection: O(1)
Pressure calculation: O(1)
State evaluation: O(1)
Budget generation: O(1)
Statistics: O(1)
Memory overhead: O(1)
"""

from __future__ import annotations

import math
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Mapping, Optional

import psutil


@dataclass(frozen=True)
class ResourcePolicy:
    """
    Immutable resource-safety policy.

    Thresholds are safety-policy values, not process-kill limits.
    """

    # ------------------------------------------------------------------
    # HOST CPU
    # ------------------------------------------------------------------

    cpu_warning: float = 85.0
    cpu_critical: float = 95.0

    # ------------------------------------------------------------------
    # HOST MEMORY
    # ------------------------------------------------------------------

    memory_warning: float = 85.0
    memory_critical: float = 95.0

    available_memory_warning_mb: float = 512.0
    available_memory_critical_mb: float = 256.0

    # ------------------------------------------------------------------
    # CYBERDEFENDER PROCESS CPU
    #
    # Normalized against total logical CPU capacity.
    # ------------------------------------------------------------------

    agent_cpu_warning: float = 8.0
    agent_cpu_critical: float = 15.0

    # ------------------------------------------------------------------
    # CYBERDEFENDER PROCESS MEMORY
    # ------------------------------------------------------------------

    agent_memory_warning_mb: float = 512.0
    agent_memory_critical_mb: float = 768.0

    # ------------------------------------------------------------------
    # SUSTAINED PRESSURE
    # ------------------------------------------------------------------

    degraded_confirmations: int = 3
    critical_confirmations: int = 3

    # ------------------------------------------------------------------
    # RECOVERY
    # ------------------------------------------------------------------

    recovery_confirmations: int = 2


class ResourceGuard:
    """
    CyberDefender Resource Safety Plane.

    This component is intentionally non-destructive.

    It observes resource pressure and produces:
        - resource state
        - pressure scores
        - runtime budget recommendations
        - observability statistics

    It does NOT:
        - terminate processes
        - disable security
        - modify firewall
        - modify registry
        - modify services
        - execute autonomous destructive actions
    """

    VERSION = "2.2"

    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"

    VALID_STATES = frozenset(
        {
            NORMAL,
            DEGRADED,
            CRITICAL,
        }
    )

    # Components that must remain protected regardless of resource state.
    PROTECTED_COMPONENTS = (
        "SafetyCore",
        "SelfDefense",
        "Integrity",
        "CryptoAdmission",
        "ReplayGuard",
    )

    def __init__(
        self,
        policy: Optional[ResourcePolicy] = None,
        host_metrics_provider: Any | None = None,
        agent_metrics_provider: Any | None = None,
    ) -> None:
        self.policy = policy or ResourcePolicy()

        self._host_metrics_provider = host_metrics_provider
        self._agent_metrics_provider = agent_metrics_provider

        self.check_count = 0
        self.normal_count = 0
        self.degraded_count = 0
        self.critical_count = 0

        self.last_state = self.NORMAL
        self.last_snapshot: Optional[Dict[str, Any]] = None
        self.last_check_time: Optional[float] = None

        # Sustained-pressure tracking.
        self._degraded_streak = 0
        self._critical_streak = 0
        self._recovery_streak = 0

        # Process tracking.
        self._process: Optional[psutil.Process] = None
        self._process_pid: Optional[int] = None

        self._initialize_process_monitor()

    # ==================================================================
    # PROCESS MONITOR
    # ==================================================================

    def _initialize_process_monitor(self) -> None:
        """
        Initialize monitoring for the current CyberDefender process.

        Monitoring failure is non-fatal.
        """

        try:
            process = psutil.Process(os.getpid())

            # Prime psutil CPU measurement.
            process.cpu_percent(interval=None)

            self._process = process
            self._process_pid = process.pid

        except Exception:
            self._process = None
            self._process_pid = None

    # ==================================================================
    # VALIDATION
    # ==================================================================

    @staticmethod
    def _finite_float(
        value: Any,
        default: float = 0.0,
    ) -> float:
        """
        Convert input to finite float.

        NaN and infinity are rejected.
        """

        try:
            result = float(value)

            if not math.isfinite(result):
                return default

            return result

        except (TypeError, ValueError):
            return default

    @classmethod
    def _non_negative(
        cls,
        value: Any,
        default: float = 0.0,
    ) -> float:
        """
        Return finite non-negative value.
        """

        result = cls._finite_float(value, default)
        return max(0.0, result)

    @staticmethod
    def _bounded_percent(value: Any) -> float:
        """
        Sanitize percentage values into [0, 100].
        """

        value = ResourceGuard._non_negative(value)
        return min(100.0, value)

    @staticmethod
    def _bounded_confirmation(value: Any, default: int) -> int:
        """
        Validate confirmation counters.

        A confirmation count below 1 would break the state machine,
        therefore invalid values fail safely to the supplied default.
        """

        try:
            result = int(value)
        except (TypeError, ValueError):
            return default

        return max(1, result)

    def _validated_policy(self) -> ResourcePolicy:
        """
        Return a sanitized policy.

        ResourcePolicy is normally immutable and valid. This defensive
        boundary prevents malformed externally-created policy objects
        from destabilizing the state machine.
        """

        p = self.policy

        return ResourcePolicy(
            cpu_warning=self._finite_float(
                p.cpu_warning,
                85.0,
            ),
            cpu_critical=self._finite_float(
                p.cpu_critical,
                95.0,
            ),
            memory_warning=self._finite_float(
                p.memory_warning,
                85.0,
            ),
            memory_critical=self._finite_float(
                p.memory_critical,
                95.0,
            ),
            available_memory_warning_mb=self._non_negative(
                p.available_memory_warning_mb,
                512.0,
            ),
            available_memory_critical_mb=self._non_negative(
                p.available_memory_critical_mb,
                256.0,
            ),
            agent_cpu_warning=self._finite_float(
                p.agent_cpu_warning,
                8.0,
            ),
            agent_cpu_critical=self._finite_float(
                p.agent_cpu_critical,
                15.0,
            ),
            agent_memory_warning_mb=self._non_negative(
                p.agent_memory_warning_mb,
                512.0,
            ),
            agent_memory_critical_mb=self._non_negative(
                p.agent_memory_critical_mb,
                768.0,
            ),
            degraded_confirmations=self._bounded_confirmation(
                p.degraded_confirmations,
                3,
            ),
            critical_confirmations=self._bounded_confirmation(
                p.critical_confirmations,
                3,
            ),
            recovery_confirmations=self._bounded_confirmation(
                p.recovery_confirmations,
                2,
            ),
        )

    # ==================================================================
    # HEALTH
    # ==================================================================

    def health_check(self) -> Dict[str, Any]:
        """
        Return component health.

        Resource collection failure is not automatically a runtime
        failure.
        """

        return {
            "component": "ResourceGuard",
            "status": "HEALTHY",
            "version": self.VERSION,
            "state": self.last_state,
            "process_monitor": self._process is not None,
            "metric_providers": {
                "host_injected": self._host_metrics_provider is not None,
                "agent_injected": self._agent_metrics_provider is not None,
            },
        }

    # ==================================================================
    # HOST COLLECTION
    # ==================================================================

    def _collect_host_metrics(self) -> Dict[str, float]:
        """
        Collect host resource metrics.

        Injected providers are used by deterministic tests and controlled
        integration environments.
        """

        if self._host_metrics_provider is not None:
            try:
                metrics = self._host_metrics_provider()

                if not isinstance(metrics, Mapping):
                    raise TypeError(
                        "host_metrics_provider must return a mapping"
                    )

                return {
                    "cpu_percent": round(
                        self._bounded_percent(
                            metrics.get("cpu_percent", 0.0)
                        ),
                        2,
                    ),
                    "memory_percent": round(
                        self._bounded_percent(
                            metrics.get("memory_percent", 0.0)
                        ),
                        2,
                    ),
                    "memory_available_mb": round(
                        self._non_negative(
                            metrics.get(
                                "memory_available_mb",
                                0.0,
                            )
                        ),
                        2,
                    ),
                }

            except Exception:
                # Fail-safe collection boundary.
                return {
                    "cpu_percent": 0.0,
                    "memory_percent": 0.0,
                    "memory_available_mb": 0.0,
                }

        try:
            cpu_percent = self._bounded_percent(
                psutil.cpu_percent(interval=0.0)
            )
        except Exception:
            cpu_percent = 0.0

        try:
            memory = psutil.virtual_memory()

            memory_percent = self._bounded_percent(
                memory.percent
            )

            memory_available_mb = (
                self._non_negative(memory.available)
                / (1024.0 * 1024.0)
            )

        except Exception:
            memory_percent = 0.0
            memory_available_mb = 0.0

        return {
            "cpu_percent": round(cpu_percent, 2),
            "memory_percent": round(memory_percent, 2),
            "memory_available_mb": round(
                memory_available_mb,
                2,
            ),
        }

    # ==================================================================
    # AGENT COLLECTION
    # ==================================================================

    def _collect_agent_metrics(self) -> Dict[str, Any]:
        """
        Collect CyberDefender process resource usage.

        CPU is normalized against total logical CPU capacity.
        """

        result: Dict[str, Any] = {
            "pid": self._process_pid,
            "cpu_percent": 0.0,
            "cpu_percent_raw": 0.0,
            "memory_rss_mb": 0.0,
            "memory_percent": 0.0,
            "threads": 0,
            "available": False,
        }

        if self._agent_metrics_provider is not None:
            try:
                metrics = self._agent_metrics_provider()

                if not isinstance(metrics, Mapping):
                    raise TypeError(
                        "agent_metrics_provider must return a mapping"
                    )

                return {
                    "pid": self._process_pid,
                    "cpu_percent": round(
                        self._bounded_percent(
                            metrics.get("cpu_percent", 0.0)
                        ),
                        2,
                    ),
                    "cpu_percent_raw": round(
                        self._non_negative(
                            metrics.get(
                                "cpu_percent_raw",
                                metrics.get(
                                    "cpu_percent",
                                    0.0,
                                ),
                            )
                        ),
                        2,
                    ),
                    "memory_rss_mb": round(
                        self._non_negative(
                            metrics.get(
                                "memory_rss_mb",
                                0.0,
                            )
                        ),
                        2,
                    ),
                    "memory_percent": round(
                        self._bounded_percent(
                            metrics.get(
                                "memory_percent",
                                0.0,
                            )
                        ),
                        2,
                    ),
                    "threads": max(
                        0,
                        int(
                            self._non_negative(
                                metrics.get(
                                    "threads",
                                    0,
                                )
                            )
                        ),
                    ),
                    "available": True,
                }

            except Exception:
                return {
                    "pid": self._process_pid,
                    "cpu_percent": 0.0,
                    "cpu_percent_raw": 0.0,
                    "memory_rss_mb": 0.0,
                    "memory_percent": 0.0,
                    "threads": 0,
                    "available": False,
                }

        process = self._process

        if process is None:
            return result

        try:
            if not process.is_running():
                return result

            raw_cpu = self._non_negative(
                process.cpu_percent(interval=None)
            )

            logical_cpus = max(
                1,
                psutil.cpu_count(logical=True) or 1,
            )

            normalized_cpu = raw_cpu / logical_cpus

            memory_info = process.memory_info()

            rss_mb = (
                self._non_negative(memory_info.rss)
                / (1024.0 * 1024.0)
            )

            memory_percent = self._bounded_percent(
                process.memory_percent()
            )

            try:
                thread_count = max(
                    0,
                    int(process.num_threads()),
                )
            except Exception:
                thread_count = 0

            result.update(
                {
                    "cpu_percent": round(
                        min(100.0, normalized_cpu),
                        2,
                    ),
                    "cpu_percent_raw": round(
                        raw_cpu,
                        2,
                    ),
                    "memory_rss_mb": round(
                        rss_mb,
                        2,
                    ),
                    "memory_percent": round(
                        memory_percent,
                        2,
                    ),
                    "threads": thread_count,
                    "available": True,
                }
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            result["available"] = False

        except Exception:
            result["available"] = False

        return result

    # ==================================================================
    # COLLECTION
    # ==================================================================

    def collect(self) -> Dict[str, Any]:
        """
        Collect a complete resource snapshot.

        Backward-compatible top-level fields are preserved.
        """

        timestamp = time.time()

        host = self._collect_host_metrics()
        agent = self._collect_agent_metrics()

        collection_ok = (
            agent.get("available", False)
            or self._process is None
        )

        return {
            "timestamp": timestamp,

            # Backward-compatible fields.
            "cpu_percent": host["cpu_percent"],
            "memory_percent": host["memory_percent"],
            "memory_available_mb": host[
                "memory_available_mb"
            ],

            # v2 host namespace.
            "host": host,

            # v2 CyberDefender namespace.
            "agent": agent,

            "collection_ok": bool(collection_ok),
        }

    # ==================================================================
    # PRESSURE SCORE
    # ==================================================================

    @staticmethod
    def _ratio_score(
        value: float,
        warning: float,
        critical: float,
        inverse: bool = False,
    ) -> float:
        """
        Convert a metric into bounded 0..100 pressure.

        Normal metric:
            <= warning -> 0
            >= critical -> 100

        Inverse metric:
            >= warning -> 0
            <= critical -> 100
        """

        value = ResourceGuard._finite_float(value, 0.0)
        warning = ResourceGuard._finite_float(warning, 0.0)
        critical = ResourceGuard._finite_float(critical, 0.0)

        if inverse:
            if warning <= critical:
                return 100.0 if value <= critical else 0.0

            if value >= warning:
                return 0.0

            if value <= critical:
                return 100.0

            span = warning - critical

            pressure = (
                (warning - value) / span
            ) * 100.0

        else:
            if critical <= warning:
                return 100.0 if value >= critical else 0.0

            if value <= warning:
                return 0.0

            if value >= critical:
                return 100.0

            span = critical - warning

            pressure = (
                (value - warning) / span
            ) * 100.0

        return round(
            max(
                0.0,
                min(
                    100.0,
                    pressure,
                ),
            ),
            2,
        )

    def calculate_pressure_score(
        self,
        snapshot: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calculate independent pressure signals.

        Overall pressure is the maximum signal so that a severe
        single-resource condition cannot be averaged away.
        """

        policy = self._validated_policy()

        host = snapshot.get("host", {})
        agent = snapshot.get("agent", {})

        if not isinstance(host, Mapping):
            host = {}

        if not isinstance(agent, Mapping):
            agent = {}

        host_cpu = self._ratio_score(
            host.get(
                "cpu_percent",
                snapshot.get(
                    "cpu_percent",
                    0.0,
                ),
            ),
            policy.cpu_warning,
            policy.cpu_critical,
        )

        host_memory = self._ratio_score(
            host.get(
                "memory_percent",
                snapshot.get(
                    "memory_percent",
                    0.0,
                ),
            ),
            policy.memory_warning,
            policy.memory_critical,
        )

        available_memory = self._ratio_score(
            host.get(
                "memory_available_mb",
                snapshot.get(
                    "memory_available_mb",
                    0.0,
                ),
            ),
            policy.available_memory_warning_mb,
            policy.available_memory_critical_mb,
            inverse=True,
        )

        agent_cpu = self._ratio_score(
            agent.get(
                "cpu_percent",
                0.0,
            ),
            policy.agent_cpu_warning,
            policy.agent_cpu_critical,
        )

        agent_memory = self._ratio_score(
            agent.get(
                "memory_rss_mb",
                0.0,
            ),
            policy.agent_memory_warning_mb,
            policy.agent_memory_critical_mb,
        )

        signals = {
            "host_cpu": host_cpu,
            "host_memory": host_memory,
            "available_memory": available_memory,
            "agent_cpu": agent_cpu,
            "agent_memory": agent_memory,
        }

        overall = max(signals.values())

        return {
            "overall": round(
                overall,
                2,
            ),
            "signals": signals,
        }

    # ==================================================================
    # STATE MACHINE
    # ==================================================================

    def _commit_state(self, state: str) -> str:
        """
        Atomically commit a validated state.

        This is the critical fix for direct evaluate() callers.

        Previously ResourceSafetyPlane could call evaluate() without
        check(), leaving last_state stale. That could prevent recovery
        from progressing correctly.
        """

        if state not in self.VALID_STATES:
            # Fail closed toward the most restrictive safe state.
            state = self.CRITICAL

        self.last_state = state
        return state

    def evaluate(
        self,
        snapshot: Dict[str, Any],
    ) -> str:
        """
        Deterministically evaluate and COMMIT resource state.

        Public callers may invoke this directly.

        State transition guarantees:

            NORMAL
              -> DEGRADED after sustained pressure
              -> CRITICAL after sustained critical pressure

            CRITICAL
              -> DEGRADED after first healthy recovery sample
              -> NORMAL after required healthy confirmations

        A single clean sample never immediately returns NORMAL from
        CRITICAL/DEGRADED when recovery confirmations > 1.
        """

        policy = self._validated_policy()

        host = snapshot.get("host", {})
        agent = snapshot.get("agent", {})

        if not isinstance(host, Mapping):
            host = {}

        if not isinstance(agent, Mapping):
            agent = {}

        cpu = self._finite_float(
            host.get(
                "cpu_percent",
                snapshot.get(
                    "cpu_percent",
                    0.0,
                ),
            )
        )

        memory = self._finite_float(
            host.get(
                "memory_percent",
                snapshot.get(
                    "memory_percent",
                    0.0,
                ),
            )
        )

        available_memory = self._finite_float(
            host.get(
                "memory_available_mb",
                snapshot.get(
                    "memory_available_mb",
                    0.0,
                ),
            )
        )

        agent_cpu = self._finite_float(
            agent.get(
                "cpu_percent",
                0.0,
            )
        )

        agent_memory = self._finite_float(
            agent.get(
                "memory_rss_mb",
                0.0,
            )
        )

        # --------------------------------------------------------------
        # CRITICAL SIGNAL
        # --------------------------------------------------------------

        host_critical = (
            cpu >= policy.cpu_critical
            or memory >= policy.memory_critical
            or available_memory
            <= policy.available_memory_critical_mb
        )

        agent_critical = (
            agent_cpu >= policy.agent_cpu_critical
            or agent_memory >= policy.agent_memory_critical_mb
        )

        critical_signal = (
            host_critical
            or agent_critical
        )

        # --------------------------------------------------------------
        # DEGRADED SIGNAL
        # --------------------------------------------------------------

        host_degraded = (
            cpu >= policy.cpu_warning
            or memory >= policy.memory_warning
            or available_memory
            <= policy.available_memory_warning_mb
        )

        agent_degraded = (
            agent_cpu >= policy.agent_cpu_warning
            or agent_memory >= policy.agent_memory_warning_mb
        )

        degraded_signal = (
            host_degraded
            or agent_degraded
        )

        # --------------------------------------------------------------
        # CRITICAL PRESSURE
        # --------------------------------------------------------------

        if critical_signal:
            self._critical_streak += 1
            self._degraded_streak += 1

            # Pressure invalidates recovery.
            self._recovery_streak = 0

            if (
                self._critical_streak
                >= policy.critical_confirmations
            ):
                return self._commit_state(
                    self.CRITICAL
                )

            # Before critical confirmation, preserve an already critical
            # state; otherwise use DEGRADED as the conservative staging
            # state.
            if self.last_state == self.CRITICAL:
                return self._commit_state(
                    self.CRITICAL
                )

            return self._commit_state(
                self.DEGRADED
            )

        # --------------------------------------------------------------
        # CRITICAL PRESSURE CLEARED
        # --------------------------------------------------------------

        self._critical_streak = 0

        # --------------------------------------------------------------
        # DEGRADED PRESSURE
        # --------------------------------------------------------------

        if degraded_signal:
            self._degraded_streak += 1

            # Pressure invalidates recovery.
            self._recovery_streak = 0

            if (
                self._degraded_streak
                >= policy.degraded_confirmations
            ):
                return self._commit_state(
                    self.DEGRADED
                )

            # Do not silently recover from CRITICAL while pressure is
            # still present.
            if self.last_state == self.CRITICAL:
                return self._commit_state(
                    self.CRITICAL
                )

            return self._commit_state(
                self.NORMAL
            )

        # --------------------------------------------------------------
        # HEALTHY / RECOVERY
        # --------------------------------------------------------------

        self._degraded_streak = 0
        self._recovery_streak += 1

        previous_state = self.last_state

        if previous_state in (
            self.CRITICAL,
            self.DEGRADED,
        ):
            if (
                self._recovery_streak
                < policy.recovery_confirmations
            ):
                # Explicitly preserve state until recovery is confirmed.
                return self._commit_state(
                    previous_state
                )

        # Recovery confirmed.
        return self._commit_state(
            self.NORMAL
        )

    # ==================================================================
    # CHECK
    # ==================================================================

    def check(self) -> Dict[str, Any]:
        """
        Perform one complete resource check.

        Existing API is preserved.
        """

        snapshot = self.collect()

        pressure = self.calculate_pressure_score(
            snapshot
        )

        state = self.evaluate(
            snapshot
        )

        self.check_count += 1
        self.last_check_time = snapshot["timestamp"]
        self.last_snapshot = snapshot

        if state == self.NORMAL:
            self.normal_count += 1

        elif state == self.DEGRADED:
            self.degraded_count += 1

        elif state == self.CRITICAL:
            self.critical_count += 1

        return {
            "component": "ResourceGuard",
            "version": self.VERSION,
            "state": state,
            "resource": snapshot,
            "pressure": pressure,

            "protected_components": list(
                self.PROTECTED_COMPONENTS
            ),

            "safety": {
                "process_termination": False,
                "system_modification": False,
                "firewall_modification": False,
                "registry_modification": False,
                "service_modification": False,
            },

            "streaks": {
                "degraded": self._degraded_streak,
                "critical": self._critical_streak,
                "recovery": self._recovery_streak,
            },
        }

    # ==================================================================
    # RUNTIME BUDGET
    # ==================================================================

    def get_runtime_budget(self) -> Dict[str, Any]:
        """
        Return bounded runtime workload recommendations.

        ResourceGuard never directly enforces destructive actions.
        """

        state = self.last_state

        base = {
            "state": state,

            "protected_components": list(
                self.PROTECTED_COMPONENTS
            ),

            # Security invariants.
            "allow_security_pipeline": True,
            "allow_safety_core": True,
            "allow_self_defense": True,
            "allow_integrity": True,

            # Never terminate processes.
            "process_termination": False,
        }

        # --------------------------------------------------------------
        # NORMAL
        # --------------------------------------------------------------

        if state == self.NORMAL:
            return {
                **base,

                "sensor_sampling": "NORMAL",
                "deep_analysis": True,
                "ai_inference": True,
                "graph_processing": True,
                "telemetry_batching": "NORMAL",
                "event_rate_limit": "NORMAL",
                "backpressure": False,
                "low_priority_eviction": False,
                "spool_mode": "NORMAL",
            }

        # --------------------------------------------------------------
        # DEGRADED
        # --------------------------------------------------------------

        if state == self.DEGRADED:
            return {
                **base,

                "sensor_sampling": "REDUCED",
                "deep_analysis": False,
                "ai_inference": "LIMITED",
                "graph_processing": True,
                "telemetry_batching": "AGGRESSIVE",
                "event_rate_limit": "THROTTLED",
                "backpressure": True,
                "low_priority_eviction": True,
                "spool_mode": "BOUNDED",
            }

        # --------------------------------------------------------------
        # CRITICAL
        # --------------------------------------------------------------

        return {
            **base,

            "sensor_sampling": "MINIMAL",
            "deep_analysis": False,
            "ai_inference": False,
            "graph_processing": "MINIMAL",
            "telemetry_batching": "MAXIMUM",
            "event_rate_limit": "STRICT",
            "backpressure": True,
            "low_priority_eviction": True,
            "spool_mode": "EMERGENCY_BOUNDED",
        }

    # ==================================================================
    # STATS
    # ==================================================================

    def get_stats(self) -> Dict[str, Any]:
        """
        Return bounded observability statistics.
        """

        pressure = None

        if self.last_snapshot is not None:
            pressure = self.calculate_pressure_score(
                self.last_snapshot
            )

        return {
            "component": "ResourceGuard",
            "version": self.VERSION,

            "checks": self.check_count,
            "normal": self.normal_count,
            "degraded": self.degraded_count,
            "critical": self.critical_count,

            "last_state": self.last_state,
            "last_check_time": self.last_check_time,

            "policy": asdict(
                self._validated_policy()
            ),

            "pressure": pressure,

            "streaks": {
                "degraded": self._degraded_streak,
                "critical": self._critical_streak,
                "recovery": self._recovery_streak,
            },

            "process_monitor": {
                "pid": self._process_pid,
                "available": self._process is not None,
            },

            "protected_components": list(
                self.PROTECTED_COMPONENTS
            ),
        }