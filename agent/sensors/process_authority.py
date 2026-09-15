from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time
from pathlib import Path
from typing import Any


class ProcessSensorAuthorityError(RuntimeError):
    """Authority-controller configuration or contract failure."""


class ProcessSensorMode:
    """Stable process-sensor authority modes.

    These values are intentionally plain strings so they remain easy to
    expose through environment configuration, logs, health telemetry and
    future cross-language control-plane schemas.
    """

    PYTHON_ONLY = "PYTHON_ONLY"
    RUST_SHADOW = "RUST_SHADOW"
    RUST_CANARY = "RUST_CANARY"
    RUST_PRIMARY_WITH_FALLBACK = "RUST_PRIMARY_WITH_FALLBACK"

    ALL = {
        PYTHON_ONLY,
        RUST_SHADOW,
        RUST_CANARY,
        RUST_PRIMARY_WITH_FALLBACK,
    }


@dataclass(frozen=True)
class RustAuthorityEvidence:
    eligible: bool
    reason: str
    coverage_mode: str | None
    coverage_valid: bool
    binary_trusted: bool
    probe_healthy: bool
    snapshot_validated: bool
    alignment_verdict: str | None
    identity_disagreements: int
    parent_disagreements: int
    exact_identity_matches: int
    common_processes: int
    alignment_age_seconds: float | None
    healthy_streak: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "reason": self.reason,
            "coverage_mode": self.coverage_mode,
            "coverage_valid": self.coverage_valid,
            "binary_trusted": self.binary_trusted,
            "probe_healthy": self.probe_healthy,
            "snapshot_validated": self.snapshot_validated,
            "alignment_verdict": self.alignment_verdict,
            "identity_disagreements": self.identity_disagreements,
            "parent_disagreements": self.parent_disagreements,
            "exact_identity_matches": self.exact_identity_matches,
            "common_processes": self.common_processes,
            "alignment_age_seconds": self.alignment_age_seconds,
            "healthy_streak": self.healthy_streak,
        }


@dataclass(frozen=True)
class ProcessAuthorityDecision:
    authoritative_sensor: str | None
    disposition: str
    reason: str
    may_ingest: bool
    would_select_sensor: str | None
    controller_state: str
    mode: str
    generation: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "authoritative_sensor": self.authoritative_sensor,
            "disposition": self.disposition,
            "reason": self.reason,
            "may_ingest": self.may_ingest,
            "would_select_sensor": self.would_select_sensor,
            "controller_state": self.controller_state,
            "mode": self.mode,
            "generation": self.generation,
        }


class ProcessSensorAuthorityController:
    """Fail-closed authority selector for process telemetry.

    Security goals:
      * Python remains authoritative in the current release.
      * RUST_SHADOW never affects ProcessGraph ownership.
      * RUST_CANARY may calculate a would-select decision but never owns data.
      * RUST_PRIMARY_WITH_FALLBACK remains protected by a compiled release
        lock plus explicit operator unlock and all evidence gates.
      * One transient primary failure cannot flip authority.
      * Failback is also hysteresis-controlled to prevent sensor flapping.
      * No mixed/merged authoritative snapshot is ever created here.
      * An unsafe candidate yields no authoritative snapshot rather than an
        implicit trust downgrade.

    This controller decides *ownership*. It does not collect processes and it
    does not mutate ProcessGraph, EventBus, Policy, SafetyCore, or OS state.
    """

    VERSION = "1.0"

    # Current pinned native artifact. A different Rust binary requires an
    # explicit reviewed code release rather than a mutable environment-only
    # trust override.
    PINNED_RUST_V04_SHA256 = (
        "ada90a9ee632b225196348213ef05970828c38ceb0c69eb3776c7e8cb9bedd2d"
    )

    GOOD_ALIGNMENT_VERDICTS = {
        "ALIGNED_COMMON_SET",
        "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
    }

    SAFE_COVERAGE_MODES = {
        "COMPLETE",
        "PARTIAL_EXPLICIT_COVERAGE",
    }

    # Automatic authority promotion is intentionally stricter than graph
    # lifecycle acceptance. For v0.4, only the known PID 0 coverage gap may be
    # auto-eligible. Other explicit skips remain useful shadow/canary evidence
    # but require a future reviewed policy before automatic authority.
    AUTO_FAILOVER_ALLOWED_SKIP_REASONS = {
        "SYSTEM_IDLE_UNQUERYABLE",
    }

    PRIMARY_UNLOCK_TOKEN = "ALLOW_RUST_PRIMARY_V0_4"

    def __init__(
        self,
        *,
        mode: str,
        primary_unlock_token: str | None = None,
        python_failure_threshold: int = 2,
        python_recovery_threshold: int = 2,
        rust_healthy_threshold: int = 2,
        max_alignment_age_seconds: float = 30.0,
        compiled_primary_enabled: bool = False,
    ) -> None:
        normalized, config_error = self.normalize_mode(mode)

        if python_failure_threshold < 1:
            raise ValueError("python_failure_threshold")
        if python_recovery_threshold < 1:
            raise ValueError("python_recovery_threshold")
        if rust_healthy_threshold < 1:
            raise ValueError("rust_healthy_threshold")
        if not 0 < max_alignment_age_seconds <= 300:
            raise ValueError("max_alignment_age_seconds")

        self.mode = normalized
        self.config_error = config_error

        self.python_failure_threshold = int(python_failure_threshold)
        self.python_recovery_threshold = int(python_recovery_threshold)
        self.rust_healthy_threshold = int(rust_healthy_threshold)
        self.max_alignment_age_seconds = float(max_alignment_age_seconds)

        self.compiled_primary_enabled = bool(compiled_primary_enabled)
        self.primary_unlock_present = (
            str(primary_unlock_token or "").strip()
            == self.PRIMARY_UNLOCK_TOKEN
        )

        self.state = "PYTHON_PRIMARY"
        self.authoritative_sensor = "ProcessSensor"
        self.python_failure_streak = 0
        self.python_recovery_streak = 0
        self.rust_healthy_streak = 0

        self.generation = 0
        self.failover_count = 0
        self.failback_count = 0
        self.hold_count = 0
        self.fail_closed_count = 0
        self.canary_would_failover_count = 0

        self.last_transition_monotonic: float | None = None
        self.last_good_alignment_monotonic: float | None = None
        self.last_alignment_verdict: str | None = None
        self.last_alignment_identity_disagreements = -1
        self.last_alignment_parent_disagreements = -1
        self.last_alignment_exact_identity_matches = -1
        self.last_alignment_common_processes = -1
        self.last_rust_evidence: RustAuthorityEvidence | None = None
        self.last_decision: ProcessAuthorityDecision | None = None
        self.last_error: str | None = config_error

    # ---------------------------------------------------------
    # CONFIGURATION
    # ---------------------------------------------------------

    @staticmethod
    def normalize_mode(value: Any) -> tuple[str, str | None]:
        text = str(value or "").strip().upper()
        if text in ProcessSensorMode.ALL:
            return text, None

        # Invalid authority configuration must never broaden authority.
        return (
            ProcessSensorMode.PYTHON_ONLY,
            "INVALID_PROCESS_SENSOR_MODE",
        )

    @staticmethod
    def sha256_file(path: str | Path) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    def rust_binary_trusted(cls, digest: Any) -> bool:
        return (
            isinstance(digest, str)
            and digest.lower() == cls.PINNED_RUST_V04_SHA256
        )

    def rust_required(self) -> bool:
        return self.mode in {
            ProcessSensorMode.RUST_SHADOW,
            ProcessSensorMode.RUST_CANARY,
            ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK,
        }

    def primary_runtime_unlocked(self) -> bool:
        return (
            self.mode == ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK
            and self.compiled_primary_enabled
            and self.primary_unlock_present
        )

    # ---------------------------------------------------------
    # RUST EVIDENCE
    # ---------------------------------------------------------

    @staticmethod
    def _coverage_contract(
        snapshot: dict[str, Any],
    ) -> tuple[bool, str, str]:
        partial = snapshot.get("partial", False)
        skipped = snapshot.get("skipped", 0)

        if type(partial) is not bool:
            return False, "PARTIAL_FAIL_CLOSED", "PARTIAL_FLAG_INVALID"
        if type(skipped) is not int or skipped < 0:
            return False, "PARTIAL_FAIL_CLOSED", "SKIPPED_COUNT_INVALID"

        diagnostics = snapshot.get("skipped_processes")

        if not partial:
            if skipped != 0:
                return (
                    False,
                    "PARTIAL_FAIL_CLOSED",
                    "COMPLETE_WITH_NONZERO_SKIPPED",
                )
            return True, "COMPLETE", "COMPLETE_NEGATIVE_INFERENCE_ALLOWED"

        if not isinstance(diagnostics, list):
            return False, "PARTIAL_FAIL_CLOSED", "SKIP_LIST_INVALID"
        if len(diagnostics) != skipped:
            return False, "PARTIAL_FAIL_CLOSED", "SKIPPED_COUNT_MISMATCH"

        observed: set[int] = set()
        for row in snapshot.get("processes", []):
            if isinstance(row, dict) and type(row.get("pid")) is int:
                observed.add(row["pid"])

        skipped_seen: set[int] = set()
        for item in diagnostics:
            if not isinstance(item, dict):
                return False, "PARTIAL_FAIL_CLOSED", "SKIP_ENTRY_INVALID"
            pid = item.get("pid")
            reason = item.get("reason")
            if type(pid) is not int or pid < 0:
                return False, "PARTIAL_FAIL_CLOSED", "SKIP_PID_INVALID"
            if not isinstance(reason, str) or not reason:
                return False, "PARTIAL_FAIL_CLOSED", "SKIP_REASON_INVALID"
            if pid in skipped_seen:
                return False, "PARTIAL_FAIL_CLOSED", "SKIP_PID_DUPLICATE"
            if pid in observed:
                return (
                    False,
                    "PARTIAL_FAIL_CLOSED",
                    "SKIPPED_PID_ALSO_OBSERVED",
                )
            skipped_seen.add(pid)

        return True, "PARTIAL_EXPLICIT_COVERAGE", "PARTIAL_SKIP_SCOPE_APPLIED"

    @classmethod
    def _auto_failover_skip_scope_safe(
        cls,
        snapshot: dict[str, Any],
    ) -> bool:
        if not snapshot.get("partial"):
            return True

        diagnostics = snapshot.get("skipped_processes")
        if not isinstance(diagnostics, list) or not diagnostics:
            return False

        for item in diagnostics:
            if not isinstance(item, dict):
                return False
            if item.get("reason") not in cls.AUTO_FAILOVER_ALLOWED_SKIP_REASONS:
                return False

            # v0.4 automatic promotion scope is deliberately pinned to the
            # already-verified Windows PID 0 limitation.
            if (
                item.get("reason") == "SYSTEM_IDLE_UNQUERYABLE"
                and not (
                    item.get("pid") == 0
                    and item.get("win32_error") == 87
                )
            ):
                return False

        return True

    def assess_rust_evidence(
        self,
        *,
        rust_snapshot: dict[str, Any] | None,
        comparison: dict[str, Any] | None,
        probe_health: dict[str, Any] | None,
        binary_sha256: str | None,
        transport_validated: bool = False,
        now_monotonic: float | None = None,
    ) -> RustAuthorityEvidence:
        now = time.monotonic() if now_monotonic is None else float(now_monotonic)

        binary_trusted = self.rust_binary_trusted(binary_sha256)
        probe_healthy = (
            isinstance(probe_health, dict)
            and probe_health.get("status") == "HEALTHY"
        )
        snapshot_validated = (
            transport_validated is True
            and isinstance(rust_snapshot, dict)
            and rust_snapshot.get("schema") == "cd.process.v4"
            and rust_snapshot.get("sensor") == "RustProcessSensor"
            and rust_snapshot.get("version") == "0.4.0"
        )

        coverage_valid = False
        coverage_mode: str | None = None
        coverage_reason = "RUST_SNAPSHOT_MISSING"
        if snapshot_validated and isinstance(rust_snapshot, dict):
            coverage_valid, coverage_mode, coverage_reason = (
                self._coverage_contract(rust_snapshot)
            )

        if isinstance(comparison, dict):
            candidate_verdict = comparison.get("verdict")
            candidate_identity_disagreements = int(
                comparison.get("identity_disagreements", {}).get("count", -1)
            )
            candidate_parent_disagreements = int(
                comparison.get("parent_disagreements", {}).get("count", -1)
            )
            candidate_exact_identity_matches = int(
                comparison.get("exact_graph_identity_matches", -1)
            )
            candidate_common_processes = int(
                comparison.get("common_processes", -1)
            )

            fresh_comparison_good = (
                candidate_verdict in self.GOOD_ALIGNMENT_VERDICTS
                and candidate_identity_disagreements == 0
                and candidate_parent_disagreements == 0
                and candidate_common_processes >= 0
                and candidate_exact_identity_matches == candidate_common_processes
            )

            if fresh_comparison_good:
                self.last_good_alignment_monotonic = now
                self.last_alignment_verdict = candidate_verdict
                self.last_alignment_identity_disagreements = (
                    candidate_identity_disagreements
                )
                self.last_alignment_parent_disagreements = (
                    candidate_parent_disagreements
                )
                self.last_alignment_exact_identity_matches = (
                    candidate_exact_identity_matches
                )
                self.last_alignment_common_processes = candidate_common_processes
            else:
                # A fresh disagreement invalidates older parity evidence.
                self.last_good_alignment_monotonic = None
                self.last_alignment_verdict = candidate_verdict
                self.last_alignment_identity_disagreements = (
                    candidate_identity_disagreements
                )
                self.last_alignment_parent_disagreements = (
                    candidate_parent_disagreements
                )
                self.last_alignment_exact_identity_matches = (
                    candidate_exact_identity_matches
                )
                self.last_alignment_common_processes = candidate_common_processes

        alignment_verdict = self.last_alignment_verdict
        identity_disagreements = self.last_alignment_identity_disagreements
        parent_disagreements = self.last_alignment_parent_disagreements
        exact_identity_matches = self.last_alignment_exact_identity_matches
        common_processes = self.last_alignment_common_processes

        alignment_age: float | None = None
        if self.last_good_alignment_monotonic is not None:
            alignment_age = max(0.0, now - self.last_good_alignment_monotonic)

        comparison_good = (
            self.last_good_alignment_monotonic is not None
            and alignment_verdict in self.GOOD_ALIGNMENT_VERDICTS
            and identity_disagreements == 0
            and parent_disagreements == 0
            and common_processes >= 0
            and exact_identity_matches == common_processes
        )

        skip_scope_safe = (
            isinstance(rust_snapshot, dict)
            and self._auto_failover_skip_scope_safe(rust_snapshot)
        )

        reason = "RUST_GATE_PASS"

        # Health streak measures current native-sensor quality and therefore
        # can continue while Python is temporarily unavailable. Alignment is
        # a separate lease with a bounded age.
        current_native_health_good = all([
            binary_trusted,
            probe_healthy,
            snapshot_validated,
            coverage_valid,
            coverage_mode in self.SAFE_COVERAGE_MODES,
            skip_scope_safe,
        ])

        if current_native_health_good:
            self.rust_healthy_streak += 1
        else:
            self.rust_healthy_streak = 0

        eligible = True
        checks = [
            (binary_trusted, "RUST_BINARY_UNTRUSTED"),
            (probe_healthy, "RUST_PROBE_UNHEALTHY"),
            (snapshot_validated, "RUST_SNAPSHOT_UNVALIDATED"),
            (coverage_valid, "RUST_COVERAGE_INVALID"),
            (coverage_mode in self.SAFE_COVERAGE_MODES, "RUST_COVERAGE_MODE_UNSAFE"),
            (skip_scope_safe, "RUST_SKIP_SCOPE_NOT_AUTO_ELIGIBLE"),
            (comparison_good, "RUST_ALIGNMENT_NOT_GOOD"),
            (
                alignment_age is not None
                and alignment_age <= self.max_alignment_age_seconds,
                "RUST_ALIGNMENT_STALE",
            ),
            (
                self.rust_healthy_streak >= self.rust_healthy_threshold,
                "RUST_HEALTH_STREAK_TOO_SHORT",
            ),
        ]

        for passed, failure_reason in checks:
            if not passed:
                eligible = False
                reason = failure_reason
                break

        evidence = RustAuthorityEvidence(
            eligible=eligible,
            reason=reason if eligible else (
                reason if reason != "RUST_COVERAGE_INVALID" else coverage_reason
            ),
            coverage_mode=coverage_mode,
            coverage_valid=coverage_valid,
            binary_trusted=binary_trusted,
            probe_healthy=probe_healthy,
            snapshot_validated=snapshot_validated,
            alignment_verdict=alignment_verdict,
            identity_disagreements=identity_disagreements,
            parent_disagreements=parent_disagreements,
            exact_identity_matches=exact_identity_matches,
            common_processes=common_processes,
            alignment_age_seconds=alignment_age,
            healthy_streak=self.rust_healthy_streak,
        )
        self.last_rust_evidence = evidence
        return evidence

    # ---------------------------------------------------------
    # AUTHORITY STATE MACHINE
    # ---------------------------------------------------------

    def _commit(
        self,
        *,
        authoritative_sensor: str | None,
        disposition: str,
        reason: str,
        may_ingest: bool,
        would_select_sensor: str | None,
    ) -> ProcessAuthorityDecision:
        self.generation += 1
        decision = ProcessAuthorityDecision(
            authoritative_sensor=authoritative_sensor,
            disposition=disposition,
            reason=reason,
            may_ingest=may_ingest,
            would_select_sensor=would_select_sensor,
            controller_state=self.state,
            mode=self.mode,
            generation=self.generation,
        )
        self.last_decision = decision
        return decision

    def decide(
        self,
        *,
        python_snapshot: dict[str, Any] | None,
        rust_snapshot: dict[str, Any] | None = None,
        rust_evidence: RustAuthorityEvidence | None = None,
        now_monotonic: float | None = None,
    ) -> ProcessAuthorityDecision:
        now = time.monotonic() if now_monotonic is None else float(now_monotonic)
        python_ok = isinstance(python_snapshot, dict)
        rust_ok = (
            isinstance(rust_snapshot, dict)
            and isinstance(rust_evidence, RustAuthorityEvidence)
            and rust_evidence.eligible
        )

        # -----------------------------------------------------
        # Current Python-primary state
        # -----------------------------------------------------
        if self.state == "PYTHON_PRIMARY":
            self.python_recovery_streak = 0

            if python_ok:
                self.python_failure_streak = 0
                self.authoritative_sensor = "ProcessSensor"
                return self._commit(
                    authoritative_sensor="ProcessSensor",
                    disposition="PYTHON_AUTHORITATIVE",
                    reason="PYTHON_HEALTHY",
                    may_ingest=True,
                    would_select_sensor=None,
                )

            self.python_failure_streak += 1

            if self.python_failure_streak < self.python_failure_threshold:
                self.hold_count += 1
                return self._commit(
                    authoritative_sensor=None,
                    disposition="HOLD_LAST_GRAPH_STATE",
                    reason="PYTHON_FAILURE_NOT_CONFIRMED",
                    may_ingest=False,
                    would_select_sensor=None,
                )

            # PYTHON_ONLY and RUST_SHADOW never promote Rust.
            if self.mode in {
                ProcessSensorMode.PYTHON_ONLY,
                ProcessSensorMode.RUST_SHADOW,
            }:
                self.fail_closed_count += 1
                return self._commit(
                    authoritative_sensor=None,
                    disposition="NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                    reason=(
                        "RUST_DISABLED"
                        if self.mode == ProcessSensorMode.PYTHON_ONLY
                        else "RUST_SHADOW_NON_AUTHORITATIVE"
                    ),
                    may_ingest=False,
                    would_select_sensor=None,
                )

            # Canary computes readiness but cannot own the graph.
            if self.mode == ProcessSensorMode.RUST_CANARY:
                if rust_ok:
                    self.canary_would_failover_count += 1
                    would_select = "RustProcessSensor"
                    reason = "CANARY_WOULD_FAILOVER"
                else:
                    would_select = None
                    reason = (
                        rust_evidence.reason
                        if isinstance(rust_evidence, RustAuthorityEvidence)
                        else "RUST_EVIDENCE_MISSING"
                    )

                self.fail_closed_count += 1
                return self._commit(
                    authoritative_sensor=None,
                    disposition="CANARY_NO_AUTHORITY_SWITCH",
                    reason=reason,
                    may_ingest=False,
                    would_select_sensor=would_select,
                )

            # Production-primary mode requires both code-release and operator
            # locks. Environment configuration alone cannot activate it.
            if not self.compiled_primary_enabled:
                self.fail_closed_count += 1
                return self._commit(
                    authoritative_sensor=None,
                    disposition="NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                    reason="RUST_PRIMARY_COMPILED_LOCKED",
                    may_ingest=False,
                    would_select_sensor=(
                        "RustProcessSensor" if rust_ok else None
                    ),
                )

            if not self.primary_unlock_present:
                self.fail_closed_count += 1
                return self._commit(
                    authoritative_sensor=None,
                    disposition="NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                    reason="RUST_PRIMARY_OPERATOR_LOCKED",
                    may_ingest=False,
                    would_select_sensor=(
                        "RustProcessSensor" if rust_ok else None
                    ),
                )

            if not rust_ok:
                self.fail_closed_count += 1
                return self._commit(
                    authoritative_sensor=None,
                    disposition="NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                    reason=(
                        rust_evidence.reason
                        if isinstance(rust_evidence, RustAuthorityEvidence)
                        else "RUST_EVIDENCE_MISSING"
                    ),
                    may_ingest=False,
                    would_select_sensor=None,
                )

            self.state = "RUST_FAILOVER"
            self.authoritative_sensor = "RustProcessSensor"
            self.failover_count += 1
            self.python_recovery_streak = 0
            self.last_transition_monotonic = now

            return self._commit(
                authoritative_sensor="RustProcessSensor",
                disposition="RUST_FAILOVER_AUTHORITATIVE",
                reason="PYTHON_FAILURE_CONFIRMED_RUST_GATE_PASS",
                may_ingest=True,
                would_select_sensor="RustProcessSensor",
            )

        # -----------------------------------------------------
        # Rust failover state (reachable only in explicitly compiled tests or
        # a future reviewed release).
        # -----------------------------------------------------
        if python_ok:
            self.python_recovery_streak += 1
        else:
            self.python_recovery_streak = 0

        if (
            python_ok
            and self.python_recovery_streak >= self.python_recovery_threshold
        ):
            self.state = "PYTHON_PRIMARY"
            self.authoritative_sensor = "ProcessSensor"
            self.python_failure_streak = 0
            self.python_recovery_streak = 0
            self.failback_count += 1
            self.last_transition_monotonic = now

            return self._commit(
                authoritative_sensor="ProcessSensor",
                disposition="PYTHON_FAILBACK_AUTHORITATIVE",
                reason="PYTHON_RECOVERY_CONFIRMED",
                may_ingest=True,
                would_select_sensor=None,
            )

        if not rust_ok:
            self.fail_closed_count += 1
            self.authoritative_sensor = None
            return self._commit(
                authoritative_sensor=None,
                disposition="NO_SAFE_AUTHORITATIVE_SNAPSHOT",
                reason=(
                    rust_evidence.reason
                    if isinstance(rust_evidence, RustAuthorityEvidence)
                    else "RUST_EVIDENCE_MISSING"
                ),
                may_ingest=False,
                would_select_sensor=None,
            )

        self.authoritative_sensor = "RustProcessSensor"
        return self._commit(
            authoritative_sensor="RustProcessSensor",
            disposition="RUST_FAILOVER_AUTHORITATIVE",
            reason="RUST_REMAINS_SAFE",
            may_ingest=True,
            would_select_sensor="RustProcessSensor",
        )

    # ---------------------------------------------------------
    # HEALTH / TELEMETRY
    # ---------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        status = "HEALTHY"

        if self.config_error:
            status = "DEGRADED"
        elif self.state == "RUST_FAILOVER":
            status = "DEGRADED"
        elif (
            self.mode == ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK
            and not self.compiled_primary_enabled
        ):
            # Configuration requests a capability this release intentionally
            # does not compile-enable. This is observable but fail-closed.
            status = "LOCKED"

        return {
            "component": "ProcessSensorAuthorityController",
            "status": status,
            "version": self.VERSION,
            "mode": self.mode,
            "state": self.state,
            "authoritative_sensor": self.authoritative_sensor,
            "compiled_primary_enabled": self.compiled_primary_enabled,
            "primary_unlock_present": self.primary_unlock_present,
            "python_failure_streak": self.python_failure_streak,
            "python_recovery_streak": self.python_recovery_streak,
            "rust_healthy_streak": self.rust_healthy_streak,
            "python_failure_threshold": self.python_failure_threshold,
            "python_recovery_threshold": self.python_recovery_threshold,
            "rust_healthy_threshold": self.rust_healthy_threshold,
            "max_alignment_age_seconds": self.max_alignment_age_seconds,
            "generation": self.generation,
            "failover_count": self.failover_count,
            "failback_count": self.failback_count,
            "hold_count": self.hold_count,
            "fail_closed_count": self.fail_closed_count,
            "canary_would_failover_count": self.canary_would_failover_count,
            "config_error": self.config_error,
            "last_error": self.last_error,
            "last_rust_evidence": (
                self.last_rust_evidence.to_dict()
                if self.last_rust_evidence is not None
                else None
            ),
            "last_decision": (
                self.last_decision.to_dict()
                if self.last_decision is not None
                else None
            ),
        }

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()
