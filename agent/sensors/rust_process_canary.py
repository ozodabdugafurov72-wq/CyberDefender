from __future__ import annotations

import hashlib
import math
import time
from pathlib import Path
from typing import Any, Callable

from agent.sensors.native_process_supervisor import (
    NativeProcessSensorSupervisor,
    NativeSensorSupervisorError,
)
from agent.sensors.rust_process_v05_contract import compare_enrichment


class RustProcessCanaryError(RuntimeError):
    """Non-authoritative Rust process canary failure."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(parsed):
        return default
    return max(minimum, min(parsed, maximum))


class RustProcessCanary:
    """Persistent non-authoritative Rust v0.5.1 process telemetry canary.

    Security boundary:
      * the canary never mutates ProcessGraph;
      * it never publishes directly to EventBus;
      * it never contributes authorization, Policy, SafetyCore or actions;
      * its binary is deployment-pinned before supervisor startup;
      * IPC is bounded and replay/order bound by NativeProcessSensorSupervisor;
      * failures are isolated from the Python-authoritative runtime.

    The canary is observability and readiness evidence only.  Its local
    deployment pin is deliberately *not* sufficient authority evidence for a
    future Rust-primary release; that future release requires signed release
    metadata / attestation rooted in CyberDefender trust infrastructure.
    """

    VERSION = "1.0"
    SENSOR_VERSION = "0.5.1"
    MODE = "RUST_CANARY"

    def __init__(
        self,
        executable: str | Path,
        expected_sha256: str,
        *,
        timeout: float = 5.0,
        max_restarts: int = 2,
        restart_window_seconds: float = 60.0,
        min_field_coverage: float = 0.98,
        supervisor_factory: Callable[..., Any] = NativeProcessSensorSupervisor,
    ) -> None:
        path = Path(executable).expanduser().resolve()
        if not path.is_absolute() or not path.is_file():
            raise RustProcessCanaryError("RUST_CANARY_EXECUTABLE_NOT_FOUND")

        expected = str(expected_sha256 or "").strip().lower()
        if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
            raise RustProcessCanaryError("RUST_CANARY_PIN_INVALID")

        actual = _sha256_file(path)
        if actual != expected:
            raise RustProcessCanaryError("RUST_CANARY_BINARY_HASH_MISMATCH")

        self.executable = path
        self.expected_sha256 = expected
        self.binary_sha256 = actual
        self.binary_trusted = True
        self.min_field_coverage = _bounded_float(
            min_field_coverage, 0.98, 0.50, 1.0
        )

        self.supervisor = supervisor_factory(
            path,
            expected_sha256=expected,
            timeout=_bounded_float(timeout, 5.0, 0.25, 30.0),
            max_restarts=max(0, min(int(max_restarts), 10)),
            restart_window_seconds=_bounded_float(
                restart_window_seconds, 60.0, 1.0, 600.0
            ),
        )

        self.sample_count = 0
        self.success_count = 0
        self.failure_count = 0
        self.last_error: str | None = None
        self.last_sample_time: float | None = None
        self.last_sample_latency_ms: float | None = None
        self.last_comparison: dict[str, Any] | None = None
        self.last_snapshot_summary: dict[str, Any] | None = None
        self.last_candidate_ready = False
        self.last_readiness_reason = "NO_SAMPLE"

    @staticmethod
    def _known_coverage_safe(snapshot: dict[str, Any]) -> bool:
        if snapshot.get("partial") is False:
            return int(snapshot.get("skipped", 0)) == 0

        diagnostics = snapshot.get("skipped_processes")
        if not isinstance(diagnostics, list) or not diagnostics:
            return False

        for item in diagnostics:
            if not isinstance(item, dict):
                return False
            if not (
                item.get("pid") == 0
                and item.get("reason") == "SYSTEM_IDLE_UNQUERYABLE"
                and item.get("win32_error") == 87
            ):
                return False
        return True

    @staticmethod
    def _extra_enrichment_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
        rows = snapshot.get("processes")
        if not isinstance(rows, list):
            rows = []
        total = len(rows)
        result: dict[str, Any] = {}
        for field in ("sid", "session_id", "integrity_level"):
            collected = 0
            for row in rows:
                if not isinstance(row, dict):
                    continue
                status_map = row.get("enrichment_status")
                status = None
                if isinstance(status_map, dict):
                    item = status_map.get(field)
                    if isinstance(item, dict):
                        status = item.get("status")
                if status == "COLLECTED" and row.get(field) is not None:
                    collected += 1
            result[field] = {
                "collected": collected,
                "total": total,
                "coverage_rate": round(collected / total, 6) if total else 0.0,
            }
        return result

    def _readiness(
        self,
        snapshot: dict[str, Any],
        comparison: dict[str, Any],
    ) -> tuple[bool, str]:
        supervisor_health = self.supervisor.health_check()
        if not isinstance(supervisor_health, dict) or supervisor_health.get("status") != "HEALTHY":
            return False, "SUPERVISOR_NOT_HEALTHY"
        if not self.binary_trusted:
            return False, "BINARY_PIN_NOT_TRUSTED"
        if not self._known_coverage_safe(snapshot):
            return False, "COVERAGE_NOT_CANARY_READY"

        checks = (
            ("identity_disagreements", "IDENTITY_DISAGREEMENT"),
            ("parent_disagreements", "PARENT_DISAGREEMENT"),
            ("canonical_name_conflicts", "CANONICAL_NAME_CONFLICT"),
        )
        for key, reason in checks:
            section = comparison.get(key)
            if not isinstance(section, dict) or int(section.get("count", -1)) != 0:
                return False, reason

        fields = comparison.get("fields")
        if not isinstance(fields, dict):
            return False, "ENRICHMENT_FIELDS_MISSING"
        for field in ("exe", "username", "cmdline"):
            stats = fields.get(field)
            if not isinstance(stats, dict):
                return False, f"{field.upper()}_PARITY_MISSING"
            if int(stats.get("mismatches", -1)) != 0:
                return False, f"{field.upper()}_PARITY_MISMATCH"
            try:
                coverage = float(stats.get("coverage_rate", 0.0))
            except (TypeError, ValueError):
                coverage = 0.0
            if coverage < self.min_field_coverage:
                return False, f"{field.upper()}_COVERAGE_BELOW_THRESHOLD"

        return True, "CANARY_PARITY_GATE_PASS"

    def sample(self, authoritative_snapshot: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(authoritative_snapshot, dict):
            raise RustProcessCanaryError("AUTHORITATIVE_SNAPSHOT_REQUIRED")

        self.sample_count += 1
        started = time.perf_counter()
        try:
            rust_snapshot = self.supervisor.snapshot()
            comparison = compare_enrichment(authoritative_snapshot, rust_snapshot)
            ready, reason = self._readiness(rust_snapshot, comparison)

            self.success_count += 1
            self.last_error = None
            self.last_sample_time = time.time()
            self.last_sample_latency_ms = round(
                (time.perf_counter() - started) * 1000.0, 3
            )
            self.last_comparison = comparison
            self.last_candidate_ready = ready
            self.last_readiness_reason = reason
            self.last_snapshot_summary = {
                "sensor": rust_snapshot.get("sensor"),
                "version": rust_snapshot.get("version"),
                "timestamp": rust_snapshot.get("timestamp"),
                "process_count": rust_snapshot.get("process_count"),
                "partial": rust_snapshot.get("partial"),
                "skipped": rust_snapshot.get("skipped"),
                "coverage_safe": self._known_coverage_safe(rust_snapshot),
                "extra_enrichment": self._extra_enrichment_coverage(rust_snapshot),
                "ipc": {
                    key: rust_snapshot.get("ipc", {}).get(key)
                    for key in (
                        "protocol",
                        "version",
                        "sequence",
                        "sensor_epoch",
                        "supervisor_pid",
                        "sensor_pid",
                    )
                } if isinstance(rust_snapshot.get("ipc"), dict) else {},
            }

            return {
                "schema": "cd.process-canary-result.v1",
                "mode": self.MODE,
                "authoritative": False,
                "authoritative_sensor": "ProcessSensor",
                "candidate_sensor": "RustProcessSensor",
                "candidate_version": self.SENSOR_VERSION,
                "candidate_ready": ready,
                "readiness_reason": reason,
                "sample_latency_ms": self.last_sample_latency_ms,
                "comparison": comparison,
                "snapshot_summary": self.last_snapshot_summary,
            }
        except Exception as exc:
            self.failure_count += 1
            self.last_error = "CANARY_SAMPLE_FAILED"
            self.last_sample_latency_ms = round(
                (time.perf_counter() - started) * 1000.0, 3
            )
            self.last_candidate_ready = False
            self.last_readiness_reason = "CANARY_SAMPLE_FAILED"
            raise RustProcessCanaryError("RUST_CANARY_SAMPLE_FAILED") from exc

    def health_check(self) -> dict[str, Any]:
        try:
            supervisor = self.supervisor.health_check()
        except Exception as exc:
            supervisor = {
                "component": "NativeProcessSensorSupervisor",
                "status": "DEGRADED",
                "error": type(exc).__name__,
            }

        supervisor_status = str(supervisor.get("status", "UNKNOWN")).upper()
        if self.last_sample_time is None:
            status = "STARTING" if supervisor_status in {"NOT_STARTED", "STARTING"} else supervisor_status
        elif self.last_error is not None:
            status = "DEGRADED"
        elif supervisor_status != "HEALTHY":
            status = "DEGRADED"
        else:
            status = "HEALTHY"

        age = None
        if self.last_sample_time is not None:
            age = round(max(0.0, time.time() - self.last_sample_time), 3)

        return {
            "component": "RustProcessCanary",
            "version": self.VERSION,
            "sensor_version": self.SENSOR_VERSION,
            "status": status,
            "mode": self.MODE,
            "authoritative": False,
            "authoritative_sensor": "ProcessSensor",
            "candidate_sensor": "RustProcessSensor",
            "promotion_bound": False,
            "authority_note": (
                "Canary evidence is observational only and is not accepted as "
                "Rust-primary authority evidence in this release."
            ),
            "binary_trusted": self.binary_trusted,
            "binary_sha256": self.binary_sha256,
            "expected_sha256": self.expected_sha256,
            "sample_count": self.sample_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "last_error": self.last_error,
            "last_sample_time": self.last_sample_time,
            "last_sample_age_seconds": age,
            "last_sample_latency_ms": self.last_sample_latency_ms,
            "candidate_ready": self.last_candidate_ready,
            "readiness_reason": self.last_readiness_reason,
            "min_field_coverage": self.min_field_coverage,
            "supervisor": supervisor,
            "comparison": self.last_comparison,
            "snapshot_summary": self.last_snapshot_summary,
        }

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()

    def close(self) -> None:
        self.supervisor.close()
