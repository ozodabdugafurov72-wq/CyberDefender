from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
from unittest.mock import patch
import time
from typing import Any

from agent.sensors.rust_process_canary import RustProcessCanary, RustProcessCanaryError


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def rust_snapshot() -> dict[str, Any]:
    now = time.time()
    return {
        "schema": "cd.process.v5",
        "sensor": "RustProcessSensor",
        "version": "0.5.1",
        "timestamp": now,
        "partial": True,
        "skipped": 1,
        "process_count": 1,
        "ipc": {
            "protocol": "cd.sensor.ipc.v1", "version": 1, "sequence": 2,
            "sensor_epoch": "epoch-test", "supervisor_pid": 1000, "sensor_pid": 1001,
        },
        "enrichment_provenance": {},
        "processes": [{
            "pid": 321, "ppid": 4, "name": "probe.exe", "create_time": 12345.125,
            "creation_filetime": "0", "exe": r"C:\\probe.exe", "username": "DOMAIN\\user",
            "cmdline": [r"C:\\probe.exe", "--probe"], "sid": "S-1-5-21-1",
            "session_id": 1, "integrity_level": "MEDIUM", "cpu_percent": None,
            "memory_percent": None,
            "enrichment_status": {
                "exe": {"status": "COLLECTED"}, "username": {"status": "COLLECTED"},
                "cmdline": {"status": "COLLECTED"}, "sid": {"status": "COLLECTED"},
                "session_id": {"status": "COLLECTED"}, "integrity_level": {"status": "COLLECTED"},
                "cpu_percent": {"status": "NOT_COLLECTED_V05_CORE"},
                "memory_percent": {"status": "NOT_COLLECTED_V05_CORE"},
            },
        }],
        "skipped_processes": [{"pid": 0, "reason": "SYSTEM_IDLE_UNQUERYABLE", "win32_error": 87}],
    }


def python_snapshot() -> dict[str, Any]:
    row = rust_snapshot()["processes"][0]
    return {
        "sensor": "ProcessSensor", "version": "1.0", "timestamp": time.time(),
        "process_count": 1,
        "processes": [{
            "pid": row["pid"], "ppid": row["ppid"], "name": row["name"],
            "exe": row["exe"], "username": row["username"], "cmdline": list(row["cmdline"]),
            "create_time": row["create_time"], "cpu_percent": 0.0, "memory_percent": 0.0,
        }],
    }


class FakeSupervisor:
    def __init__(self, _path: Path, **_kwargs: Any) -> None:
        self.closed = False
        self.calls = 0
        self.fail = False
        self.snapshot_override: dict[str, Any] | None = None

    def snapshot(self) -> dict[str, Any]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic native failure")
        if self.snapshot_override is not None:
            return self.snapshot_override
        return rust_snapshot()

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "NativeProcessSensorSupervisor", "version": "test",
            "status": "HEALTHY" if not self.fail else "DEGRADED",
            "protocol": "cd.sensor.ipc.v1", "generation": 1, "sequence": self.calls,
            "sensor_epoch": "epoch-test", "sensor_pid": 1001, "child_pid": 1001,
            "supervisor_pid": 1000, "launch_binding_verified": True,
            "direct_pid_verified": True, "child_alive": True, "restart_count": 0,
            "failures": 0, "last_error": None,
        }

    def close(self) -> None:
        self.closed = True


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_canary_") as td:
        exe = Path(td) / "sensor.exe"
        exe.write_bytes(b"exact-canary-binary")
        digest = hashlib.sha256(exe.read_bytes()).hexdigest()

        canary = RustProcessCanary(
            exe, digest, min_field_coverage=0.98, supervisor_factory=FakeSupervisor
        )
        result = canary.sample(python_snapshot())
        check(result["authoritative"] is False, "canary result is explicitly non-authoritative")
        check(result["authoritative_sensor"] == "ProcessSensor", "Python remains authoritative in canary result")
        check(result["candidate_ready"] is True, "aligned v0.5.1 evidence passes canary readiness")
        check(result["comparison"]["identity_disagreements"]["count"] == 0, "canary identity parity is exact")
        check(result["comparison"]["parent_disagreements"]["count"] == 0, "canary parent parity is exact")
        check(result["comparison"]["fields"]["exe"]["mismatches"] == 0, "canary executable parity has zero mismatches")

        health = canary.health_check()
        check(health["status"] == "HEALTHY", "canary exposes HEALTHY observability after good sample")
        check(health["promotion_bound"] is False, "canary evidence is not promotion-bound")
        check(health["binary_trusted"] is True, "canary binary pin is verified before use")
        check(health["snapshot_summary"]["extra_enrichment"]["sid"]["coverage_rate"] == 1.0, "native SID coverage is observable")

        # Windows service-account display names may differ by localization or
        # account-resolution context.  The native token SID is the stronger
        # principal evidence and must keep such a display-only variant ready.
        variant = rust_snapshot()
        variant["processes"][0]["username"] = "NT AUTHORITY\\LOCALIZED-SYSTEM"
        variant["processes"][0]["sid"] = "S-1-5-18"
        canary.supervisor.snapshot_override = variant
        py_variant = python_snapshot()
        py_variant["processes"][0]["username"] = "NT AUTHORITY\\SYSTEM"
        with patch(
            "agent.sensors.rust_process_v05_contract._resolve_windows_username_sid",
            return_value="S-1-5-18",
        ):
            result = canary.sample(py_variant)
        user_stats = result["comparison"]["fields"]["username"]
        check(result["candidate_ready"] is True, "SID-backed username display variant remains canary-ready")
        check(user_stats["mismatches"] == 0, "SID-backed username display variant is not a hard mismatch")
        check(user_stats["sid_backed_display_variants"] == 1, "SID-backed username display variant is observable")

        # Without valid collected SID evidence, the exact same username
        # divergence remains fail-closed.
        no_sid = rust_snapshot()
        no_sid["processes"][0]["username"] = "OTHER\\user"
        no_sid["processes"][0]["sid"] = None
        no_sid["processes"][0]["enrichment_status"]["sid"] = {"status": "QUERY_FAILED"}
        canary.supervisor.snapshot_override = no_sid
        result = canary.sample(python_snapshot())
        check(result["candidate_ready"] is False, "username divergence without SID remains blocked")
        check(result["readiness_reason"] == "USERNAME_PARITY_MISMATCH", "username hard mismatch reason remains explicit")

        canary.supervisor.snapshot_override = None
        canary.supervisor.fail = True
        try:
            canary.sample(python_snapshot())
        except RustProcessCanaryError:
            pass
        else:
            raise AssertionError("native canary failure was not isolated")
        check(canary.failure_count == 1, "native canary failure is counted")
        check(canary.health_check()["status"] == "DEGRADED", "canary failure degrades canary health only")

        canary.close()
        check(canary.supervisor.closed is True, "canary closes its persistent supervisor")

        try:
            RustProcessCanary(exe, "0" * 64, supervisor_factory=FakeSupervisor)
        except RustProcessCanaryError as exc:
            check(str(exc) == "RUST_CANARY_BINARY_HASH_MISMATCH", "binary substitution fails closed")
        else:
            raise AssertionError("wrong binary hash was accepted")

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
