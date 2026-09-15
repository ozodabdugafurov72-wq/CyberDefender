from __future__ import annotations

from agent.sensors.process_authority import (
    ProcessSensorAuthorityController,
    ProcessSensorMode,
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def rust_snapshot(*, reason: str = "SYSTEM_IDLE_UNQUERYABLE") -> dict:
    return {
        "schema": "cd.process.v4",
        "sensor": "RustProcessSensor",
        "version": "0.4.0",
        "timestamp": 1_800_000_000.0,
        "partial": True,
        "skipped": 1,
        "process_count": 1,
        "processes": [
            {
                "pid": 100,
                "ppid": 4,
                "name": "proc.exe",
                "exe": None,
                "username": None,
                "cmdline": None,
                "create_time": 1000.0,
                "creation_filetime": "116444746000000000",
                "cpu_percent": None,
                "memory_percent": None,
            }
        ],
        "skipped_processes": [
            {
                "pid": 0 if reason == "SYSTEM_IDLE_UNQUERYABLE" else 200,
                "reason": reason,
                "win32_error": 87 if reason == "SYSTEM_IDLE_UNQUERYABLE" else 5,
            }
        ],
    }


def comparison() -> dict:
    return {
        "mode": "SHADOW_ONLY",
        "authoritative_sensor": "ProcessSensor",
        "shadow_sensor": "RustProcessSensor",
        "verdict": "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
        "python_process_count": 2,
        "rust_process_count": 1,
        "common_processes": 1,
        "exact_graph_identity_matches": 1,
        "identity_disagreements": {"count": 0, "examples": []},
        "parent_disagreements": {"count": 0, "examples": []},
    }


def healthy_probe() -> dict:
    return {
        "component": "RustProcessShadowProbe",
        "status": "HEALTHY",
        "mode": "SHADOW_ONLY",
    }


def eligible_evidence(
    controller: ProcessSensorAuthorityController,
    *,
    now: float = 100.0,
):
    snap = rust_snapshot()
    # Two healthy native observations satisfy the bounded health streak.
    controller.assess_rust_evidence(
        rust_snapshot=snap,
        comparison=comparison(),
        probe_health=healthy_probe(),
        binary_sha256=controller.PINNED_RUST_V04_SHA256,
        transport_validated=True,
        now_monotonic=now,
    )
    return controller.assess_rust_evidence(
        rust_snapshot=snap,
        comparison=comparison(),
        probe_health=healthy_probe(),
        binary_sha256=controller.PINNED_RUST_V04_SHA256,
        transport_validated=True,
        now_monotonic=now + 1.0,
    )


def main() -> int:
    invalid = ProcessSensorAuthorityController(mode="surprise-primary")
    check(
        invalid.mode == ProcessSensorMode.PYTHON_ONLY,
        "invalid authority mode fails safe to PYTHON_ONLY",
    )
    check(
        invalid.config_error == "INVALID_PROCESS_SENSOR_MODE",
        "invalid authority configuration remains observable",
    )

    python_only = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.PYTHON_ONLY,
    )
    d = python_only.decide(python_snapshot={"sensor": "ProcessSensor"})
    check(
        d.authoritative_sensor == "ProcessSensor" and d.may_ingest,
        "PYTHON_ONLY selects Python while healthy",
    )
    python_only.decide(python_snapshot=None)
    d = python_only.decide(python_snapshot=None)
    check(
        d.authoritative_sensor is None and d.reason == "RUST_DISABLED",
        "PYTHON_ONLY confirmed failure fails closed",
    )

    shadow = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_SHADOW,
    )
    ev = eligible_evidence(shadow)
    check(ev.eligible, "known PID0-only Rust evidence becomes eligible")
    shadow.decide(python_snapshot={"sensor": "ProcessSensor"})
    shadow.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    d = shadow.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    check(
        d.authoritative_sensor is None
        and d.reason == "RUST_SHADOW_NON_AUTHORITATIVE",
        "RUST_SHADOW can never become authoritative",
    )

    canary = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_CANARY,
    )
    ev = eligible_evidence(canary)
    canary.decide(python_snapshot={"sensor": "ProcessSensor"})
    canary.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    d = canary.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    check(
        d.authoritative_sensor is None
        and d.would_select_sensor == "RustProcessSensor"
        and d.disposition == "CANARY_NO_AUTHORITY_SWITCH",
        "RUST_CANARY computes failover readiness without switching authority",
    )

    locked = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK,
        primary_unlock_token=(
            ProcessSensorAuthorityController.PRIMARY_UNLOCK_TOKEN
        ),
        compiled_primary_enabled=False,
    )
    ev = eligible_evidence(locked)
    locked.decide(python_snapshot={"sensor": "ProcessSensor"})
    locked.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    d = locked.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    check(
        d.authoritative_sensor is None
        and d.reason == "RUST_PRIMARY_COMPILED_LOCKED",
        "environment unlock cannot bypass compiled primary lock",
    )

    # Future release state-machine proof in isolation only.
    future = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK,
        primary_unlock_token=(
            ProcessSensorAuthorityController.PRIMARY_UNLOCK_TOKEN
        ),
        compiled_primary_enabled=True,
    )
    ev = eligible_evidence(future)
    check(
        future.decide(
            python_snapshot={"sensor": "ProcessSensor"},
            rust_snapshot=rust_snapshot(),
            rust_evidence=ev,
        ).authoritative_sensor == "ProcessSensor",
        "future mode still prefers healthy Python",
    )
    first = future.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    check(
        first.disposition == "HOLD_LAST_GRAPH_STATE",
        "one Python failure cannot flip authority",
    )
    second = future.decide(
        python_snapshot=None,
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    check(
        second.authoritative_sensor == "RustProcessSensor",
        "future compiled mode requires confirmed Python loss before failover",
    )
    r1 = future.decide(
        python_snapshot={"sensor": "ProcessSensor"},
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    check(
        r1.authoritative_sensor == "RustProcessSensor",
        "one Python recovery sample cannot flap authority back",
    )
    r2 = future.decide(
        python_snapshot={"sensor": "ProcessSensor"},
        rust_snapshot=rust_snapshot(),
        rust_evidence=ev,
    )
    check(
        r2.authoritative_sensor == "ProcessSensor"
        and r2.disposition == "PYTHON_FAILBACK_AUTHORITATIVE",
        "confirmed Python recovery performs bounded failback",
    )

    # Fresh alignment becomes a bounded lease and can be reused briefly while
    # Python is unavailable, but not indefinitely.
    lease = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_CANARY,
        rust_healthy_threshold=1,
        max_alignment_age_seconds=30.0,
    )
    fresh = lease.assess_rust_evidence(
        rust_snapshot=rust_snapshot(),
        comparison=comparison(),
        probe_health=healthy_probe(),
        binary_sha256=lease.PINNED_RUST_V04_SHA256,
        transport_validated=True,
        now_monotonic=100.0,
    )
    check(fresh.eligible, "fresh parity establishes Rust alignment lease")
    reused = lease.assess_rust_evidence(
        rust_snapshot=rust_snapshot(),
        comparison=None,
        probe_health=healthy_probe(),
        binary_sha256=lease.PINNED_RUST_V04_SHA256,
        transport_validated=True,
        now_monotonic=110.0,
    )
    check(
        reused.eligible and reused.alignment_age_seconds == 10.0,
        "recent parity lease survives temporary Python unavailability",
    )
    stale = lease.assess_rust_evidence(
        rust_snapshot=rust_snapshot(),
        comparison=None,
        probe_health=healthy_probe(),
        binary_sha256=lease.PINNED_RUST_V04_SHA256,
        transport_validated=True,
        now_monotonic=131.0,
    )
    check(
        not stale.eligible and stale.reason == "RUST_ALIGNMENT_STALE",
        "stale parity lease blocks Rust authority",
    )

    unsafe_skip = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_CANARY,
        rust_healthy_threshold=1,
    )
    ev_bad_skip = unsafe_skip.assess_rust_evidence(
        rust_snapshot=rust_snapshot(reason="OPEN_ACCESS_DENIED"),
        comparison=comparison(),
        probe_health=healthy_probe(),
        binary_sha256=unsafe_skip.PINNED_RUST_V04_SHA256,
        transport_validated=True,
        now_monotonic=100.0,
    )
    check(
        not ev_bad_skip.eligible
        and ev_bad_skip.reason == "RUST_SKIP_SCOPE_NOT_AUTO_ELIGIBLE",
        "automatic failover rejects broader AccessDenied coverage loss",
    )

    unvalidated = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_CANARY,
        rust_healthy_threshold=1,
    ).assess_rust_evidence(
        rust_snapshot=rust_snapshot(),
        comparison=comparison(),
        probe_health=healthy_probe(),
        binary_sha256=(
            ProcessSensorAuthorityController.PINNED_RUST_V04_SHA256
        ),
        transport_validated=False,
        now_monotonic=100.0,
    )
    check(
        not unvalidated.eligible
        and unvalidated.reason == "RUST_SNAPSHOT_UNVALIDATED",
        "schema-looking snapshot cannot bypass validated transport boundary",
    )

    bad_hash = ProcessSensorAuthorityController(
        mode=ProcessSensorMode.RUST_CANARY,
        rust_healthy_threshold=1,
    ).assess_rust_evidence(
        rust_snapshot=rust_snapshot(),
        comparison=comparison(),
        probe_health=healthy_probe(),
        binary_sha256="0" * 64,
        transport_validated=True,
        now_monotonic=100.0,
    )
    check(
        not bad_hash.eligible and bad_hash.reason == "RUST_BINARY_UNTRUSTED",
        "unpinned Rust binary is never authority-eligible",
    )

    health = locked.health_check()
    check(
        health["status"] == "LOCKED"
        and health["compiled_primary_enabled"] is False,
        "health surface exposes compiled promotion lock",
    )

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
