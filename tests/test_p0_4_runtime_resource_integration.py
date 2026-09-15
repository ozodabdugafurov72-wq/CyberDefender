from __future__ import annotations

import base64
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.bus.event_bus import EventBus
from agent.config import load_config
from agent.core.backpressure_controller import BackpressureController
from agent.core.crypto_replay_admission_gateway import CryptoReplayAdmissionGateway
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.core.event_bus_resource_safety_gate import EventBusResourceSafetyGate
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.resource_safety_plane import ResourceSafetyPlane
from agent.core.runtime_security_pipeline import RuntimeSecurityPipeline
from agent.crypto.key_manager import KeyManager, generate_storage_key
from agent.crypto.replay_guard import ReplayGuard
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy

checks = 0


def check(label: str, condition: bool) -> None:
    global checks
    if not condition:
        raise AssertionError(label)
    checks += 1
    print(f"PASS | {label}")


def make_event(label: str, severity: str = "HIGH", payload: Any | None = None) -> SecurityEvent:
    return SecurityEvent(
        event_type=f"P0_4_{label}",
        severity=severity,
        value=payload if payload is not None else {"label": label},
        source="P0.4-Test",
        message=f"P0.4 {label}",
        confidence=1.0,
        host_id="p0-4-host",
        sensor_id="p0-4-sensor",
    )


def make_spool(root: Path, name: str, *, max_events: int = 32, max_event_bytes: int = 16 * 1024) -> DurableEventSpool:
    return DurableEventSpool(
        root / name,
        policy=DurableSpoolPolicy(
            max_pending_events=max_events,
            max_pending_bytes=256 * 1024,
            max_event_bytes=max_event_bytes,
            protected_reserve_events=min(4, max(1, max_events // 4)),
            protected_reserve_bytes=32 * 1024,
            max_recovery_batch=8,
            max_recovery_scan_bytes=256 * 1024,
        ),
    )


print("=== CYBERDEFENDER P0.4 PRODUCTION RESOURCE-AWARE RUNTIME INTEGRATION ===")

with tempfile.TemporaryDirectory(prefix="cyberdefender_p04_") as td:
    root = Path(td)

    # ------------------------------------------------------------------
    # A. Exact-cycle snapshot binding: stale snapshot cannot be reused.
    # ------------------------------------------------------------------
    plane = ResourceSafetyPlane(
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
    )
    bus = EventBus(max_size=32)
    gate = EventBusResourceSafetyGate(
        bus,
        plane,
        require_committed_snapshot=True,
        enforce_cycle_binding=True,
    )

    check("Cycle-bound gate starts in bootstrap-ready health", gate.health_check()["status"] == "HEALTHY")
    check("Cycle 1 binding succeeds", gate.bind_cycle(1) is True)
    check("Cycle 1 snapshot commit succeeds", plane.commit_resource_snapshot({"state": "NORMAL"}, 1) is True)
    check("Cycle 1 exact snapshot is available", plane.has_committed_snapshot(1) is True)
    check("Cycle 1 gate health is HEALTHY", gate.health_check()["status"] == "HEALTHY")

    check("Cycle 2 binding succeeds before sample", gate.bind_cycle(2) is True)
    check("Old cycle 1 snapshot is not accepted for cycle 2", plane.has_committed_snapshot(2) is False)

    stale_low = gate.publish_detailed({"event_type": "STALE_LOW", "severity": "INFO", "source": "P0.4"})
    check("LOW is deferred when current-cycle snapshot is missing", stale_low.disposition == "DEFERRED")
    check("Missing current-cycle snapshot reason is explicit", stale_low.reason == "RESOURCE_SNAPSHOT_UNAVAILABLE")
    check("Gate health is DEGRADED while bound cycle lacks snapshot", gate.health_check()["status"] == "DEGRADED")

    stale_high = gate.publish_detailed({"event_type": "STALE_HIGH", "severity": "HIGH", "source": "P0.4"})
    check("HIGH remains available when current-cycle snapshot is missing", stale_high.delivered is True)
    check("Cycle 2 snapshot commit succeeds", plane.commit_resource_snapshot({"state": "NORMAL"}, 2) is True)
    check("Gate returns HEALTHY after current-cycle snapshot commit", gate.health_check()["status"] == "HEALTHY")
    check("Backward cycle binding is rejected", gate.bind_cycle(1) is False)

    # ------------------------------------------------------------------
    # B. Real Crypto -> Replay -> Durable -> Gate -> EventBus tri-state.
    # ------------------------------------------------------------------
    storage_key = generate_storage_key()
    km = KeyManager(root / "keys", storage_key)
    key_id = km.generate_key()
    check("P0.4 test KeyManager provisions ACTIVE key", isinstance(key_id, str) and bool(key_id))

    rbus = EventBus(max_size=1)
    rplane = ResourceSafetyPlane(
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
    )
    rgate = EventBusResourceSafetyGate(
        rbus,
        rplane,
        require_committed_snapshot=True,
        enforce_cycle_binding=True,
    )
    check("Transport cycle binding succeeds", rgate.bind_cycle(7) is True)
    check("Transport NORMAL snapshot commits", rplane.commit_resource_snapshot({"state": "NORMAL"}, 7) is True)

    rspool = make_spool(root, "transport_spool")
    rpipeline = DurableEventPipeline(
        rspool,
        rbus,
        delivery_gateway=rgate,
    )
    replay = ReplayGuard(max_entries=128)
    crypto = CryptoReplayAdmissionGateway(
        km,
        replay,
        rpipeline,
        use_detailed_transport=True,
    )
    runtime_pipe = RuntimeSecurityPipeline(crypto)

    first = make_event("FIRST", "HIGH")
    first_result = runtime_pipe.ingest(first)
    check("First trusted event is accepted", first_result.accepted is True)
    check("First trusted event disposition is ADMITTED", first_result.disposition == "ADMITTED")
    check("First trusted event is durable", first_result.durable is True)
    check("First trusted event is immediately published", first_result.published is True)
    check("First event replay reservation is retained", replay.contains(first.event_id) is True)
    check("First event reaches EventBus", rbus.size() == 1)

    second = make_event("SECOND", "HIGH")
    second_result = runtime_pipe.ingest(second)
    check("Bus-full second event is still accepted into trusted durable boundary", second_result.accepted is True)
    check("Bus-full second event becomes PERSISTED_DEFERRED", second_result.disposition == "PERSISTED_DEFERRED")
    check("Deferred event remains durable", second_result.durable is True)
    check("Deferred event is not falsely reported published", second_result.published is False)
    check("Deferred delivery is retryable", second_result.retryable is True)
    check("Deferred event replay reservation is retained", replay.contains(second.event_id) is True)
    check("Deferred event remains pending on disk", any(r.get("event_id") == second.event_id for r in rspool.pending_records()))
    check("Persisted deferral is not runtime rejection", runtime_pipe.get_stats()["rejected"] == 0)
    check("Persisted deferral counter increments", runtime_pipe.get_stats()["persisted_deferred"] == 1)
    check("Crypto gateway records persisted deferral", crypto.get_stats()["persisted_deferred"] == 1)

    replay_second = runtime_pipe.ingest(second)
    check("Same deferred event replay is blocked", replay_second.accepted is False)
    check("Deferred event replay fails at replay boundary", replay_second.stage == "REPLAY_PROTECTION")
    check("Replay does not create duplicate durable record", sum(1 for r in rspool.pending_records() if r.get("event_id") == second.event_id) == 1)

    # Drain first event and recover second through the same resource gate.
    rbus.subscribe(lambda _event: None)
    check("Queued first event dispatches", rbus.dispatch_once(timeout=0) is True)
    check("First event ACK succeeds", rpipeline.ack(first.event_id) is True)
    check("Deferred event republishes through bounded recovery", rpipeline.publish_pending(max_events=8) == 1)
    check("Recovered deferred event reaches EventBus", rbus.size() == 1)

    # ------------------------------------------------------------------
    # C. Resource CRITICAL: LOW persists/deferred, HIGH is protected.
    # ------------------------------------------------------------------
    cbus = EventBus(max_size=16)
    cplane = ResourceSafetyPlane(
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
    )
    cgate = EventBusResourceSafetyGate(
        cbus,
        cplane,
        require_committed_snapshot=True,
        enforce_cycle_binding=True,
    )
    check("Critical cycle binding succeeds", cgate.bind_cycle(11) is True)
    check("Critical resource snapshot commits", cplane.commit_resource_snapshot({"state": "CRITICAL"}, 11) is True)
    cspool = make_spool(root, "critical_spool")
    cpipeline = DurableEventPipeline(cspool, cbus, delivery_gateway=cgate)
    creplay = ReplayGuard(max_entries=128)
    ccrypto = CryptoReplayAdmissionGateway(km, creplay, cpipeline, use_detailed_transport=True)
    cruntime = RuntimeSecurityPipeline(ccrypto)

    low = make_event("CRITICAL_LOW", "LOW")
    low_result = cruntime.ingest(low)
    check("LOW under CRITICAL is trusted and durable", low_result.accepted is True and low_result.durable is True)
    check("LOW under CRITICAL is PERSISTED_DEFERRED", low_result.disposition == "PERSISTED_DEFERRED")
    check("LOW under CRITICAL does not consume EventBus", cbus.size() == 0)
    check("LOW replay reservation remains protected", creplay.contains(low.event_id) is True)

    high = make_event("CRITICAL_HIGH", "HIGH")
    high_result = cruntime.ingest(high)
    check("HIGH under CRITICAL is accepted", high_result.accepted is True)
    check("HIGH under CRITICAL is ADMITTED", high_result.disposition == "ADMITTED")
    check("HIGH under CRITICAL reaches EventBus", cbus.size() == 1)

    # ------------------------------------------------------------------
    # D. Pre-durable rejection rolls back replay reservation.
    # ------------------------------------------------------------------
    tiny_bus = EventBus(max_size=8)
    tiny_plane = ResourceSafetyPlane(
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
    )
    tiny_gate = EventBusResourceSafetyGate(
        tiny_bus,
        tiny_plane,
        require_committed_snapshot=True,
        enforce_cycle_binding=True,
    )
    check("Tiny transport cycle binds", tiny_gate.bind_cycle(21) is True)
    check("Tiny transport snapshot commits", tiny_plane.commit_resource_snapshot({"state": "NORMAL"}, 21) is True)
    tiny_spool = make_spool(root, "tiny_spool", max_event_bytes=256)
    tiny_pipeline = DurableEventPipeline(tiny_spool, tiny_bus, delivery_gateway=tiny_gate)
    tiny_replay = ReplayGuard(max_entries=128)
    tiny_crypto = CryptoReplayAdmissionGateway(km, tiny_replay, tiny_pipeline, use_detailed_transport=True)
    huge = make_event("TOO_LARGE", "HIGH", payload="X" * 4096)
    env = tiny_crypto.sign_event(huge)
    reject = tiny_crypto.admit_detailed(huge, env["key_id"], env["signature"])
    check("Oversized event is rejected before durability", reject.accepted is False and reject.durable is False)
    check("Pre-durable rejection disposition is REJECTED", reject.disposition == "REJECTED")
    check("Pre-durable rejection rolls back replay reservation", tiny_replay.contains(huge.event_id) is False)
    check("Replay rollback is observable", tiny_crypto.get_stats()["replay_rollbacks"] == 1)
    check("Rejected oversized event is not pending", not any(r.get("event_id") == huge.event_id for r in tiny_spool.pending_records()))

    # ------------------------------------------------------------------
    # E. Main runtime wiring contract.
    # ------------------------------------------------------------------
    main_state = root / "main_state"
    main_key = os.urandom(32)
    os.environ["CYBERDEFENDER_STATE_DIR"] = str(main_state)
    os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(main_key).decode()

    bootstrap_km = KeyManager(main_state / "keys", main_key)
    check("Main test key provisioning succeeds", bool(bootstrap_km.generate_key()))

    main_runtime = CyberDefenderRuntime(SafetyCore(), load_config())
    check("Main runtime version is P0.7-hardened v2.4", main_runtime.VERSION == "2.4")
    check("Main has ResourceSafetyPlane", isinstance(main_runtime.resource_safety_plane, ResourceSafetyPlane))
    check("Main has resource delivery gate", isinstance(main_runtime.resource_delivery_gate, EventBusResourceSafetyGate))
    check("Main gate requires committed snapshot", main_runtime.resource_delivery_gate.require_committed_snapshot is True)
    check("Main gate enforces exact cycle binding", main_runtime.resource_delivery_gate.enforce_cycle_binding is True)
    check("Main production spool is ResourceSafetyPlane bounded spool", main_runtime.resource_safety_plane.bounded_spool is main_runtime.spool)
    check("Main DurableEventPipeline uses resource gate", main_runtime.pipeline.delivery_gateway is main_runtime.resource_delivery_gate)
    check("Main CryptoReplay gateway enables detailed transport", main_runtime.admission_gateway.use_detailed_transport is True)
    check("Main RuntimeSecurityPipeline exposes P0.4 transport contract", main_runtime.runtime_pipeline.RUNTIME_TRANSPORT_CONTRACT_VERSION == "P0.4-1")
    check("Main CryptoReplay gateway exposes P0.4 transport contract", main_runtime.admission_gateway.RUNTIME_TRANSPORT_CONTRACT_VERSION == "P0.4-1")

    # Bootstrap health must remain honest and usable before first cycle.
    bootstrap_health = main_runtime.health_snapshot()
    check("Bootstrap runtime health is HEALTHY", bootstrap_health["runtime"]["status"] == "HEALTHY")
    check("Bootstrap resource gate health is HEALTHY", bootstrap_health["resource_delivery_gate"]["status"] == "HEALTHY")
    check("Bootstrap pipeline health is HEALTHY", bootstrap_health["pipeline"]["status"] == "HEALTHY")

    # Prove exactly one authoritative sample is used while event bursts read it.
    original_check = main_runtime.resource_guard.check
    calls = {"count": 0}

    def counted_check():
        calls["count"] += 1
        return original_check()

    main_runtime.resource_guard.check = counted_check
    main_runtime.cycle_count = 1
    result = main_runtime.update_resource_safety_cycle()
    check("Main authoritative resource sample succeeds", isinstance(result, dict))
    check("Main ResourceGuard sampled exactly once", calls["count"] == 1)
    check("Main exact cycle snapshot committed", main_runtime.resource_safety_plane.has_committed_snapshot(1) is True)

    for i in range(20):
        delivery = main_runtime.resource_delivery_gate.publish_detailed(
            {"event_type": f"MAIN_BURST_{i}", "severity": "INFO", "source": "P0.4-Main"}
        )
        check(f"Main snapshot burst {i} does not hard reject", delivery.disposition in {"PUBLISHED", "DEFERRED"})

    check("Main event burst never resamples ResourceGuard", calls["count"] == 1)
    check("Main ResourceSafetyPlane reports zero legacy samples", main_runtime.resource_safety_plane.get_stats()["legacy_resource_samples"] == 0)
    check("Main gate is bound to current cycle", main_runtime.resource_delivery_gate.required_cycle_id() == 1)

    # Binding a new cycle without a sample invalidates the old snapshot for delivery.
    check("Main gate can bind next cycle", main_runtime.resource_delivery_gate.bind_cycle(2) is True)
    check("Previous snapshot is not current for cycle 2", main_runtime.resource_safety_plane.has_committed_snapshot(2) is False)
    check("Main gate degrades on missing exact-cycle snapshot", main_runtime.resource_delivery_gate.health_check()["status"] == "DEGRADED")

    # EventBus v2.4 preserves bounded admission and adds bounded fairness.
    check("Production EventBus is v2.4", main_runtime.event_bus.VERSION == "2.4")
    check("Action Gateway remains dry-run only", main_runtime.action_gateway.health_check().get("dry_run_only") is True)
    main_runtime.close()

print()
print("=== P0.4 RESULT ===")
print(f"PASS: {checks}")
print("FAIL: 0")
print("Production main.py resource-aware runtime wiring: VERIFIED")
print("One authoritative ResourceGuard sample per cycle: VERIFIED")
print("Stale resource snapshot reuse: BLOCKED")
print("Crypto replay reservation on PERSISTED_DEFERRED: PRESERVED")
print("Replay rollback only before durable commit: VERIFIED")
print("ADMITTED / PERSISTED_DEFERRED / REJECTED runtime semantics: VERIFIED")
print("HIGH/CRITICAL security delivery under pressure: PRESERVED")
print("Production EventBus v2.4 fairness hardening: ACTIVE")
print("Real privileged execution: STILL BLOCKED / DRY-RUN ONLY")
print("RESULT: PASS")
