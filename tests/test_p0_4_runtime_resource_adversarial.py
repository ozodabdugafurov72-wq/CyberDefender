from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path
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


def event(label: str, severity: str = "HIGH") -> SecurityEvent:
    return SecurityEvent(
        event_type=f"P0_4_ADV_{label}",
        severity=severity,
        value={"label": label},
        source="P0.4-Adversarial",
        message=f"P0.4 adversarial {label}",
        confidence=1.0,
        host_id="p0-4-adv-host",
        sensor_id="p0-4-adv-sensor",
    )


def spool(root: Path, name: str) -> DurableEventSpool:
    return DurableEventSpool(
        root / name,
        policy=DurableSpoolPolicy(
            max_pending_events=32,
            max_pending_bytes=256 * 1024,
            max_event_bytes=16 * 1024,
            protected_reserve_events=4,
            protected_reserve_bytes=32 * 1024,
            max_recovery_batch=8,
            max_recovery_scan_bytes=256 * 1024,
        ),
    )


print("=== CYBERDEFENDER P0.4 RESOURCE-AWARE RUNTIME ADVERSARIAL TEST ===")

with tempfile.TemporaryDirectory(prefix="cyberdefender_p04_adv_") as td:
    root = Path(td)

    # ------------------------------------------------------------------
    # A. Unexpected detailed-transport exception: fail closed and keep the
    # replay reservation because durability is unknown.  Do not advertise a
    # retry that the replay boundary would immediately reject.
    # ------------------------------------------------------------------
    storage_key = generate_storage_key()
    km = KeyManager(root / "exception_keys", storage_key)
    check("Exception test KeyManager provisions ACTIVE key", bool(km.generate_key()))

    class ExplodingDetailedPipeline:
        def ingest_detailed(self, _event):
            raise RuntimeError("injected-detailed-transport-failure")

        def ingest(self, _event):
            raise AssertionError("legacy ingest must not be used in P0.4 mode")

        def health_check(self):
            return {"component": "ExplodingDetailedPipeline", "status": "DEGRADED"}

    replay = ReplayGuard(max_entries=64)
    crypto = CryptoReplayAdmissionGateway(
        km,
        replay,
        ExplodingDetailedPipeline(),
        use_detailed_transport=True,
    )
    runtime_pipe = RuntimeSecurityPipeline(crypto)
    uncertain = event("UNCERTAIN", "HIGH")
    uncertain_result = runtime_pipe.ingest(uncertain)

    check("Unexpected detailed transport exception is rejected", uncertain_result.accepted is False)
    check("Unexpected detailed transport exception is fail-closed", uncertain_result.fail_closed is True)
    check("Unexpected detailed transport exception is explicit", uncertain_result.reason == "ADMISSION_EXCEPTION")
    check("Unexpected detailed transport exception reports uncertainty", uncertain_result.durability_uncertain is True)
    check("Uncertain exception retains replay reservation", uncertain_result.replay_reservation_kept is True)
    check("ReplayGuard actually retains uncertain event", replay.contains(uncertain.event_id) is True)
    check("Uncertain exception is not falsely retryable", uncertain_result.retryable is False)
    check("Crypto gateway records degraded uncertainty", crypto.get_stats()["degraded"] >= 1)
    check("Second same-event attempt is stopped by replay boundary", runtime_pipe.ingest(uncertain).stage == "REPLAY_PROTECTION")

    # ------------------------------------------------------------------
    # B. Delivery-boundary exception AFTER durable commit must become
    # PERSISTED_DEFERRED, not a rejection.  Replay reservation stays.
    # ------------------------------------------------------------------
    class RaisingDeliveryGateway:
        def publish_detailed(self, _event):
            raise RuntimeError("injected-delivery-failure")

        def health_check(self):
            return {"component": "RaisingDeliveryGateway", "status": "DEGRADED"}

    delivery_spool = spool(root, "delivery_exception_spool")
    delivery_bus = EventBus(max_size=8)
    delivery_pipeline = DurableEventPipeline(
        delivery_spool,
        delivery_bus,
        delivery_gateway=RaisingDeliveryGateway(),
    )
    delivery_replay = ReplayGuard(max_entries=64)
    delivery_crypto = CryptoReplayAdmissionGateway(
        km,
        delivery_replay,
        delivery_pipeline,
        use_detailed_transport=True,
    )
    delivery_runtime = RuntimeSecurityPipeline(delivery_crypto)
    deferred = event("DELIVERY_EXCEPTION", "HIGH")
    deferred_result = delivery_runtime.ingest(deferred)

    check("Post-durable delivery exception remains accepted", deferred_result.accepted is True)
    check("Post-durable delivery exception is PERSISTED_DEFERRED", deferred_result.disposition == "PERSISTED_DEFERRED")
    check("Post-durable delivery exception remains durable", deferred_result.durable is True)
    check("Post-durable delivery exception is not falsely published", deferred_result.published is False)
    check("Post-durable delivery exception remains retryable by recovery", deferred_result.retryable is True)
    check("Post-durable replay reservation is retained", delivery_replay.contains(deferred.event_id) is True)
    check("Post-durable event remains pending", any(r.get("event_id") == deferred.event_id for r in delivery_spool.pending_records()))
    check("Post-durable deferral is not runtime rejection", delivery_runtime.get_stats()["rejected"] == 0)

    # ------------------------------------------------------------------
    # C. Main current-cycle ResourceGuard failure.  Previous snapshot must
    # not be reused. LOW/MEDIUM defer; HIGH security evidence survives.
    # ------------------------------------------------------------------
    state_dir = root / "main_state"
    main_key = os.urandom(32)
    old_state_dir = os.environ.get("CYBERDEFENDER_STATE_DIR")
    old_storage_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
    os.environ["CYBERDEFENDER_STATE_DIR"] = str(state_dir)
    os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(main_key).decode()
    runtime = None

    try:
        bootstrap = KeyManager(state_dir / "keys", main_key)
        check("Main adversarial KeyManager provisions ACTIVE key", bool(bootstrap.generate_key()))
        runtime = CyberDefenderRuntime(SafetyCore(), load_config())

        runtime.cycle_count = 1
        first_snapshot = runtime.update_resource_safety_cycle()
        check("Main cycle 1 authoritative snapshot succeeds", isinstance(first_snapshot, dict))
        check("Main cycle 1 exact snapshot exists", runtime.resource_safety_plane.has_committed_snapshot(1) is True)

        original_check = runtime.resource_guard.check
        calls = {"count": 0}

        def injected_failure():
            calls["count"] += 1
            raise RuntimeError("injected-resource-sample-failure")

        runtime.resource_guard.check = injected_failure
        runtime.cycle_count = 2
        failed_snapshot = runtime.update_resource_safety_cycle()
        check("Current-cycle ResourceGuard failure is contained", failed_snapshot is None)
        check("Failed cycle attempts exactly one ResourceGuard sample", calls["count"] == 1)
        check("Old cycle snapshot is not current after sample failure", runtime.resource_safety_plane.has_committed_snapshot(2) is False)
        check("Gate remains bound to failed current cycle", runtime.resource_delivery_gate.required_cycle_id() == 2)
        check("Gate health is DEGRADED without current-cycle snapshot", runtime.resource_delivery_gate.health_check()["status"] == "DEGRADED")
        check("Runtime records resource snapshot failure", runtime.resource_snapshot_failures >= 1)
        check("Runtime marks contained resource failure degraded", runtime.degraded is True)

        before_samples = calls["count"]
        low_decision = runtime.resource_delivery_gate.publish_detailed(
            {"event_type": "ADV_LOW", "severity": "LOW", "source": "P0.4-Adversarial"}
        )
        high_decision = runtime.resource_delivery_gate.publish_detailed(
            {"event_type": "ADV_HIGH", "severity": "HIGH", "source": "P0.4-Adversarial"}
        )
        check("LOW defers when current-cycle sample failed", low_decision.disposition == "DEFERRED")
        check("LOW sample-failure reason is explicit", low_decision.reason == "RESOURCE_SNAPSHOT_UNAVAILABLE")
        check("HIGH remains deliverable when current-cycle sample failed", high_decision.delivered is True)
        check("Event decisions never re-sample failed ResourceGuard", calls["count"] == before_samples)

        # Restore real sampler and prove the next monotonic cycle can recover.
        runtime.resource_guard.check = original_check
        runtime.cycle_count = 3
        recovered_snapshot = runtime.update_resource_safety_cycle()
        check("Next cycle can establish a fresh authoritative snapshot", isinstance(recovered_snapshot, dict))
        check("Recovered cycle exact snapshot exists", runtime.resource_safety_plane.has_committed_snapshot(3) is True)
        check("Resource delivery gate returns HEALTHY after fresh snapshot", runtime.resource_delivery_gate.health_check()["status"] == "HEALTHY")
    finally:
        if runtime is not None:
            runtime.close()
        if old_state_dir is None:
            os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
        else:
            os.environ["CYBERDEFENDER_STATE_DIR"] = old_state_dir
        if old_storage_key is None:
            os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
        else:
            os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_storage_key

    # ------------------------------------------------------------------
    # D. Exact-cycle fail-safe under a burst after rebinding.  A previous
    # NORMAL snapshot may never silently reopen LOW delivery in new cycle.
    # ------------------------------------------------------------------
    burst_bus = EventBus(max_size=64)
    burst_plane = ResourceSafetyPlane(
        event_rate_limiter=EventRateLimiter(),
        backpressure_controller=BackpressureController(),
    )
    burst_gate = EventBusResourceSafetyGate(
        burst_bus,
        burst_plane,
        require_committed_snapshot=True,
        enforce_cycle_binding=True,
    )
    check("Burst cycle 100 binds", burst_gate.bind_cycle(100) is True)
    check("Burst cycle 100 NORMAL snapshot commits", burst_plane.commit_resource_snapshot({"state": "NORMAL"}, 100) is True)
    check("Burst cycle 101 rebinds before sample", burst_gate.bind_cycle(101) is True)

    resource_checks_before = burst_plane.get_stats().get("legacy_resource_samples", 0)
    deferred_count = 0
    for index in range(25):
        result = burst_gate.publish_detailed(
            {"event_type": f"BURST_LOW_{index}", "severity": "LOW", "source": "P0.4-Adversarial"}
        )
        if result.disposition == "DEFERRED":
            deferred_count += 1
    resource_checks_after = burst_plane.get_stats().get("legacy_resource_samples", 0)
    check("All LOW events defer while new-cycle snapshot is absent", deferred_count == 25)
    check("Missing-snapshot burst does not advance resource hysteresis", resource_checks_after == resource_checks_before)
    check("Missing-snapshot burst does not consume EventBus", burst_bus.size() == 0)

print("\n=== P0.4 ADVERSARIAL RESULT ===")
print(f"PASS: {checks}")
print("FAIL: 0")
print("Current-cycle sample failure containment: VERIFIED")
print("Stale snapshot reuse after sample failure: BLOCKED")
print("Post-durable delivery exception: PERSISTED_DEFERRED")
print("Unknown durability exception: FAIL-CLOSED + REPLAY RESERVATION RETAINED")
print("Event-volume re-sampling after failure: BLOCKED")
print("HIGH security preservation with missing snapshot: VERIFIED")
print("RESULT: PASS")
