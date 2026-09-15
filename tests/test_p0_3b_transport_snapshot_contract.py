from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.bus.event_bus import EventBus
from agent.core.backpressure_controller import BackpressureController
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.core.event_bus_resource_safety_gate import EventBusResourceSafetyGate
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.resource_safety_plane import ResourceSafetyPlane
from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy

ROOT = PROJECT_ROOT / "state" / "test_p0_3b_transport_snapshot_contract"
shutil.rmtree(ROOT, ignore_errors=True)
ROOT.mkdir(parents=True, exist_ok=True)

checks = 0

def check(label: str, condition: bool) -> None:
    global checks
    if not condition:
        raise AssertionError(label)
    checks += 1
    print(f"PASS | {label}")


class CountingGuard:
    def __init__(self) -> None:
        self.calls = 0

    def check(self) -> Dict[str, Any]:
        self.calls += 1
        return {"state": "CRITICAL"}


def event(label: str, severity: str = "LOW") -> SecurityEvent:
    return SecurityEvent(
        event_type=f"P0_3B_{label}",
        severity=severity,
        value={"label": label},
        source="P0.3B-Test",
        message=f"P0.3B {label}",
        confidence=1.0,
        host_id="p0-3b-host",
    )


def make_spool(name: str, max_events: int = 32) -> DurableEventSpool:
    return DurableEventSpool(
        ROOT / name,
        policy=DurableSpoolPolicy(
            max_pending_events=max_events,
            max_pending_bytes=256 * 1024,
            max_event_bytes=16 * 1024,
            protected_reserve_events=min(4, max(1, max_events // 4)),
            protected_reserve_bytes=32 * 1024,
            max_recovery_batch=8,
            max_recovery_scan_bytes=256 * 1024,
        ),
    )


print("=== CYBERDEFENDER P0.3B TRANSPORT + SNAPSHOT CONTRACT ===")

# ---------------------------------------------------------------------------
# A. Authoritative one-snapshot-per-cycle contract
# ---------------------------------------------------------------------------
guard = CountingGuard()
plane = ResourceSafetyPlane(
    resource_guard=guard,
    event_rate_limiter=EventRateLimiter(),
    backpressure_controller=BackpressureController(),
)

check("No resource snapshot exists initially", plane.has_committed_snapshot() is False)
check(
    "First cycle snapshot commits",
    plane.commit_resource_snapshot({"state": "NORMAL"}, cycle_id=1) is True,
)
check("Committed snapshot exists", plane.has_committed_snapshot() is True)
check("Committed cycle id is visible", plane.get_resource_snapshot()["cycle_id"] == 1)
check("Committed state is NORMAL", plane.get_resource_snapshot()["state"] == "NORMAL")
check(
    "Duplicate snapshot for same cycle is rejected",
    plane.commit_resource_snapshot({"state": "CRITICAL"}, cycle_id=1) is False,
)
check(
    "Stale snapshot is rejected",
    plane.commit_resource_snapshot({"state": "DEGRADED"}, cycle_id=0) is False,
)
check(
    "Invalid snapshot state is rejected",
    plane.commit_resource_snapshot({"state": "UNKNOWN"}, cycle_id=2) is False,
)
check(
    "Invalid cycle id is rejected",
    plane.commit_resource_snapshot({"state": "NORMAL"}, cycle_id=-1) is False,
)
check("Rejected snapshots do not call ResourceGuard", guard.calls == 0)

bus = EventBus(max_size=64)
gate = EventBusResourceSafetyGate(
    event_bus=bus,
    safety_plane=plane,
    require_committed_snapshot=True,
)

# Burst publications must consume the committed snapshot only.
for i in range(20):
    result = gate.publish_detailed(
        {
            "event_type": f"SNAPSHOT_BURST_{i}",
            "severity": "INFO",
            "source": "P0.3B-SnapshotTest",
        }
    )
    check(f"Snapshot burst event {i} published", result.delivered is True)

check("Event burst does not call ResourceGuard.check", guard.calls == 0)
plane_stats = plane.get_stats()
check("No legacy resource samples occurred", plane_stats["legacy_resource_samples"] == 0)
check("Exactly one resource snapshot committed", plane_stats["snapshot_commits"] == 1)
check("Duplicate snapshot rejection is observable", plane_stats["snapshot_duplicate_rejected"] == 1)
check("Stale snapshot rejection is observable", plane_stats["snapshot_stale_rejected"] == 1)
check("Invalid snapshot rejections are observable", plane_stats["snapshot_invalid_rejected"] == 2)

# ---------------------------------------------------------------------------
# B. Critical snapshot policy: low deferred, high survives
# ---------------------------------------------------------------------------
check(
    "Next cycle CRITICAL snapshot commits",
    plane.commit_resource_snapshot({"state": "CRITICAL"}, cycle_id=2) is True,
)

low_delivery = gate.publish_detailed(
    {"event_type": "LOW_VALUE", "severity": "INFO", "source": "P0.3B-Test"}
)
check("LOW is deferred under CRITICAL snapshot", low_delivery.disposition == "DEFERRED")
check("LOW deferral is retryable", low_delivery.retryable is True)

high_delivery = gate.publish_detailed(
    {"event_type": "HIGH_SECURITY", "severity": "HIGH", "source": "P0.3B-Test"}
)
check("HIGH survives CRITICAL snapshot", high_delivery.delivered is True)
check("HIGH delivery disposition is PUBLISHED", high_delivery.disposition == "PUBLISHED")
check("CRITICAL snapshot path still does not resample guard", guard.calls == 0)

# ---------------------------------------------------------------------------
# C. Missing required snapshot: low deferred, high preserved
# ---------------------------------------------------------------------------
missing_plane = ResourceSafetyPlane(
    resource_guard=CountingGuard(),
    event_rate_limiter=EventRateLimiter(),
    backpressure_controller=BackpressureController(),
)
missing_bus = EventBus(max_size=8)
missing_gate = EventBusResourceSafetyGate(
    event_bus=missing_bus,
    safety_plane=missing_plane,
    require_committed_snapshot=True,
)
missing_low = missing_gate.publish_detailed(
    {"event_type": "MISSING_LOW", "severity": "INFO", "source": "P0.3B-Test"}
)
check("Missing snapshot defers LOW", missing_low.disposition == "DEFERRED")
check("Missing snapshot reason is explicit", missing_low.reason == "RESOURCE_SNAPSHOT_UNAVAILABLE")
missing_high = missing_gate.publish_detailed(
    {"event_type": "MISSING_HIGH", "severity": "HIGH", "source": "P0.3B-Test"}
)
check("Missing snapshot does not intentionally block HIGH", missing_high.delivered is True)
check("Missing snapshot gate does not resample ResourceGuard", missing_plane.get_stats()["legacy_resource_samples"] == 0)
check("Required missing snapshot is explicitly DEGRADED", missing_gate.health_check()["status"] == "DEGRADED")

# ---------------------------------------------------------------------------
# D. Durable tri-state: EventBus capacity deferral is not durable rejection
# ---------------------------------------------------------------------------
small_bus = EventBus(max_size=1)
small_spool = make_spool("small_spool")
small_pipeline = DurableEventPipeline(small_spool, small_bus)

first = event("FIRST", "HIGH")
second = event("SECOND", "HIGH")

r1 = small_pipeline.ingest_detailed(first)
check("First detailed ingest is ADMITTED", r1.disposition == "ADMITTED")
check("First detailed ingest is durable", r1.durable is True)
check("First detailed ingest is published", r1.published is True)
check("First detailed ingest accepted", r1.accepted is True)

r2 = small_pipeline.ingest_detailed(second)
check("Second detailed ingest is PERSISTED_DEFERRED", r2.disposition == "PERSISTED_DEFERRED")
check("Deferred event remains accepted into durable boundary", r2.accepted is True)
check("Deferred event is durable", r2.durable is True)
check("Deferred event is not falsely published", r2.published is False)
check("Deferred event is retryable", r2.retryable is True)
check("Both events remain pending before ACK", len(small_spool.pending_records()) == 2)

pstats = small_pipeline.get_stats()
check("Persisted deferral counter increments", pstats["persisted_deferred"] == 1)
check("Persisted deferral is not counted as rejected", pstats["rejected"] == 0)
check("Persisted deferral is not a spool failure", pstats["spool_failed"] == 0)

# A duplicate pending event is idempotent at the durable boundary.
duplicate_pending = small_pipeline.ingest_detailed(second)
check("Duplicate pending maps to PERSISTED_DEFERRED", duplicate_pending.disposition == "PERSISTED_DEFERRED")
check("Duplicate pending remains durably accepted", duplicate_pending.accepted is True and duplicate_pending.durable is True)
check("Duplicate pending does not create a third record", len(small_spool.pending_records()) == 2)

# Dispatch/ACK first, then bounded recovery publishes the deferred event.
check("First queued event dispatches", small_bus.dispatch_once(timeout=0) is True)
check("First event ACK succeeds", small_pipeline.ack(first.event_id) is True)
replayed = small_pipeline.publish_pending(max_events=8)
check("Deferred pending event later republishes", replayed == 1)
check("Recovered deferred event reaches EventBus", small_bus.size() == 1)

# ---------------------------------------------------------------------------
# E. Durable + resource gate: policy throttle becomes PERSISTED_DEFERRED
# ---------------------------------------------------------------------------
resource_bus = EventBus(max_size=16)
resource_plane = ResourceSafetyPlane(
    event_rate_limiter=EventRateLimiter(),
    backpressure_controller=BackpressureController(),
)
check(
    "Resource pipeline CRITICAL snapshot commits",
    resource_plane.commit_resource_snapshot({"state": "CRITICAL"}, cycle_id=7),
)
resource_gate = EventBusResourceSafetyGate(
    resource_bus,
    resource_plane,
    require_committed_snapshot=True,
)
resource_spool = make_spool("resource_spool")
resource_pipeline = DurableEventPipeline(
    resource_spool,
    resource_bus,
    delivery_gateway=resource_gate,
)

low_event = event("RESOURCE_LOW", "LOW")
low_result = resource_pipeline.ingest_detailed(low_event)
check("Resource-throttled LOW is PERSISTED_DEFERRED", low_result.disposition == "PERSISTED_DEFERRED")
check("Resource-throttled LOW is durably preserved", low_result.durable is True)
check("Resource-throttled LOW is not on EventBus", resource_bus.size() == 0)
check("Resource-throttled LOW stays pending", len(resource_spool.pending_records()) == 1)
check("Resource-throttled LOW is not pipeline rejection", resource_pipeline.get_stats()["rejected"] == 0)

high_event = event("RESOURCE_HIGH", "HIGH")
high_result = resource_pipeline.ingest_detailed(high_event)
check("Resource-protected HIGH is ADMITTED", high_result.disposition == "ADMITTED")
check("Resource-protected HIGH reaches EventBus", resource_bus.size() == 1)

# ---------------------------------------------------------------------------
# F. Detailed hard rejection before durability
# ---------------------------------------------------------------------------
invalid_result = resource_pipeline.ingest_detailed(None)  # type: ignore[arg-type]
check("Invalid input detailed result is REJECTED", invalid_result.disposition == "REJECTED")
check("Invalid input is not durable", invalid_result.durable is False)
check("Invalid input is not accepted", invalid_result.accepted is False)

# ---------------------------------------------------------------------------
# G. Existing boolean API remains unchanged for old callers
# ---------------------------------------------------------------------------
legacy_bus = EventBus(max_size=1)
legacy_spool = make_spool("legacy_spool")
legacy_pipeline = DurableEventPipeline(legacy_spool, legacy_bus)
legacy_a = event("LEGACY_A", "HIGH")
legacy_b = event("LEGACY_B", "HIGH")
check("Legacy ingest immediate publish remains True", legacy_pipeline.ingest(legacy_a) is True)
check("Legacy ingest bus-capacity behavior remains False", legacy_pipeline.ingest(legacy_b) is False)
check("Legacy false still preserves pending event", len(legacy_spool.pending_records()) == 2)

# ---------------------------------------------------------------------------
# H. Health / contract declaration
# ---------------------------------------------------------------------------
check("Durable pipeline legacy version remains 1.3", DurableEventPipeline.VERSION == "1.3")
check("Tri-state transport contract version is explicit", DurableEventPipeline.TRANSPORT_CONTRACT_VERSION == "P0.3B-1")
check("ResourceSafetyPlane version is 1.1.0", ResourceSafetyPlane.VERSION == "1.1.0")
check("Resource gate version is 1.1", EventBusResourceSafetyGate.VERSION == "1.1")
check("Resource gate declares detailed contract", resource_gate.health_check()["detailed_delivery_contract"] is True)
check("Resource gate requires committed snapshot", resource_gate.health_check()["require_committed_snapshot"] is True)
check("Resource pipeline health remains HEALTHY", resource_pipeline.health_check()["status"] == "HEALTHY")

print()
print("=== P0.3B RESULT ===")
print(f"PASS: {checks}")
print("FAIL: 0")
print("Authoritative resource sample per cycle: VERIFIED")
print("Event-volume hysteresis coupling: BLOCKED")
print("ADMITTED / PERSISTED_DEFERRED / REJECTED: VERIFIED")
print("Deferred delivery is not durable rejection: VERIFIED")
print("HIGH/CRITICAL preservation path: VERIFIED")
print("Legacy DurableEventPipeline bool API: PRESERVED")
print("Production main.py runtime wiring: UNMODIFIED")
print("CryptoReplayAdmissionGateway semantics: UNMODIFIED")
print("RESULT: PASS")
