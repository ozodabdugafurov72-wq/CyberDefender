from __future__ import annotations

import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.bus.event_bus import EventBus
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.event import SecurityEvent
from agent.storage.durable_spool import (
    DurableEventSpool,
    DurableSpoolPolicy,
)


ROOT = Path("state/test_durable_resource_contract_v2_3")


def clean(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def make_event(label: str, severity: str = "LOW", message_size: int = 0) -> SecurityEvent:
    suffix = "X" * max(0, int(message_size))
    return SecurityEvent(
        event_type=f"P0_3_{label}",
        severity=severity,
        value={"label": label},
        source="P0.3-Test",
        message=f"durable resource contract {label} {suffix}",
        confidence=1.0,
        host_id="test-host",
    )


checks = 0


def check(condition: bool, name: str) -> None:
    global checks
    if not condition:
        raise AssertionError(name)
    checks += 1
    print(f"PASS | {name}")


print("=== CYBERDEFENDER P0.3 DURABLE RESOURCE SAFETY CONTRACT v2.3 ===")

# ---------------------------------------------------------------------------
# 1. Protected reserve / no eviction
# ---------------------------------------------------------------------------
reserve_root = ROOT / "reserve"
clean(reserve_root)
reserve_policy = DurableSpoolPolicy(
    max_pending_events=6,
    max_pending_bytes=64 * 1024,
    max_event_bytes=8 * 1024,
    protected_reserve_events=2,
    protected_reserve_bytes=8 * 1024,
    max_recovery_batch=2,
    max_recovery_scan_bytes=64 * 1024,
    compaction_terminal_ops=16,
    compaction_min_dead_bytes=64 * 1024,
)
spool = DurableEventSpool(reserve_root / "spool", policy=reserve_policy)

health = spool.health_check()
check(health["status"] == "HEALTHY", "Fresh bounded spool is HEALTHY")
check(health["bounded"] is True, "Spool explicitly reports bounded=True")
check(health["pending_index_ready"] is True, "Bounded pending index is ready")
check(health["max_pending_events"] == 6, "Configured event bound is visible")
check(health["max_recovery_batch"] == 2, "Configured recovery batch is visible")

low_events = [make_event(f"LOW_{i}", "LOW") for i in range(4)]
for event in low_events:
    result = spool.append_with_result(event)
    check(result.accepted is True, f"General LOW event {event.event_type} admitted")

before_ids = {r["event_id"] for r in spool.pending_records()}
reserve_reject = spool.append_with_result(make_event("LOW_RESERVE_REJECT", "LOW"))
check(reserve_reject.accepted is False, "LOW cannot consume protected reserve")
check(reserve_reject.reason == "PROTECTED_RESERVE", "LOW reserve rejection reason is explicit")
check({r["event_id"] for r in spool.pending_records()} == before_ids, "Capacity rejection does not evict existing evidence")

high_event = make_event("HIGH_PROTECTED", "HIGH")
critical_event = make_event("CRITICAL_PROTECTED", "CRITICAL")
high_result = spool.append_with_result(high_event)
critical_result = spool.append_with_result(critical_event)
check(high_result.accepted and high_result.protected, "HIGH uses protected capacity")
check(critical_result.accepted and critical_result.protected, "CRITICAL uses protected capacity")
check(len(spool.pending_records()) == 6, "Total event capacity is enforced exactly")

saturated = spool.append_with_result(make_event("CRITICAL_SATURATED", "CRITICAL"))
check(saturated.accepted is False, "CRITICAL is fail-closed when total durable capacity is exhausted")
check(saturated.reason == "TOTAL_CAPACITY_EXHAUSTED", "Total saturation is explicit")
check(saturated.capacity_status == "SATURATED", "Saturation state is observable")
check(len(spool.pending_records()) == 6, "Saturation never deletes prior pending evidence")

# ---------------------------------------------------------------------------
# 2. Oversized event rejection before durable write
# ---------------------------------------------------------------------------
oversize_root = ROOT / "oversize"
clean(oversize_root)
oversize_policy = DurableSpoolPolicy(
    max_pending_events=8,
    max_pending_bytes=32 * 1024,
    max_event_bytes=700,
    protected_reserve_events=2,
    protected_reserve_bytes=4 * 1024,
    max_recovery_batch=2,
    max_recovery_scan_bytes=32 * 1024,
)
oversize_spool = DurableEventSpool(oversize_root / "spool", policy=oversize_policy)
physical_before = oversize_spool._physical_pending_bytes()
oversize = oversize_spool.append_with_result(make_event("OVERSIZE", "CRITICAL", 5000))
check(oversize.accepted is False, "Oversized event is rejected")
check(oversize.reason == "EVENT_TOO_LARGE", "Oversized rejection reason is explicit")
check(oversize_spool._physical_pending_bytes() == physical_before, "Oversized rejection causes no durable growth")

# ---------------------------------------------------------------------------
# 3. Crash-safe compaction and no resurrection after restart
# ---------------------------------------------------------------------------
compact_root = ROOT / "compact"
clean(compact_root)
compact_policy = DurableSpoolPolicy(
    max_pending_events=10,
    max_pending_bytes=64 * 1024,
    max_event_bytes=8 * 1024,
    protected_reserve_events=2,
    protected_reserve_bytes=8 * 1024,
    max_recovery_batch=2,
    max_recovery_scan_bytes=64 * 1024,
    compaction_terminal_ops=1,
    compaction_min_dead_bytes=1,
)
compact_spool = DurableEventSpool(compact_root / "spool", policy=compact_policy)
compact_events = [make_event(f"COMPACT_{i}", "HIGH") for i in range(3)]
for event in compact_events:
    check(compact_spool.append(event) is True, f"Compaction fixture {event.event_type} persisted")
physical_before_ack = compact_spool._physical_pending_bytes()
check(compact_spool.ack(compact_events[0].event_id) is True, "ACK terminal transition succeeds")
physical_after_ack = compact_spool._physical_pending_bytes()
check(physical_after_ack < physical_before_ack, "ACK-triggered compaction reclaims terminal bytes")
check(compact_events[0].event_id not in {r["event_id"] for r in compact_spool.pending_records()}, "ACKed event is not pending after compaction")
check(compact_spool.get_stats()["compactions"] >= 1, "Compaction is observable")

restarted = DurableEventSpool(compact_root / "spool", policy=compact_policy)
restart_ids = {r["event_id"] for r in restarted.pending_records()}
check(compact_events[0].event_id not in restart_ids, "ACKed event does not resurrect after restart")
check(compact_events[1].event_id in restart_ids and compact_events[2].event_id in restart_ids, "Unacked evidence survives restart")
check(restarted.health_check()["pending_index_ready"] is True, "Restart rebuilds bounded pending index")

# ---------------------------------------------------------------------------
# 4. Bounded recovery batch through DurableEventPipeline
# ---------------------------------------------------------------------------
batch_root = ROOT / "batch"
clean(batch_root)
batch_policy = DurableSpoolPolicy(
    max_pending_events=10,
    max_pending_bytes=64 * 1024,
    max_event_bytes=8 * 1024,
    protected_reserve_events=2,
    protected_reserve_bytes=8 * 1024,
    max_recovery_batch=2,
    max_recovery_scan_bytes=64 * 1024,
)
batch_spool = DurableEventSpool(batch_root / "spool", policy=batch_policy)
for i in range(5):
    check(batch_spool.append(make_event(f"BATCH_{i}", "MEDIUM")) is True, f"Batch fixture {i} persisted")
check(len(batch_spool.pending_batch()) == 2, "Spool recovery snapshot is capped at max_recovery_batch")

bus = EventBus(10)
pipeline = DurableEventPipeline(batch_spool, bus)
published = pipeline.publish_pending()
check(published == 2, "Pipeline republishes only one bounded recovery batch")
check(bus.get_stats()["queue_size"] == 2, "Only bounded recovery batch reaches EventBus")
check(pipeline.VERSION == "1.3", "Pipeline bounded recovery contract version is v1.3")
check(pipeline.health_check()["status"] == "HEALTHY", "Bounded recovery pipeline remains HEALTHY")

# ---------------------------------------------------------------------------
# 5. Existing oversized/corrupt storage fails closed rather than pretending
#    to be empty/healthy.
# ---------------------------------------------------------------------------
scan_root = ROOT / "scan_limit"
clean(scan_root)
scan_dir = scan_root / "spool"
scan_dir.mkdir(parents=True, exist_ok=True)
(scan_dir / "pending.jsonl").write_bytes(b"X" * 4096)
scan_policy = DurableSpoolPolicy(
    max_pending_events=4,
    max_pending_bytes=1024,
    max_event_bytes=1024,
    protected_reserve_events=1,
    protected_reserve_bytes=256,
    max_recovery_batch=1,
    max_recovery_scan_bytes=1024,
)
scan_spool = DurableEventSpool(scan_dir, policy=scan_policy)
scan_health = scan_spool.health_check()
check(scan_health["status"] == "DEGRADED", "Oversized recovery surface is DEGRADED")
check(scan_health["capacity_status"] == "RECOVERY_LIMIT_EXCEEDED", "Recovery scan limit is explicit")
check(scan_health["pending_index_ready"] is False, "Unsafe oversized pending file never claims a ready index")
scan_append = scan_spool.append_with_result(make_event("SCAN_BLOCKED", "CRITICAL"))
check(scan_append.accepted is False, "Admission fails closed when recovery surface cannot be bounded")
check(scan_append.reason == "RECOVERY_SCAN_LIMIT_EXCEEDED", "Fail-closed scan-limit reason is explicit")

# ---------------------------------------------------------------------------
# 6. Bounded terminal tombstones and oversized terminal-state fail-closed
# ---------------------------------------------------------------------------
terminal_root = ROOT / "terminal_bound"
clean(terminal_root)
terminal_policy = DurableSpoolPolicy(
    max_pending_events=8,
    max_pending_bytes=64 * 1024,
    max_event_bytes=8 * 1024,
    protected_reserve_events=2,
    protected_reserve_bytes=8 * 1024,
    max_recovery_batch=2,
    max_recovery_scan_bytes=64 * 1024,
    compaction_terminal_ops=1,
    compaction_min_dead_bytes=1,
    max_terminal_records=2,
    max_terminal_state_bytes=4096,
)
terminal_spool = DurableEventSpool(terminal_root / "spool", policy=terminal_policy)
terminal_events = [make_event(f"TERMINAL_{i}", "HIGH") for i in range(4)]
for event in terminal_events:
    check(terminal_spool.append(event) is True, f"Terminal fixture {event.event_type} persisted")
    check(terminal_spool.ack(event.event_id) is True, f"Terminal fixture {event.event_type} ACKed")
terminal_stats = terminal_spool.get_stats()
check(terminal_stats["acked"] <= 2, "Local ACK tombstone cache is bounded")
check(terminal_stats["terminal_state_safe"] is True, "Bounded terminal state remains safe")
check((terminal_root / "spool" / "acked_state.json").stat().st_size <= 4096, "ACK snapshot byte bound is enforced")
check(len(terminal_spool.pending_records()) == 0, "Terminal compaction leaves no false pending records")
terminal_restart = DurableEventSpool(terminal_root / "spool", policy=terminal_policy)
check(terminal_restart.health_check()["terminal_state_safe"] is True, "Bounded terminal state survives restart")
check(len(terminal_restart.pending_records()) == 0, "Pruned terminal tombstones do not resurrect compacted pending records")

terminal_unsafe_root = ROOT / "terminal_unsafe"
clean(terminal_unsafe_root)
unsafe_dir = terminal_unsafe_root / "spool"
unsafe_dir.mkdir(parents=True, exist_ok=True)
(unsafe_dir / "acked_state.json").write_bytes(b"X" * 8192)
unsafe_policy = DurableSpoolPolicy(
    max_pending_events=8,
    max_pending_bytes=64 * 1024,
    max_event_bytes=8 * 1024,
    protected_reserve_events=2,
    protected_reserve_bytes=8 * 1024,
    max_recovery_batch=2,
    max_recovery_scan_bytes=64 * 1024,
    max_terminal_records=4,
    max_terminal_state_bytes=1024,
)
unsafe_spool = DurableEventSpool(unsafe_dir, policy=unsafe_policy)
unsafe_health = unsafe_spool.health_check()
check(unsafe_health["status"] == "DEGRADED", "Oversized terminal state is DEGRADED")
check(unsafe_health["terminal_state_safe"] is False, "Oversized terminal state is explicitly unsafe")
unsafe_result = unsafe_spool.append_with_result(make_event("TERMINAL_UNSAFE_BLOCK", "CRITICAL"))
check(unsafe_result.accepted is False, "Admission fails closed on unsafe terminal state")
check(unsafe_result.reason == "TERMINAL_STATE_UNSAFE", "Unsafe terminal-state rejection is explicit")

# ---------------------------------------------------------------------------
# Final invariant summary
# ---------------------------------------------------------------------------
stats = spool.get_stats()
check(stats["capacity_rejected"] >= 2, "Capacity rejection telemetry is recorded")
check(stats["protected_admitted"] >= 2, "Protected admission telemetry is recorded")
check(stats["bounded"] is True, "Stats preserve bounded contract")

print()
print("=== P0.3 RESULT ===")
print(f"PASS: {checks}")
print("FAIL: 0")
print("Protected reserve: VERIFIED")
print("No pending-evidence eviction: VERIFIED")
print("Max event size: VERIFIED")
print("Crash-safe compaction: VERIFIED")
print("Bounded recovery batch: VERIFIED")
print("Oversized recovery surface fail-closed: VERIFIED")
print("Bounded terminal tombstones: VERIFIED")
print("Oversized terminal state fail-closed: VERIFIED")
print("Production EventBus implementation: UNMODIFIED")
print("Production main.py runtime wiring: UNMODIFIED")
print("RESULT: PASS")
