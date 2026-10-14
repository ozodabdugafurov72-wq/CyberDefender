"""Durable Spool terminal-state corruption regression (Lead B, 2026-10-14).

Case 1 (garbage bytes) PASSES against durable_spool v2.3.
Case 2 (well-formed JSON, wrong acked_ids type) currently FAILS — known
defect E-SPOOL-1 handed to Codex: _read_ack_ids silently ignores a snapshot
whose acked_ids is not a list, reports HEALTHY and falls back to the legacy
journal. Do not weaken Case 2 to make this file green.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy


def policy() -> DurableSpoolPolicy:
    return DurableSpoolPolicy(
        max_pending_events=8,
        max_pending_bytes=64 * 1024,
        max_event_bytes=8 * 1024,
        protected_reserve_events=2,
        protected_reserve_bytes=8 * 1024,
        max_recovery_batch=2,
        max_recovery_scan_bytes=64 * 1024,
        compaction_terminal_ops=100,
        compaction_min_dead_bytes=64 * 1024,
        max_terminal_records=4,
        max_terminal_state_bytes=4096,
    )


def blocked_event(tag: str) -> SecurityEvent:
    return SecurityEvent(
        event_type=tag, severity="HIGH", value=1,
        source="test", message="corrupt terminal state fixture",
    )


# Case 1: in-bounds garbage bytes in the authoritative ACK snapshot must
# fail closed, not silently degrade to an empty/healthy terminal state.
with tempfile.TemporaryDirectory(prefix="cd-spool-corrupt-terminal-") as root:
    spool_dir = Path(root) / "spool"
    spool_dir.mkdir(parents=True)
    (spool_dir / "acked_state.json").write_bytes(b"{corrupt-not-json")
    spool = DurableEventSpool(spool_dir, policy=policy())
    health = spool.health_check()
    assert health["status"] == "DEGRADED", health
    assert health["terminal_state_safe"] is False, health
    result = spool.append_with_result(blocked_event("BLOCKED_AFTER_CORRUPT_STATE"))
    assert result.accepted is False, result
    print("PASS | in-bounds corrupt ACK snapshot fails closed (DEGRADED)")

# Case 2: well-formed JSON with invalid content must be rejected the same way.
with tempfile.TemporaryDirectory(prefix="cd-spool-invalid-terminal-") as root:
    spool_dir = Path(root) / "spool"
    spool_dir.mkdir(parents=True)
    (spool_dir / "acked_state.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "status": "ACKED",
                "acked_ids": "not-a-list",
            }
        ),
        encoding="utf-8",
    )
    spool = DurableEventSpool(spool_dir, policy=policy())
    health = spool.health_check()
    assert health["status"] == "DEGRADED", health
    assert health["terminal_state_safe"] is False, health
    assert spool.append_with_result(blocked_event("BLOCKED_AFTER_INVALID_STATE")).accepted is False
    print("PASS | well-formed but invalid ACK snapshot content is rejected")

# Case 3: the complete authoritative snapshot contract is exact and
# fail-closed. Missing/wrong fields, non-object roots and unknown fields are
# never reinterpreted as legacy state.
invalid_snapshots = (
    {},
    {"schema_version": "1", "status": "ACKED"},
    {"schema_version": 1, "status": "ACKED", "acked_ids": []},
    {"schema_version": "1", "status": "PENDING", "acked_ids": []},
    {"schema_version": "1", "status": "ACKED", "acked_ids": [], "extra": True},
    [],
)
for index, invalid_snapshot in enumerate(invalid_snapshots):
    with tempfile.TemporaryDirectory(prefix="cd-spool-invalid-contract-") as root:
        spool_dir = Path(root) / "spool"
        spool_dir.mkdir(parents=True)
        (spool_dir / "acked_state.json").write_text(
            json.dumps(invalid_snapshot), encoding="utf-8"
        )
        spool = DurableEventSpool(spool_dir, policy=policy())
        health = spool.health_check()
        assert health["status"] == "DEGRADED", (index, health)
        assert health["terminal_state_safe"] is False, (index, health)

# Case 4: a valid empty authoritative snapshot remains valid, and genuinely
# absent authoritative state may still migrate the supported legacy journal.
with tempfile.TemporaryDirectory(prefix="cd-spool-valid-empty-") as root:
    spool_dir = Path(root) / "spool"
    spool_dir.mkdir(parents=True)
    (spool_dir / "acked_state.json").write_text(
        json.dumps({"schema_version": "1", "status": "ACKED", "acked_ids": []}),
        encoding="utf-8",
    )
    spool = DurableEventSpool(spool_dir, policy=policy())
    assert spool.health_check()["status"] == "HEALTHY"

with tempfile.TemporaryDirectory(prefix="cd-spool-legacy-absent-") as root:
    spool_dir = Path(root) / "spool"
    spool_dir.mkdir(parents=True)
    (spool_dir / "acked.jsonl").write_text(
        json.dumps({"event_id": "legacy-event"}) + "\n", encoding="utf-8"
    )
    spool = DurableEventSpool(spool_dir, policy=policy())
    health = spool.health_check()
    assert health["status"] == "HEALTHY", health
    assert health["acked"] == 1, health
    print("PASS | strict snapshot contract preserves valid empty and absent legacy paths")

print("RESULT: PASS")
