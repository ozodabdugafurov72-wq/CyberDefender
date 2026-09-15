from pathlib import Path
import json
import shutil

from agent.crypto.persistent_replay_guard import (
    PersistentReplayGuard,
)


ROOT = Path(
    "state/test_p11_persistent_replay_v12"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)


# ============================================================
# P11.3-01 FIRST PROCESS
# ============================================================

print(
    "=== P11.3-01 FIRST PROCESS ==="
)

guard1 = PersistentReplayGuard(
    ROOT
)

event_id = (
    "p11-event-001"
)

first = guard1.check_and_remember(
    event_id
)

print(
    "FIRST_ACCEPT=",
    first,
)

print(
    "PENDING_STATE=",
    guard1.size(),
)

print(
    "READY=",
    guard1.is_ready(),
)

print(
    "STATS1=",
    guard1.get_stats(),
)


# ============================================================
# P11.3-02 RESTART
# ============================================================

print()
print(
    "=== P11.3-02 RESTART ==="
)

guard2 = PersistentReplayGuard(
    ROOT
)

print(
    "RECOVERED_SIZE=",
    guard2.size(),
)

print(
    "RECOVERED_CONTAINS=",
    guard2.contains(
        event_id
    ),
)

print(
    "READY_AFTER_RESTART=",
    guard2.is_ready(),
)


# ============================================================
# P11.3-03 REPLAY AFTER RESTART
# ============================================================

print()
print(
    "=== P11.3-03 REPLAY AFTER RESTART ==="
)

replay = guard2.check_and_remember(
    event_id
)

print(
    "REPLAY_ACCEPT=",
    replay,
)

print(
    "DUPLICATES=",
    guard2.get_stats()[
        "duplicates"
    ],
)


# ============================================================
# P11.3-04 NEW EVENT AFTER RESTART
# ============================================================

print()
print(
    "=== P11.3-04 NEW EVENT ==="
)

new_event_id = (
    "p11-event-002"
)

new_event = guard2.check_and_remember(
    new_event_id
)

print(
    "NEW_ACCEPT=",
    new_event,
)

print(
    "SIZE_AFTER_NEW=",
    guard2.size(),
)


# ============================================================
# P11.3-05 TAMPER STATE
# ============================================================

print()
print(
    "=== P11.3-05 TAMPER STATE ==="
)

state_path = (
    ROOT
    / "replay_state.json"
)

data = json.loads(
    state_path.read_text(
        encoding="utf-8"
    )
)

data["event_ids"].append(
    "ATTACKER_INJECTED_EVENT"
)

state_path.write_text(
    json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)

guard3 = PersistentReplayGuard(
    ROOT
)

print(
    "TAMPERED_STATE_SIZE=",
    guard3.size(),
)

print(
    "TAMPERED_READY=",
    guard3.is_ready(),
)

print(
    "TAMPERED_HEALTH=",
    guard3.health_check(),
)

print(
    "TAMPERED_STATS=",
    guard3.get_stats(),
)


# ============================================================
# P11.3-06 FAIL-SAFE AFTER TAMPER
# ============================================================

print()
print(
    "=== P11.3-06 FAIL-SAFE AFTER TAMPER ==="
)

blocked_event = guard3.check_and_remember(
    "new-event-after-tamper"
)

print(
    "NEW_EVENT_ACCEPT_AFTER_TAMPER=",
    blocked_event,
)

print(
    "SIZE_AFTER_TAMPER_ATTEMPT=",
    guard3.size(),
)


# ============================================================
# P11.3-07 CORRUPTED STATE
# ============================================================

print()
print(
    "=== P11.3-07 CORRUPTED STATE ==="
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

guard4 = PersistentReplayGuard(
    ROOT
)

guard4.check_and_remember(
    "corruption-test-event"
)

(
    ROOT
    / "replay_state.json"
).write_text(
    "{CORRUPTED JSON",
    encoding="utf-8",
)

guard5 = PersistentReplayGuard(
    ROOT
)

print(
    "CORRUPTED_STATE_SIZE=",
    guard5.size(),
)

print(
    "CORRUPTED_READY=",
    guard5.is_ready(),
)

print(
    "CORRUPTED_HEALTH=",
    guard5.health_check(),
)

print(
    "CORRUPTED_STATS=",
    guard5.get_stats(),
)


# ============================================================
# P11.3-08 FAIL-SAFE AFTER CORRUPTION
# ============================================================

print()
print(
    "=== P11.3-08 FAIL-SAFE AFTER CORRUPTION ==="
)

blocked_after_corruption = (
    guard5.check_and_remember(
        "new-event-after-corruption"
    )
)

print(
    "NEW_EVENT_ACCEPT_AFTER_CORRUPTION=",
    blocked_after_corruption,
)

print(
    "SIZE_AFTER_CORRUPTION_ATTEMPT=",
    guard5.size(),
)


# ============================================================
# P11.3-09 FINAL
# ============================================================

print()
print(
    "=== P11.3-09 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
