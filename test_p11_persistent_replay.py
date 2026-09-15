from pathlib import Path
import shutil
import json

from agent.event import SecurityEvent

from agent.crypto.trust import (
    CryptographicTrust,
    TrustedEventEnvelope,
)

from agent.crypto.persistent_replay_guard import (
    PersistentReplayGuard,
)


ROOT = Path(
    "state/test_p11_persistent_replay"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)


print(
    "=== P11.3-01 FIRST PROCESS ==="
)

trust = CryptographicTrust.generate()

event = SecurityEvent(
    event_type="P11_PERSISTENT_REPLAY",
    severity="CRITICAL",
    value=999,
    source="P11PersistentTest",
    message="Persistent replay test",
    confidence=0.99,
    host_id="host-p11",
    sensor_id="sensor-p11",
)

envelope = TrustedEventEnvelope(
    event,
    trust,
).to_dict()


guard1 = PersistentReplayGuard(
    ROOT
)

first = guard1.check_and_remember(
    event.event_id
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
    "STATS1=",
    guard1.get_stats(),
)


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
        event.event_id
    ),
)


print()
print(
    "=== P11.3-03 REPLAY AFTER RESTART ==="
)

replay = guard2.check_and_remember(
    event.event_id
)

print(
    "REPLAY_ACCEPT=",
    replay,
)

print(
    "STATS2=",
    guard2.get_stats(),
)


print()
print(
    "=== P11.3-04 NEW EVENT ==="
)

event2 = SecurityEvent(
    event_type="P11_PERSISTENT_NEW",
    severity="HIGH",
    value=100,
    source="P11PersistentTest",
    message="New event after restart",
    confidence=0.95,
    host_id="host-p11",
    sensor_id="sensor-p11",
)

new_event = guard2.check_and_remember(
    event2.event_id
)

print(
    "NEW_ACCEPT=",
    new_event,
)

print(
    "SIZE_AFTER_NEW=",
    guard2.size(),
)


print()
print(
    "=== P11.3-05 STATE TAMPER ==="
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
    ),
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
    "TAMPERED_STATE_HEALTH=",
    guard3.health_check(),
)

print(
    "TAMPERED_STATE_STATS=",
    guard3.get_stats(),
)


print()
print(
    "=== P11.3-06 CORRUPTED STATE ==="
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

guard4 = PersistentReplayGuard(
    ROOT
)

guard4.check_and_remember(
    event.event_id
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
    "CORRUPTED_STATE_HEALTH=",
    guard5.health_check(),
)

print(
    "CORRUPTED_STATE_STATS=",
    guard5.get_stats(),
)


print()
print(
    "=== P11.3-07 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
