from pathlib import Path
import hashlib
import hmac
import json
import shutil

from agent.crypto.authenticated_replay_state import (
    AuthenticatedReplayState,
    generate_key,
)


ROOT = Path(
    "state/test_p11_authenticated_replay"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

key = generate_key()


# ============================================================
# P11.4-01 FIRST ACCEPT
# ============================================================

print(
    "=== P11.4-01 FIRST ACCEPT ==="
)

guard1 = AuthenticatedReplayState(
    ROOT,
    key,
)

event_id = (
    "p11-auth-event-001"
)

first = guard1.check_and_remember(
    event_id
)

print(
    "FIRST_ACCEPT=",
    first,
)

print(
    "SIZE=",
    guard1.size(),
)

print(
    "READY=",
    guard1.is_ready(),
)


# ============================================================
# P11.4-02 RESTART WITH SAME KEY
# ============================================================

print()
print(
    "=== P11.4-02 RESTART SAME KEY ==="
)

guard2 = AuthenticatedReplayState(
    ROOT,
    key,
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
    "READY=",
    guard2.is_ready(),
)


# ============================================================
# P11.4-03 REPLAY
# ============================================================

print()
print(
    "=== P11.4-03 REPLAY ==="
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
# P11.4-04 STATE TAMPER WITHOUT MAC
# ============================================================

print()
print(
    "=== P11.4-04 STATE TAMPER ==="
)

state_path = (
    ROOT
    / "authenticated_replay_state.json"
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

guard3 = AuthenticatedReplayState(
    ROOT,
    key,
)

print(
    "TAMPER_READY=",
    guard3.is_ready(),
)

print(
    "TAMPER_SIZE=",
    guard3.size(),
)

print(
    "TAMPER_HEALTH=",
    guard3.health_check(),
)

print(
    "TAMPER_STATS=",
    guard3.get_stats(),
)


# ============================================================
# P11.4-05 FAIL-SAFE AFTER TAMPER
# ============================================================

print()
print(
    "=== P11.4-05 FAIL-SAFE AFTER TAMPER ==="
)

blocked = guard3.check_and_remember(
    "new-event-after-tamper"
)

print(
    "NEW_EVENT_ACCEPT=",
    blocked,
)

print(
    "SIZE_AFTER_ATTEMPT=",
    guard3.size(),
)


# ============================================================
# P11.4-06 MAC TAMPER
# ============================================================

print()
print(
    "=== P11.4-06 MAC TAMPER ==="
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

guard4 = AuthenticatedReplayState(
    ROOT,
    key,
)

guard4.check_and_remember(
    "mac-test-event"
)

mac_path = (
    ROOT
    / "authenticated_replay_state.mac"
)

mac_path.write_text(
    "00" * 32 + "\n",
    encoding="ascii",
)

guard5 = AuthenticatedReplayState(
    ROOT,
    key,
)

print(
    "BAD_MAC_READY=",
    guard5.is_ready(),
)

print(
    "BAD_MAC_SIZE=",
    guard5.size(),
)

print(
    "BAD_MAC_HEALTH=",
    guard5.health_check(),
)

print(
    "BAD_MAC_STATS=",
    guard5.get_stats(),
)


# ============================================================
# P11.4-07 WRONG KEY
# ============================================================

print()
print(
    "=== P11.4-07 WRONG KEY ==="
)

wrong_key = generate_key()

guard6 = AuthenticatedReplayState(
    ROOT,
    wrong_key,
)

print(
    "WRONG_KEY_READY=",
    guard6.is_ready(),
)

print(
    "WRONG_KEY_SIZE=",
    guard6.size(),
)

print(
    "WRONG_KEY_HEALTH=",
    guard6.health_check(),
)


# ============================================================
# P11.4-08 FAIL-SAFE WRONG KEY
# ============================================================

print()
print(
    "=== P11.4-08 FAIL-SAFE WRONG KEY ==="
)

wrong_key_accept = (
    guard6.check_and_remember(
        "wrong-key-new-event"
    )
)

print(
    "WRONG_KEY_NEW_EVENT_ACCEPT=",
    wrong_key_accept,
)

print(
    "WRONG_KEY_SIZE_AFTER=",
    guard6.size(),
)


# ============================================================
# P11.4-09 FINAL
# ============================================================

print()
print(
    "=== P11.4-09 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
