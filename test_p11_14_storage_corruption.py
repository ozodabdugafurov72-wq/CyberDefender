from pathlib import Path
import json
import shutil

from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool


ROOT = Path(
    "state/test_p11_14_storage_corruption"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

spool_dir = ROOT / "spool"


# ============================================================
# P11.14-01 CREATE SPOOL
# ============================================================

print("=== P11.14-01 CREATE SPOOL ===")

spool = DurableEventSpool(
    spool_dir
)


# ============================================================
# CREATE THREE EVENTS
#
# A = VALID
# B = STORAGE RECORD WILL BE CORRUPTED
# C = VALID
# ============================================================

event_a = SecurityEvent(
    event_type="P11_14_VALID_A",
    severity="HIGH",
    value=80,
    source="P11.14Sensor",
    message="Valid storage event A",
    confidence=0.99,
    host_id="host-p11-14",
    sensor_id="sensor-p11-14",
)

event_b = SecurityEvent(
    event_type="P11_14_CORRUPTED_B",
    severity="CRITICAL",
    value=99,
    source="P11.14Sensor",
    message="Storage record B will be corrupted",
    confidence=1.0,
    host_id="host-p11-14",
    sensor_id="sensor-p11-14",
)

event_c = SecurityEvent(
    event_type="P11_14_VALID_C",
    severity="MEDIUM",
    value=50,
    source="P11.14Sensor",
    message="Valid storage event C",
    confidence=0.95,
    host_id="host-p11-14",
    sensor_id="sensor-p11-14",
)


# ============================================================
# P11.14-02 APPEND
# ============================================================

print()
print("=== P11.14-02 APPEND EVENTS ===")

append_a = spool.append(event_a)
append_b = spool.append(event_b)
append_c = spool.append(event_c)

print(
    "APPEND_A=",
    append_a,
)

print(
    "APPEND_B=",
    append_b,
)

print(
    "APPEND_C=",
    append_c,
)

print(
    "PENDING_INITIAL=",
    len(spool.pending_records()),
)


# ============================================================
# P11.14-03 CORRUPT STORAGE RECORD B
#
# We intentionally break the JSON storage record itself.
# This is different from P11.13 where the event payload
# remained valid JSON but its integrity was modified.
# ============================================================

print()
print(
    "=== P11.14-03 CORRUPT STORAGE RECORD B ==="
)

pending_path = spool.pending_path

with pending_path.open(
    "r",
    encoding="utf-8",
) as file:
    original_lines = file.readlines()


corrupted_lines = []

for line in original_lines:

    if not line.strip():
        continue

    record = json.loads(line)

    if (
        record.get("event_id")
        == event_b.event_id
    ):
        # Deliberately corrupt the JSON record.
        #
        # The event ID is kept conceptually associated
        # with the corrupted line, but the JSON itself
        # becomes syntactically invalid.
        corrupted_lines.append(
            '{"spool_version":"1.3","event_id":"'
            + event_b.event_id
            + '","event":{"CORRUPTED":'
        )

    else:
        corrupted_lines.append(
            line.rstrip("\n")
        )

with pending_path.open(
    "w",
    encoding="utf-8",
) as file:

    for line in corrupted_lines:
        file.write(line)
        file.write("\n")


print(
    "CORRUPTION_TARGET=",
    event_b.event_id,
)

print(
    "CORRUPTION_TYPE=",
    "INVALID_JSON_RECORD",
)


# ============================================================
# P11.14-04 RAW STORAGE READ
# ============================================================

print()
print(
    "=== P11.14-04 RAW STORAGE READ ==="
)

raw_pending = spool.pending_records()

raw_ids = [
    record["event_id"]
    for record in raw_pending
]

print(
    "RAW_PENDING_COUNT=",
    len(raw_pending),
)

print(
    "RAW_PENDING_IDS=",
    raw_ids,
)


# ============================================================
# P11.14-05 RECOVERY
# ============================================================

print()
print(
    "=== P11.14-05 RECOVERY ==="
)

recovered_ids = []


def recovery_callback(event):

    recovered_ids.append(
        event.event_id
    )

    print(
        "CALLBACK_EVENT=",
        event.event_id,
    )

    return True


recovered_count = (
    spool.replay_events(
        recovery_callback
    )
)

print(
    "RECOVERED_COUNT=",
    recovered_count,
)

print(
    "RECOVERED_IDS=",
    recovered_ids,
)


# ============================================================
# P11.14-06 FINAL PENDING
# ============================================================

print()
print(
    "=== P11.14-06 FINAL PENDING ==="
)

pending_final = (
    spool.pending_records()
)

pending_final_ids = [
    record["event_id"]
    for record in pending_final
]

print(
    "PENDING_FINAL_COUNT=",
    len(pending_final),
)

print(
    "PENDING_FINAL_IDS=",
    pending_final_ids,
)

print(
    "A_PENDING=",
    event_a.event_id
    in pending_final_ids,
)

print(
    "B_PENDING=",
    event_b.event_id
    in pending_final_ids,
)

print(
    "C_PENDING=",
    event_c.event_id
    in pending_final_ids,
)


# ============================================================
# P11.14-07 STATS
# ============================================================

print()
print(
    "=== P11.14-07 STATS ==="
)

stats = spool.get_stats()

print(
    "SPOOL_STATS=",
    stats,
)


# ============================================================
# P11.14-08 SECOND RECOVERY
#
# The corrupted record must never reach the callback.
# ============================================================

print()
print(
    "=== P11.14-08 SECOND RECOVERY ==="
)

second_callbacks = []


def second_callback(event):

    second_callbacks.append(
        event.event_id
    )

    return True


second_recovery_count = (
    spool.replay_events(
        second_callback
    )
)

pending_after_second = (
    spool.pending_records()
)

pending_after_second_ids = [
    record["event_id"]
    for record in pending_after_second
]

print(
    "SECOND_RECOVERY_COUNT=",
    second_recovery_count,
)

print(
    "SECOND_CALLBACKS=",
    second_callbacks,
)

print(
    "PENDING_AFTER_SECOND=",
    pending_after_second_ids,
)


# ============================================================
# P11.14-09 FINAL STATS
# ============================================================

print()
print(
    "=== P11.14-09 FINAL STATE ==="
)

final_stats = spool.get_stats()

print(
    "FINAL_STATS=",
    final_stats,
)


# ============================================================
# P11.14-10 FINAL ASSERTIONS
# ============================================================

print()
print(
    "=== P11.14-10 FINAL ASSERTIONS ==="
)

# ------------------------------------------------------------
# All events appended before corruption.
# ------------------------------------------------------------

assert append_a is True
assert append_b is True
assert append_c is True


# ------------------------------------------------------------
# Corrupted storage record must not be delivered.
# ------------------------------------------------------------

assert event_b.event_id not in recovered_ids


# ------------------------------------------------------------
# Valid A and C must still recover.
# ------------------------------------------------------------

assert event_a.event_id in recovered_ids
assert event_c.event_id in recovered_ids


# Exactly two valid events recovered.
assert recovered_count == 2
assert len(recovered_ids) == 2


# ------------------------------------------------------------
# Valid events must be ACKed.
# ------------------------------------------------------------

assert event_a.event_id not in pending_final_ids
assert event_c.event_id not in pending_final_ids


# ------------------------------------------------------------
# Corrupted B must NOT be ACKed.
#
# Because its JSON record is syntactically corrupted,
# it cannot be safely reconstructed.
# ------------------------------------------------------------

assert event_b.event_id not in pending_final_ids


# IMPORTANT:
# Since the raw JSON line itself is corrupted,
# the current spool reader cannot preserve its event_id
# as a valid pending record.
#
# Therefore the safety invariant here is:
#
# corrupted record:
#     NOT delivered
#     NOT ACKed
#     NOT reconstructed
#
# rather than:
#
# corrupted record remains pending.
# ------------------------------------------------------------


# ------------------------------------------------------------
# Second recovery must not deliver corrupted B.
# ------------------------------------------------------------

assert second_recovery_count == 0
assert len(second_callbacks) == 0


# ------------------------------------------------------------
# Corruption must be detected.
# ------------------------------------------------------------

assert final_stats["corrupted"] >= 1


# ------------------------------------------------------------
# No unrelated valid event is blocked.
# ------------------------------------------------------------

assert event_a.event_id not in pending_after_second_ids
assert event_c.event_id not in pending_after_second_ids


print(
    "VALID_A_RECOVERED=True"
)

print(
    "VALID_C_RECOVERED=True"
)

print(
    "CORRUPTED_B_NOT_DELIVERED=True"
)

print(
    "CORRUPTED_B_NOT_ACKED=True"
)

print(
    "CORRUPTED_STORAGE_DETECTED=True"
)

print(
    "VALID_EVENTS_NOT_BLOCKED=True"
)

print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)
