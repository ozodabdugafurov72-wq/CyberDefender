from pathlib import Path
import json
import shutil

from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool


ROOT = Path(
    "state/test_p11_13_tampered_recovery"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

spool_dir = ROOT / "spool"


# ============================================================
# P11.13-01 CREATE SPOOL
# ============================================================

print("=== P11.13-01 CREATE SPOOL ===")

spool = DurableEventSpool(
    spool_dir
)


# ============================================================
# CREATE THREE EVENTS
#
# A = VALID
# B = WILL BE TAMPERED
# C = VALID
# ============================================================

event_a = SecurityEvent(
    event_type="P11_13_VALID_A",
    severity="HIGH",
    value=81,
    source="P11.13Sensor",
    message="Valid event A",
    confidence=0.99,
    host_id="host-p11-13",
    sensor_id="sensor-p11-13",
)

event_b = SecurityEvent(
    event_type="P11_13_TAMPERED_B",
    severity="CRITICAL",
    value=99,
    source="P11.13Sensor",
    message="Event B will be tampered",
    confidence=1.0,
    host_id="host-p11-13",
    sensor_id="sensor-p11-13",
)

event_c = SecurityEvent(
    event_type="P11_13_VALID_C",
    severity="MEDIUM",
    value=55,
    source="P11.13Sensor",
    message="Valid event C",
    confidence=0.95,
    host_id="host-p11-13",
    sensor_id="sensor-p11-13",
)


# ============================================================
# P11.13-02 APPEND ALL EVENTS
# ============================================================

print()
print("=== P11.13-02 APPEND EVENTS ===")

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
# P11.13-03 TAMPER EVENT B ON DISK
# ============================================================

print()
print(
    "=== P11.13-03 TAMPER EVENT B ==="
)

pending_path = (
    spool.pending_path
)

raw_lines = []

with pending_path.open(
    "r",
    encoding="utf-8",
) as file:
    raw_lines = file.readlines()


tampered_lines = []

for line in raw_lines:

    if not line.strip():
        continue

    record = json.loads(line)

    if (
        record.get("event_id")
        == event_b.event_id
    ):

        event_data = dict(
            record["event"]
        )

        # Payload modification WITHOUT
        # recalculating the original integrity.
        event_data["message"] = (
            "ATTACKER MODIFIED EVENT B"
        )

        record["event"] = event_data

    tampered_lines.append(
        json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


with pending_path.open(
    "w",
    encoding="utf-8",
) as file:

    file.writelines(
        tampered_lines
    )

print(
    "TAMPER_TARGET=",
    event_b.event_id,
)

print(
    "TAMPERED_MESSAGE=",
    "ATTACKER MODIFIED EVENT B",
)


# ============================================================
# P11.13-04 VERIFY THREE RAW RECORDS EXIST
# ============================================================

print()
print(
    "=== P11.13-04 VERIFY RAW RECORDS ==="
)

raw_pending = (
    spool.pending_records()
)

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
# P11.13-05 RECOVERY
#
# Valid A -> SUCCESS
# Tampered B -> rejected before callback
# Valid C -> SUCCESS
# ============================================================

print()
print(
    "=== P11.13-05 RECOVERY ==="
)

recovered_ids = []
callback_ids = []


def recovery_callback(event):

    callback_ids.append(
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
    "CALLBACK_COUNT=",
    len(callback_ids),
)

print(
    "CALLBACK_IDS=",
    callback_ids,
)


# ============================================================
# P11.13-06 FINAL PENDING STATE
# ============================================================

print()
print(
    "=== P11.13-06 FINAL PENDING ==="
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
# P11.13-07 ACKED STATE
# ============================================================

print()
print(
    "=== P11.13-07 ACKED STATE ==="
)

stats = spool.get_stats()

print(
    "SPOOL_STATS=",
    stats,
)


# ============================================================
# P11.13-08 SECOND RECOVERY
#
# Tampered B must remain pending.
# It must NOT be delivered.
# ============================================================

print()
print(
    "=== P11.13-08 SECOND RECOVERY ==="
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

print(
    "SECOND_RECOVERY_COUNT=",
    second_recovery_count,
)

print(
    "SECOND_CALLBACKS=",
    second_callbacks,
)

pending_after_second = (
    spool.pending_records()
)

pending_after_second_ids = [
    record["event_id"]
    for record in pending_after_second
]

print(
    "PENDING_AFTER_SECOND=",
    pending_after_second_ids,
)


# ============================================================
# P11.13-09 FINAL HEALTH-LIKE STATE
# ============================================================

print()
print(
    "=== P11.13-09 FINAL STATE ==="
)

final_stats = spool.get_stats()

print(
    "FINAL_STATS=",
    final_stats,
)


# ============================================================
# P11.13-10 FINAL ASSERTIONS
# ============================================================

print()
print(
    "=== P11.13-10 FINAL ASSERTIONS ==="
)


# ------------------------------------------------------------
# All three events initially appended.
# ------------------------------------------------------------

assert append_a is True
assert append_b is True
assert append_c is True


# ------------------------------------------------------------
# Three raw records existed.
# ------------------------------------------------------------

assert len(raw_pending) == 3

assert event_a.event_id in raw_ids
assert event_b.event_id in raw_ids
assert event_c.event_id in raw_ids


# ------------------------------------------------------------
# Tampered event MUST NOT reach callback.
# ------------------------------------------------------------

assert event_b.event_id not in callback_ids


# ------------------------------------------------------------
# Valid events MUST be recovered.
# ------------------------------------------------------------

assert event_a.event_id in callback_ids
assert event_c.event_id in callback_ids


# Exactly two valid events should be processed.
assert recovered_count == 2
assert len(callback_ids) == 2


# ------------------------------------------------------------
# Valid events must be ACKed.
# ------------------------------------------------------------

assert event_a.event_id not in pending_final_ids
assert event_c.event_id not in pending_final_ids


# ------------------------------------------------------------
# Tampered event must remain pending.
# ------------------------------------------------------------

assert event_b.event_id in pending_final_ids

assert len(pending_final) == 1


# ------------------------------------------------------------
# Second recovery must NOT deliver tampered event.
# ------------------------------------------------------------

assert second_recovery_count == 0

assert len(second_callbacks) == 0

assert event_b.event_id not in second_callbacks


# ------------------------------------------------------------
# Tampered event must remain pending forever
# until explicitly repaired/quarantined.
# ------------------------------------------------------------

assert event_b.event_id in pending_after_second_ids

assert len(pending_after_second) == 1


# ------------------------------------------------------------
# Integrity rejection must be recorded.
# ------------------------------------------------------------

assert final_stats["integrity_rejected"] >= 1


# ------------------------------------------------------------
# No corruption of unrelated valid events.
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
    "TAMPERED_B_BLOCKED=True"
)

print(
    "TAMPERED_B_NOT_DELIVERED=True"
)

print(
    "TAMPERED_B_NOT_ACKED=True"
)

print(
    "VALID_EVENTS_NOT_BLOCKED=True"
)

print(
    "INTEGRITY_REJECTION_RECORDED=True"
)

print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)
