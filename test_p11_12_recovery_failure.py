from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool


ROOT = Path("state/test_p11_12_recovery_failure")

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

spool_dir = ROOT / "spool"

spool = DurableEventSpool(
    spool_dir
)


# ============================================================
# P11.12-01 CREATE EVENT
# ============================================================

print("=== P11.12-01 CREATE EVENT ===")

event = SecurityEvent(
    event_type="P11_12_RECOVERY_FAILURE",
    severity="CRITICAL",
    value=99,
    source="P11.12TestSensor",
    message="At-least-once recovery test",
    confidence=1.0,
    host_id="host-p11-12",
    sensor_id="sensor-p11-12",
)

appended = spool.append(event)

print("APPENDED=", appended)
print("EVENT_ID=", event.event_id)
print(
    "PENDING_INITIAL=",
    len(spool.pending_records()),
)


# ============================================================
# P11.12-02 RECOVERY FAILURE
# ============================================================

print()
print("=== P11.12-02 RECOVERY FAILURE ===")

failed_callbacks = []


def failing_callback(recovered_event):
    failed_callbacks.append(recovered_event)

    print(
        "CALLBACK_FAILURE_EVENT_ID=",
        recovered_event.event_id,
    )

    return False


failed_replay_count = spool.replay_events(
    failing_callback
)

pending_after_failure = (
    spool.pending_records()
)

print(
    "FAILED_REPLAY_COUNT=",
    failed_replay_count,
)

print(
    "FAILED_CALLBACK_COUNT=",
    len(failed_callbacks),
)

print(
    "PENDING_AFTER_FAILURE=",
    len(pending_after_failure),
)


# ============================================================
# P11.12-03 VERIFY FAILURE PRESERVATION
# ============================================================

print()
print(
    "=== P11.12-03 VERIFY PENDING AFTER FAILURE ==="
)

pending_ids_after_failure = [
    record["event_id"]
    for record in pending_after_failure
]

original_event_still_pending = (
    event.event_id
    in pending_ids_after_failure
)

print(
    "PENDING_IDS=",
    pending_ids_after_failure,
)

print(
    "ORIGINAL_EVENT_STILL_PENDING=",
    original_event_still_pending,
)


# ============================================================
# P11.12-04 SECOND RECOVERY
# SUCCESS
# ============================================================

print()
print(
    "=== P11.12-04 RECOVERY SUCCESS ==="
)

successful_callbacks = []


def successful_callback(recovered_event):
    successful_callbacks.append(
        recovered_event
    )

    print(
        "CALLBACK_SUCCESS_EVENT_ID=",
        recovered_event.event_id,
    )

    return True


successful_replay_count = spool.replay_events(
    successful_callback
)

pending_after_success = (
    spool.pending_records()
)

print(
    "SUCCESSFUL_REPLAY_COUNT=",
    successful_replay_count,
)

print(
    "SUCCESSFUL_CALLBACK_COUNT=",
    len(successful_callbacks),
)

print(
    "PENDING_AFTER_SUCCESS=",
    len(pending_after_success),
)


# ============================================================
# P11.12-05 AUTOMATIC ACK
# ============================================================

print()
print(
    "=== P11.12-05 AUTOMATIC ACK ==="
)

pending_ids_after_success = [
    record["event_id"]
    for record in pending_after_success
]

event_pending_after_success = (
    event.event_id
    in pending_ids_after_success
)

print(
    "PENDING_IDS_AFTER_SUCCESS=",
    pending_ids_after_success,
)

print(
    "EVENT_PENDING_AFTER_SUCCESS=",
    event_pending_after_success,
)


# ============================================================
# P11.12-06 THIRD RECOVERY
# ============================================================

print()
print(
    "=== P11.12-06 THIRD RECOVERY ==="
)

third_callbacks = []


def third_callback(recovered_event):
    third_callbacks.append(
        recovered_event
    )

    return True


third_replay_count = spool.replay_events(
    third_callback
)

pending_final = spool.pending_records()

print(
    "THIRD_REPLAY_COUNT=",
    third_replay_count,
)

print(
    "THIRD_CALLBACK_COUNT=",
    len(third_callbacks),
)

print(
    "PENDING_FINAL=",
    len(pending_final),
)


# ============================================================
# P11.12-07 STATS
# ============================================================

print()
print(
    "=== P11.12-07 STATS ==="
)

stats = spool.get_stats()

print(
    "SPOOL_STATS=",
    stats,
)


# ============================================================
# P11.12-08 FINAL ASSERTIONS
# ============================================================

print()
print(
    "=== P11.12-08 FINAL ASSERTIONS ==="
)

# ------------------------------------------------------------
# Initial append
# ------------------------------------------------------------

assert appended is True

# ------------------------------------------------------------
# Failure MUST preserve event
# ------------------------------------------------------------

assert failed_replay_count == 0

assert len(
    failed_callbacks
) == 1

assert failed_callbacks[0].event_id == (
    event.event_id
)

assert len(
    pending_after_failure
) == 1

assert original_event_still_pending is True

# ------------------------------------------------------------
# Successful recovery MUST process event
# ------------------------------------------------------------

assert successful_replay_count == 1

assert len(
    successful_callbacks
) == 1

assert successful_callbacks[0].event_id == (
    event.event_id
)

# ------------------------------------------------------------
# Successful recovery MUST ACK event
# ------------------------------------------------------------

assert len(
    pending_after_success
) == 0

assert event_pending_after_success is False

# ------------------------------------------------------------
# Third recovery MUST find nothing
# ------------------------------------------------------------

assert third_replay_count == 0

assert len(
    third_callbacks
) == 0

assert len(
    pending_final
) == 0

# ------------------------------------------------------------
# Stats invariants
# ------------------------------------------------------------

assert stats["pending"] == 0

assert stats["acked"] == 1

assert stats["appended"] == 1

assert stats["replayed"] == 1

assert stats["callback_failed"] == 1

assert stats["integrity_rejected"] == 0

assert stats["corrupted"] == 0


print(
    "FAILURE_PRESERVED_EVENT=True"
)

print(
    "SUCCESS_RECOVERY_PROCESSED=True"
)

print(
    "SUCCESS_AUTOMATIC_ACK=True"
)

print(
    "NO_REPLAY_AFTER_ACK=True"
)

print(
    "FINAL_PENDING_ZERO=True"
)

print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)
