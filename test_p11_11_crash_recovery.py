from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline

from agent.crypto.key_manager import (
    KeyManager,
    generate_storage_key,
)

from agent.crypto.persistent_replay_guard import (
    PersistentReplayGuard,
)

from agent.core.crypto_replay_admission_gateway import (
    CryptoReplayAdmissionGateway,
)


ROOT = Path(
    "state/test_p11_11_crash_recovery"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)


# ============================================================
# SHARED STORAGE / TRUST
# ============================================================

storage_key = generate_storage_key()

key_root = ROOT / "keys"
replay_root = ROOT / "replay"
spool_root = ROOT / "spool"


# ============================================================
# PROCESS 1
# ============================================================

print("=== P11.11-01 PROCESS 1 ===")

bus1 = EventBus(10)

key_manager1 = KeyManager(
    key_root,
    storage_key,
)

key_id = key_manager1.generate_key()

replay1 = PersistentReplayGuard(
    replay_root,
    max_entries=100000,
)

spool1 = DurableEventSpool(
    spool_root
)

pipeline1 = DurableEventPipeline(
    spool1,
    bus1,
)

gateway1 = CryptoReplayAdmissionGateway(
    key_manager1,
    replay1,
    pipeline1,
)


# ------------------------------------------------------------
# EVENT A
# This event will be ACKed before the simulated crash.
# ------------------------------------------------------------

event_a = SecurityEvent(
    event_type="P11_11_EVENT_A",
    severity="HIGH",
    value=81,
    source="P11.11Sensor",
    message="Event A - will be ACKed",
    confidence=0.99,
    host_id="host-p11-11",
    sensor_id="sensor-p11-11",
)

envelope_a = gateway1.sign_event(
    event_a
)

accepted_a = gateway1.admit(
    event_a,
    envelope_a["key_id"],
    envelope_a["signature"],
)

print(
    "EVENT_A_ACCEPT=",
    accepted_a,
)


# ------------------------------------------------------------
# EVENT B
# This event will remain unacknowledged at crash time.
# ------------------------------------------------------------

event_b = SecurityEvent(
    event_type="P11_11_EVENT_B",
    severity="CRITICAL",
    value=97,
    source="P11.11Sensor",
    message="Event B - crash before ACK",
    confidence=1.0,
    host_id="host-p11-11",
    sensor_id="sensor-p11-11",
)

envelope_b = gateway1.sign_event(
    event_b
)

accepted_b = gateway1.admit(
    event_b,
    envelope_b["key_id"],
    envelope_b["signature"],
)

print(
    "EVENT_B_ACCEPT=",
    accepted_b,
)

print()
print(
    "PENDING_BEFORE_ACK=",
    len(
        spool1.pending_records()
    ),
)


# ============================================================
# DELIVER EVENTS
# ACK ONLY EVENT A
# ============================================================

print()
print(
    "=== P11.11-02 ACK EVENT A ONLY ==="
)

received_before_crash = []

bus1.subscribe(
    lambda event: received_before_crash.append(
        event
    )
)

bus1.dispatch_all()

print(
    "RECEIVED_BEFORE_CRASH=",
    len(received_before_crash),
)

ack_a = pipeline1.ack(
    event_a.event_id
)

print(
    "ACK_EVENT_A=",
    ack_a,
)

print(
    "PENDING_AFTER_ACK_A=",
    len(
        spool1.pending_records()
    ),
)


# ============================================================
# SIMULATED CRASH
# ============================================================

print()
print(
    "=== P11.11-03 SIMULATED CRASH ==="
)

del gateway1
del pipeline1
del spool1
del replay1
del key_manager1
del bus1

print(
    "PROCESS1_CRASHED=True"
)


# ============================================================
# PROCESS 2 / RESTART
# ============================================================

print()
print(
    "=== P11.11-04 PROCESS 2 RESTART ==="
)

bus2 = EventBus(10)

key_manager2 = KeyManager(
    key_root,
    storage_key,
)

replay2 = PersistentReplayGuard(
    replay_root,
    max_entries=100000,
)

spool2 = DurableEventSpool(
    spool_root
)

pipeline2 = DurableEventPipeline(
    spool2,
    bus2,
)

gateway2 = CryptoReplayAdmissionGateway(
    key_manager2,
    replay2,
    pipeline2,
)

print(
    "REPLAY_RECOVERED=",
    replay2.size(),
)

print(
    "EVENT_A_REPLAY_STATE=",
    replay2.contains(
        event_a.event_id
    ),
)

print(
    "EVENT_B_REPLAY_STATE=",
    replay2.contains(
        event_b.event_id
    ),
)

print(
    "SPOOL_PENDING_AFTER_RESTART=",
    len(
        spool2.pending_records()
    ),
)


# ============================================================
# VERIFY ACKED EVENT A IS NOT PENDING
# ============================================================

print()
print(
    "=== P11.11-05 ACKED EVENT A CHECK ==="
)

pending_after_restart = (
    spool2.pending_events()
)

pending_ids = [
    event.event_id
    for event in pending_after_restart
]

print(
    "PENDING_IDS=",
    pending_ids,
)

print(
    "EVENT_A_PENDING=",
    event_a.event_id in pending_ids,
)

print(
    "EVENT_B_PENDING=",
    event_b.event_id in pending_ids,
)


# ============================================================
# RECOVER UNACKNOWLEDGED EVENT B
#
# DurableEventSpool.replay_events():
#
# callback success -> automatic ACK
# callback failure -> remains pending
# ============================================================

print()
print(
    "=== P11.11-06 RECOVER EVENT B ==="
)

recovered = []


def recovery_callback(event):

    recovered.append(
        event
    )

    published = bus2.publish(
        event
    )

    return published


replayed_count = (
    spool2.replay_events(
        recovery_callback
    )
)

print(
    "REPLAYED_COUNT=",
    replayed_count,
)

print(
    "RECOVERED_COUNT=",
    len(recovered),
)

print(
    "RECOVERED_IDS=",
    [
        event.event_id
        for event in recovered
    ],
)

print(
    "BUS_SIZE_AFTER_RECOVERY=",
    bus2.size(),
)

print(
    "PENDING_AFTER_RECOVERY=",
    len(
        spool2.pending_records()
    ),
)


# ============================================================
# VERIFY EVENT A WAS NOT RECOVERED
# ============================================================

print()
print(
    "=== P11.11-07 ACKED EVENT NOT REPLAYED ==="
)

recovered_ids = [
    event.event_id
    for event in recovered
]

print(
    "EVENT_A_REPLAYED=",
    event_a.event_id in recovered_ids,
)

print(
    "EVENT_B_REPLAYED=",
    event_b.event_id in recovered_ids,
)


# ============================================================
# DISPATCH RECOVERED EVENT
# ============================================================

print()
print(
    "=== P11.11-08 DISPATCH RECOVERED ==="
)

consumer_events = []

bus2.subscribe(
    lambda event: consumer_events.append(
        event
    )
)

bus2.dispatch_all()

print(
    "CONSUMER_RECEIVED=",
    len(consumer_events),
)

print(
    "CONSUMER_IDS=",
    [
        event.event_id
        for event in consumer_events
    ],
)

print(
    "BUS_AFTER_DISPATCH=",
    bus2.size(),
)


# ============================================================
# RECOVERED EVENT ACK VERIFICATION
#
# IMPORTANT:
# replay_events() automatically ACKs the record after
# successful callback execution.
#
# Therefore pipeline.ack(EVENT_B) is expected to return False
# because EVENT_B has already been ACKed by the spool recovery.
# ============================================================

print()
print(
    "=== P11.11-09 VERIFY RECOVERED EVENT ALREADY ACKED ==="
)

ack_b_after_recovery = pipeline2.ack(
    event_b.event_id
)

print(
    "ACK_EVENT_B_AFTER_RECOVERY=",
    ack_b_after_recovery,
)

print(
    "RECOVERY_ALREADY_ACKED=",
    (
        ack_b_after_recovery is False
        and len(
            spool2.pending_records()
        ) == 0
    ),
)

print(
    "PENDING_AFTER_RECOVERY_ACK_CHECK=",
    len(
        spool2.pending_records()
    ),
)


# ============================================================
# SECOND RECOVERY MUST BE EMPTY
# ============================================================

print()
print(
    "=== P11.11-10 SECOND RECOVERY ==="
)

second_recovered = []

second_count = (
    spool2.replay_events(
        lambda event:
            second_recovered.append(
                event
            )
    )
)

print(
    "SECOND_REPLAY_COUNT=",
    second_count,
)

print(
    "SECOND_RECOVERED_COUNT=",
    len(second_recovered),
)

print(
    "PENDING_FINAL=",
    len(
        spool2.pending_records()
    ),
)


# ============================================================
# REPLAY GUARD CHECK
# ============================================================

print()
print(
    "=== P11.11-11 REPLAY GUARD ==="
)

print(
    "EVENT_A_TRACKED=",
    replay2.contains(
        event_a.event_id
    ),
)

print(
    "EVENT_B_TRACKED=",
    replay2.contains(
        event_b.event_id
    ),
)

print(
    "REPLAY_STATS=",
    replay2.get_stats(),
)


# ============================================================
# PIPELINE / SPOOL STATS
# ============================================================

print()
print(
    "=== P11.11-12 STATS ==="
)

print(
    "PIPELINE_STATS=",
    pipeline2.get_stats(),
)

print(
    "SPOOL_STATS=",
    spool2.get_stats(),
)

print(
    "BUS_STATS=",
    bus2.get_stats(),
)


# ============================================================
# HEALTH
# ============================================================

print()
print(
    "=== P11.11-13 HEALTH ==="
)

print(
    "REPLAY_HEALTH=",
    replay2.health_check(),
)

print(
    "PIPELINE_HEALTH=",
    pipeline2.health_check(),
)


# ============================================================
# FINAL ASSERTIONS
# ============================================================

print()
print(
    "=== P11.11-14 FINAL ASSERTIONS ==="
)


# First process accepted both events.
assert accepted_a is True
assert accepted_b is True


# Event A was ACKed before crash.
assert ack_a is True


# After restart:
# A must NOT be pending.
# B MUST be pending.
assert event_a.event_id not in pending_ids
assert event_b.event_id in pending_ids


# Exactly one event must be recovered.
assert replayed_count == 1
assert len(recovered) == 1


# A must never be replayed.
# B must be replayed.
assert event_a.event_id not in recovered_ids
assert event_b.event_id in recovered_ids


# Recovery callback succeeded, therefore spool automatically
# ACKed B. Calling pipeline.ack() afterwards must return False.
assert ack_b_after_recovery is False
assert len(spool2.pending_records()) == 0


# A second recovery must find nothing.
assert second_count == 0
assert len(second_recovered) == 0


# Final durable state must be empty.
assert len(spool2.pending_records()) == 0


# Replay state must still know both event IDs.
assert replay2.contains(
    event_a.event_id
)

assert replay2.contains(
    event_b.event_id
)


print(
    "ALL_ASSERTIONS_PASS=True"
)

print(
    "TEST_COMPLETE=True"
)
