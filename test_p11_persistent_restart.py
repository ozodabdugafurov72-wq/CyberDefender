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
    "state/test_p11_10_restart"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)


# ============================================================
# SHARED STORAGE
# ============================================================

storage_key = (
    generate_storage_key()
)

key_root = (
    ROOT / "keys"
)

replay_root = (
    ROOT / "replay"
)

spool_root = (
    ROOT / "spool"
)


# ============================================================
# PROCESS 1
# ============================================================

print(
    "=== P11.10-01 PROCESS 1 ==="
)

bus1 = EventBus(
    10
)

key_manager1 = KeyManager(
    key_root,
    storage_key,
)

key_id1 = (
    key_manager1.generate_key()
)

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

gateway1 = (
    CryptoReplayAdmissionGateway(
        key_manager1,
        replay1,
        pipeline1,
    )
)

event1 = SecurityEvent(
    event_type="P11_10_RESTART_EVENT",
    severity="HIGH",
    value=88,
    source="P11.10TestSensor",
    message="Persistent replay restart test",
    confidence=0.99,
    host_id="host-p11-10",
    sensor_id="sensor-p11-10",
)

envelope1 = (
    gateway1.sign_event(
        event1
    )
)

accepted1 = gateway1.admit(
    event1,
    envelope1["key_id"],
    envelope1["signature"],
)

print(
    "FIRST_ACCEPT=",
    accepted1,
)

print(
    "EVENT_ID=",
    event1.event_id,
)

print(
    "REPLAY_SIZE_PROCESS1=",
    replay1.size(),
)

print(
    "REPLAY_CONTAINS_PROCESS1=",
    replay1.contains(
        event1.event_id
    ),
)

print(
    "READY_PROCESS1=",
    replay1.is_ready(),
)

print(
    "PENDING_PROCESS1=",
    len(
        spool1.pending_records()
    ),
)


# ============================================================
# VERIFY PERSISTED STATE
# ============================================================

print()
print(
    "=== P11.10-02 PERSISTED STATE ==="
)

state_files = list(
    replay_root.glob("*")
)

print(
    "STATE_FILES=",
    [
        p.name
        for p in state_files
        if p.is_file()
    ],
)

print(
    "STATE_FILE_COUNT=",
    len(
        [
            p
            for p in state_files
            if p.is_file()
        ]
    ),
)


# ============================================================
# SIMULATED PROCESS SHUTDOWN
# ============================================================

print()
print(
    "=== P11.10-03 PROCESS 1 SHUTDOWN ==="
)

del gateway1
del pipeline1
del spool1
del replay1
del key_manager1
del bus1

print(
    "PROCESS1_SHUTDOWN=True"
)


# ============================================================
# PROCESS 2 / RESTART
# ============================================================

print()
print(
    "=== P11.10-04 PROCESS 2 RESTART ==="
)

bus2 = EventBus(
    10
)

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

gateway2 = (
    CryptoReplayAdmissionGateway(
        key_manager2,
        replay2,
        pipeline2,
    )
)

print(
    "RECOVERED_SIZE=",
    replay2.size(),
)

print(
    "RECOVERED_CONTAINS=",
    replay2.contains(
        event1.event_id
    ),
)

print(
    "READY_AFTER_RESTART=",
    replay2.is_ready(),
)

print(
    "STATUS_AFTER_RESTART=",
    replay2.get_status(),
)


# ============================================================
# REPLAY AFTER RESTART
# ============================================================

print()
print(
    "=== P11.10-05 REPLAY AFTER RESTART ==="
)

replay_after_restart = (
    gateway2.admit(
        event1,
        envelope1["key_id"],
        envelope1["signature"],
    )
)

print(
    "REPLAY_ACCEPT=",
    replay_after_restart,
)

print(
    "SPOOL_PENDING_AFTER_REPLAY=",
    len(
        spool2.pending_records()
    ),
)

print(
    "BUS_SIZE_AFTER_REPLAY=",
    bus2.size(),
)

print(
    "REPLAY_STATS_AFTER_REPLAY=",
    replay2.get_stats(),
)


# ============================================================
# NEW EVENT AFTER RESTART
# ============================================================

print()
print(
    "=== P11.10-06 NEW EVENT AFTER RESTART ==="
)

event2 = SecurityEvent(
    event_type="P11_10_NEW_AFTER_RESTART",
    severity="CRITICAL",
    value=100,
    source="P11.10TestSensor",
    message="New event after restart",
    confidence=1.0,
    host_id="host-p11-10",
    sensor_id="sensor-p11-10",
)

envelope2 = (
    gateway2.sign_event(
        event2
    )
)

new_after_restart = gateway2.admit(
    event2,
    envelope2["key_id"],
    envelope2["signature"],
)

print(
    "NEW_ACCEPT=",
    new_after_restart,
)

print(
    "NEW_EVENT_ID=",
    event2.event_id,
)

print(
    "REPLAY_SIZE_AFTER_NEW=",
    replay2.size(),
)

print(
    "PENDING_AFTER_NEW=",
    len(
        spool2.pending_records()
    ),
)

print(
    "BUS_AFTER_NEW=",
    bus2.size(),
)


# ============================================================
# DISPATCH
# ============================================================

print()
print(
    "=== P11.10-07 DISPATCH ==="
)

received = []

bus2.subscribe(
    lambda event: received.append(
        event
    )
)

bus2.dispatch_all()

print(
    "RECEIVED=",
    len(received),
)

print(
    "BUS_AFTER_DISPATCH=",
    bus2.size(),
)


# ============================================================
# ACK
# ============================================================

print()
print(
    "=== P11.10-08 ACK ==="
)

ack_count = 0

for received_event in received:

    if pipeline2.ack(
        received_event.event_id
    ):
        ack_count += 1

print(
    "ACK_COUNT=",
    ack_count,
)

print(
    "PENDING_AFTER_ACK=",
    len(
        spool2.pending_records()
    ),
)


# ============================================================
# STATE TAMPER
# ============================================================

print()
print(
    "=== P11.10-09 STATE TAMPER ==="
)

state_path = (
    replay_root
    / "replay_state.json"
)

if state_path.exists():

    original_state = (
        state_path.read_text(
            encoding="utf-8"
        )
    )

    state_path.write_text(
        original_state.replace(
            '"event_id"',
            '"tampered_event_id"',
            1,
        ),
        encoding="utf-8",
    )

else:

    state_path = None

    print(
        "STATE_PATH_NOT_FOUND=True"
    )


# ============================================================
# PROCESS 3 AFTER TAMPER
# ============================================================

print()
print(
    "=== P11.10-10 PROCESS 3 AFTER TAMPER ==="
)

if state_path is not None:

    replay3 = PersistentReplayGuard(
        replay_root,
        max_entries=100000,
    )

    print(
        "TAMPERED_SIZE=",
        replay3.size(),
    )

    print(
        "TAMPERED_READY=",
        replay3.is_ready(),
    )

    print(
        "TAMPERED_DEGRADED=",
        replay3.is_degraded(),
    )

    print(
        "TAMPERED_HEALTH=",
        replay3.health_check(),
    )

    print(
        "TAMPERED_STATS=",
        replay3.get_stats(),
    )

    tampered_event = SecurityEvent(
        event_type="P11_10_TAMPER_TEST",
        severity="CRITICAL",
        value=999,
        source="P11.10TamperTest",
        message="Must fail closed",
        confidence=1.0,
        host_id="host-p11-10",
        sensor_id="sensor-p11-10",
    )

    # Directly test degraded replay guard.
    tampered_accept = (
        replay3.check_and_remember(
            tampered_event.event_id
        )
    )

    print(
        "NEW_EVENT_ACCEPT_AFTER_TAMPER=",
        tampered_accept,
    )

    print(
        "SIZE_AFTER_TAMPER_ATTEMPT=",
        replay3.size(),
    )


# ============================================================
# FINAL STATS
# ============================================================

print()
print(
    "=== P11.10-11 FINAL STATS ==="
)

print(
    "GATEWAY2_STATS=",
    gateway2.get_stats(),
)

print(
    "PIPELINE2_STATS=",
    pipeline2.get_stats(),
)

print(
    "SPOOL2_STATS=",
    spool2.get_stats(),
)

print(
    "BUS2_STATS=",
    bus2.get_stats(),
)

print(
    "REPLAY2_STATS=",
    replay2.get_stats(),
)


# ============================================================
# FINAL
# ============================================================

print()
print(
    "=== P11.10-12 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
