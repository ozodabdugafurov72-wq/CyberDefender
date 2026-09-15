from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline


path = Path("state/test_p09_recovery")

shutil.rmtree(
    path,
    ignore_errors=True,
)


# =========================================================
# PROCESS 1
# Event ingest qilinadi.
# Event durable spool'ga yoziladi.
# Lekin EventBus dispatch qilinmaydi.
# Bu crash holatini simulyatsiya qiladi.
# =========================================================

bus1 = EventBus(
    max_size=10
)

spool1 = DurableEventSpool(
    path
)

pipeline1 = DurableEventPipeline(
    spool=spool1,
    event_bus=bus1,
)

event = SecurityEvent(
    event_type="P09_CRASH_RECOVERY",
    severity="CRITICAL",
    value=999,
    source="RecoveryTest",
    message="Crash before processing",
    host_id="host-p09",
    sensor_id="sensor-p09",
)

print(
    "PROCESS1_INGEST=",
    pipeline1.ingest(event)
)

print(
    "PROCESS1_PENDING=",
    len(spool1.pending_records())
)

print(
    "PROCESS1_EVENT_ID=",
    event.event_id
)


# =========================================================
# PROCESS 1 crash
#
# Biz bus1/pipeline1 ni tashlab,
# yangi process holatini simulyatsiya qilamiz.
# =========================================================

del pipeline1
del spool1
del bus1


# =========================================================
# PROCESS 2 / RESTART
# =========================================================

bus2 = EventBus(
    max_size=10
)

spool2 = DurableEventSpool(
    path
)

pipeline2 = DurableEventPipeline(
    spool=spool2,
    event_bus=bus2,
)


print(
    "PROCESS2_RECOVERED_PENDING=",
    len(spool2.pending_records())
)

recovered = spool2.pending_events()

print(
    "PROCESS2_RECOVERED_EVENT_ID=",
    recovered[0].event_id
    if recovered
    else None
)

print(
    "PROCESS2_INTEGRITY=",
    recovered[0].verify_integrity()
    if recovered
    else None
)


# =========================================================
# Replay
# =========================================================

seen = []


def replay_consumer(event):
    seen.append(
        event.event_id
    )


processed = spool2.replay_events(
    replay_consumer
)


print(
    "REPLAYED=",
    processed
)

print(
    "SEEN=",
    seen
)

print(
    "PENDING_AFTER_REPLAY=",
    len(
        spool2.pending_records()
    )
)

print(
    "PIPELINE_STATS=",
    pipeline2.get_stats()
)

print(
    "SPOOL_STATS=",
    spool2.get_stats()
)