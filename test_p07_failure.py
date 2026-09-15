from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline

from pathlib import Path
import shutil


path = Path("state/test_p07_real_failure")

shutil.rmtree(
    path,
    ignore_errors=True,
)

bus = EventBus(10)

spool = DurableEventSpool(
    path
)

pipeline = DurableEventPipeline(
    spool,
    bus
)

received = []


def consumer(event):
    received.append(
        event.event_id
    )

    raise RuntimeError(
        "simulated consumer failure"
    )


bus.subscribe(
    consumer
)


event = SecurityEvent(
    event_type="P07_REAL_CONSUMER_FAILURE",
    severity="CRITICAL",
    value=999,
    source="TestConsumer",
    message="Real consumer failure test",
)


print(
    "INGEST=",
    pipeline.ingest(event)
)


bus.dispatch_all()


print(
    "CONSUMER_CALLED=",
    len(received)
)


print(
    "PENDING_AFTER_FAILURE=",
    len(spool.pending_records())
)


print(
    "ACKED=",
    spool.get_stats()["acked"]
)


print(
    "PIPELINE_STATS=",
    pipeline.get_stats()
)
