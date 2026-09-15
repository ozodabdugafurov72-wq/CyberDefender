from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.engine import CorrelationEngine
from agent.correlation.adapter import CorrelationAdapter


path = Path(
    "state/test_p10_duplicate"
)

shutil.rmtree(
    path,
    ignore_errors=True,
)

bus = EventBus(
    max_size=100
)

spool = DurableEventSpool(
    path
)

pipeline = DurableEventPipeline(
    spool=spool,
    event_bus=bus
)

engine = CorrelationEngine()

adapter = CorrelationAdapter(
    engine=engine,
    event_bus=bus,
    ack_callback=pipeline.ack,
)

bridge = SecurityEventBridge(
    output_callback=adapter.handle_event
)

bus.subscribe(
    bridge.handle_event
)


event = SecurityEvent(
    event_type="P10_DUPLICATE_TEST",
    severity="HIGH",
    value=80,
    source="DuplicateTest",
    message="Duplicate replay test",
    host_id="host-p10",
    sensor_id="sensor-p10",
)


print(
    "FIRST_INGEST=",
    pipeline.ingest(event)
)

bus.dispatch_all()

print(
    "PENDING_AFTER_FIRST=",
    len(
        spool.pending_records()
    )
)

print(
    "ENGINE_AFTER_FIRST=",
    engine.get_stats()
)


print(
    "SECOND_INGEST=",
    pipeline.ingest(event)
)

bus.dispatch_all()

print(
    "PENDING_AFTER_SECOND=",
    len(
        spool.pending_records()
    )
)

print(
    "ENGINE_AFTER_SECOND=",
    engine.get_stats()
)

print(
    "ADAPTER_STATS=",
    adapter.get_stats()
)

print(
    "PIPELINE_STATS=",
    pipeline.get_stats()
)

print(
    "SPOOL_STATS=",
    spool.get_stats()
)