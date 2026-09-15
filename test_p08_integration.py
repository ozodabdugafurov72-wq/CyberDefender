from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.engine import CorrelationEngine
from agent.correlation.adapter import CorrelationAdapter


path = Path("state/test_p08_integration")

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
    event_bus=bus,
)

engine = CorrelationEngine(
    host_id="host-p08",
)

adapter = CorrelationAdapter(
    engine=engine,
    event_bus=bus,
    ack_callback=pipeline.ack,
)


event = SecurityEvent(
    event_type="P08_INTEGRATION_TEST",
    severity="HIGH",
    value=88,
    source="TestSensor",
    message="P0.8 full integration test",
    host_id="host-p08",
    sensor_id="sensor-p08",
)


detection = SecurityEventBridge.to_detection(
    event
)

print(
    "BRIDGE_EVENT_TYPE=",
    detection["event_type"],
)

print(
    "BRIDGE_EVENT_ID=",
    detection["event_id"],
)


print(
    "INGEST=",
    pipeline.ingest(event)
)


print(
    "SPOOL_BEFORE_DISPATCH=",
    len(spool.pending_records())
)


print(
    "BUS_BEFORE_DISPATCH=",
    bus.size()
)


bus.dispatch_all()


print(
    "SPOOL_AFTER_DISPATCH=",
    len(spool.pending_records())
)


print(
    "ADAPTER_STATS=",
    adapter.get_stats()
)


print(
    "ENGINE_STATS=",
    engine.get_stats()
)


print(
    "PIPELINE_STATS=",
    pipeline.get_stats()
)


print(
    "BUS_STATS=",
    bus.get_stats()
)


print(
    "SPOOL_STATS=",
    spool.get_stats()
)
