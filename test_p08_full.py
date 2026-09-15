from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.storage.durable_spool import DurableEventSpool
from agent.core.durable_event_pipeline import DurableEventPipeline
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.engine import CorrelationEngine
from agent.correlation.adapter import CorrelationAdapter


path = Path("state/test_p08_full")

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
    event_type="P08_FULL_PIPELINE",
    severity="HIGH",
    value=95,
    source="FullPipelineTest",
    message="Full durable pipeline test",
    host_id="host-p08",
    sensor_id="sensor-p08",
)

print(
    "INGEST=",
    pipeline.ingest(event)
)

print(
    "PENDING_BEFORE_DISPATCH=",
    len(spool.pending_records())
)

print(
    "BUS_BEFORE_DISPATCH=",
    bus.size()
)

bus.dispatch_all()

print(
    "BUS_AFTER_DISPATCH=",
    bus.size()
)

print(
    "PENDING_AFTER_DISPATCH=",
    len(spool.pending_records())
)

print(
    "BRIDGE_STATS=",
    bridge.get_stats()
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
    "SPOOL_STATS=",
    spool.get_stats()
)