from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.engine import CorrelationEngine
from agent.correlation.adapter import CorrelationAdapter


bus = EventBus(
    max_size=100
)

engine = CorrelationEngine()

adapter = CorrelationAdapter(
    engine=engine,
    event_bus=bus,
)

bridge = SecurityEventBridge(
    output_callback=adapter.handle_event
)

bus.subscribe(
    bridge.handle_event
)


event = SecurityEvent(
    event_type="P08_BRIDGE_CORRELATION",
    severity="HIGH",
    value=91,
    source="BridgeTestSensor",
    message="Bridge to correlation test",
    host_id="host-p08",
    sensor_id="sensor-p08",
)


print(
    "PUBLISH_SECURITY_EVENT=",
    bus.publish(event)
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
