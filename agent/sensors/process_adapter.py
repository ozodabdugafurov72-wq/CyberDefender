from agent.sensors.process import ProcessSensor


class ProcessSensorAdapter:
    """
    ProcessSensor -> EventBus adapter.

    OBSERVE-only.
    Sensor ma'lumotlarini SecurityEvent sifatida EventBus'ga yuboradi.
    """

    VERSION = "1.0"

    def __init__(self, sensor: ProcessSensor, event_bus):
        self.sensor = sensor
        self.event_bus = event_bus

        self.published = 0
        self.failed = 0

    def collect_and_publish(self):
        try:
            snapshot = self.sensor.collect()

            event = {
                "event_type": "PROCESS_SNAPSHOT",
                "severity": "INFO",
                "timestamp": snapshot["timestamp"],
                "source": "ProcessSensorAdapter",
                "data": snapshot,
            }

            published = self.event_bus.publish(event)

            if published:
                self.published += 1
            else:
                self.failed += 1

            return published

        except Exception:
            self.failed += 1
            return False

    def get_stats(self):
        return {
            "adapter": "ProcessSensorAdapter",
            "version": self.VERSION,
            "published": self.published,
            "failed": self.failed,
        }