from __future__ import annotations

import time
from typing import Optional

from agent.sensors.host import HostSensor
from agent.bus.event_bus import EventBus


class HostSensorAdapter:
    """
    HostSensor -> EventBus adapter.

    Vazifasi:
    - HostSensor'dan snapshot olish
    - snapshot'ni EventBus orqali uzatish
    - sensor va bus o'rtasidagi coupling'ni kamaytirish

    Bu modul:
    - tizimni o'zgartirmaydi
    - processlarni to'xtatmaydi
    - fayllarni o'zgartirmaydi
    - network konfiguratsiyasiga tegmaydi
    """

    NAME = "HostSensorAdapter"
    VERSION = "1.0"

    def __init__(
        self,
        sensor: Optional[HostSensor] = None,
        event_bus: Optional[EventBus] = None,
    ):
        self.sensor = sensor or HostSensor()
        self.event_bus = event_bus or EventBus()

        self._published_count = 0
        self._failed_count = 0

    def collect_and_publish(self) -> bool:
        """
        Host snapshot oladi va EventBus'ga yuboradi.

        Returns:
            True  -> event muvaffaqiyatli yuborildi
            False -> yuborishda xatolik
        """

        try:
            snapshot = self.sensor.collect()

            event = {
                "event_type": "HOST_SNAPSHOT",
                "source": self.NAME,
                "version": self.VERSION,
                "timestamp": time.time(),
                "data": snapshot,
            }

            published = self.event_bus.publish(event)

            if published:
                self._published_count += 1
                return True

            self._failed_count += 1
            return False

        except Exception:
            self._failed_count += 1
            return False

    def get_stats(self) -> dict:
        """
        Adapter statistikasi.
        """

        return {
            "adapter": self.NAME,
            "version": self.VERSION,
            "published": self._published_count,
            "failed": self._failed_count,
        }