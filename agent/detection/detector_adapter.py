from __future__ import annotations

from typing import Any

from agent.bus.event_bus import EventBus
from agent.detection.detector import Detector


class DetectorAdapter:
    """
    Detector <-> EventBus bridge.

    Vazifasi:
    - EventBus eventlarini qabul qilish
    - Detector orqali tahlil qilish
    - Detection natijalarini EventBus'ga qayta publish qilish
    """

    VERSION = "1.0"

    def __init__(
        self,
        detector: Detector,
        event_bus: EventBus,
    ):
        if detector is None:
            raise ValueError(
                "detector berilishi kerak"
            )

        if event_bus is None:
            raise ValueError(
                "event_bus berilishi kerak"
            )

        self.detector = detector
        self.event_bus = event_bus

        self._received = 0
        self._published = 0
        self._failed = 0

        self.event_bus.subscribe(
            self.handle_event
        )

    def health_check(self) -> dict:
        return {
            "adapter": "DetectorAdapter",
            "status": "HEALTHY",
            "version": self.VERSION,
        }

    def handle_event(
        self,
        event: Any,
    ) -> None:
        """
        EventBus subscriber callback.

        Muhim:
        Detection eventning o'zi qayta
        Detector'ga tushib infinite loop
        hosil qilmasligi uchun
        DETECTION eventlari ignore qilinadi.
        """

        if not isinstance(event, dict):
            return

        event_type = event.get(
            "event_type"
        )

        if event_type == "DETECTION":
            return

        self._received += 1

        try:
            detections = self.detector.handle_event(
                event
            )

            for detection in detections:
                detection_event = {
                    "event_type": "DETECTION",
                    "source": "DetectorAdapter",
                    "severity": detection.get(
                        "severity",
                        "INFO"
                    ),
                    "data": detection,
                }

                if self.event_bus.publish(
                    detection_event
                ):
                    self._published += 1

        except Exception:
            self._failed += 1

    def get_stats(self) -> dict:
        return {
            "adapter": "DetectorAdapter",
            "version": self.VERSION,
            "received": self._received,
            "published": self._published,
            "failed": self._failed,
        }