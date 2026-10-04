from __future__ import annotations

from typing import Any, Optional

from .threat_signals import ThreatSignalEngine


class RuleEngine:
    """
    CyberDefender Rule Engine.

    Vazifasi:
    - EventBus orqali kelgan snapshotlarni tahlil qilish
    - konfiguratsiyadagi thresholdlar asosida detection yaratish
    - tizimga hech qanday o'zgartirish kiritmaslik

    Bu engine:
    - process o'ldirmaydi
    - networkni uzmaydi
    - firewallni o'zgartirmaydi
    - fayllarni o'zgartirmaydi
    - faqat detection yaratadi
    """

    NAME = "RuleEngine"
    VERSION = "1.0"

    DEFAULT_THRESHOLDS = {
        "memory_warning": 85.0,
        "memory_critical": 95.0,

        "cpu_warning": 85.0,
        "cpu_critical": 95.0,

        "process_warning": 300,
        "process_critical": 400,

        "available_memory_warning": 1024.0,
        "available_memory_critical": 512.0,
    }

    def __init__(
        self,
        config: Optional[dict[str, Any]] = None,
    ):
        self.thresholds = self._load_thresholds(config)
        self.threat_signals = ThreatSignalEngine(config)

        self._analyzed_count = 0
        self._detection_count = 0

    def _load_thresholds(
        self,
        config: Optional[dict[str, Any]],
    ) -> dict[str, float]:
        """
        Config'dan thresholdlarni oladi.

        Config noto'g'ri yoki yetishmayotgan bo'lsa,
        xavfsiz default qiymatlar ishlatiladi.
        """

        thresholds = dict(
            self.DEFAULT_THRESHOLDS
        )

        if not isinstance(config, dict):
            return thresholds

        detection_config = config.get(
            "detection",
            {},
        )

        if not isinstance(
            detection_config,
            dict,
        ):
            return thresholds

        for name in thresholds:
            value = detection_config.get(
                name
            )

            if value is None:
                continue

            try:
                numeric_value = float(value)

                if numeric_value >= 0:
                    thresholds[name] = numeric_value

            except (TypeError, ValueError):
                continue

        return thresholds

    def analyze(
        self,
        snapshot: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Host snapshotni rule-based tahlil qiladi.
        """

        self._analyzed_count += 1

        if not isinstance(snapshot, dict):
            return []

        detections = []

        self._check_memory(
            snapshot,
            detections,
        )

        self._check_cpu(
            snapshot,
            detections,
        )

        self._check_processes(
            snapshot,
            detections,
        )

        self._check_available_memory(
            snapshot,
            detections,
        )

        self._detection_count += len(
            detections
        )

        return detections

    def analyze_event(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        EventBus'dan kelgan eventni tahlil qiladi.

        Faqat HOST_SNAPSHOT eventlari tahlil qilinadi.
        """

        if not isinstance(event, dict):
            return []

        if event.get("event_type") != "HOST_SNAPSHOT":
            return self.threat_signals.analyze_event(event)

        data = event.get("data")

        if not isinstance(data, dict):
            return []

        return self.analyze(data)

    def _check_memory(
        self,
        snapshot: dict[str, Any],
        detections: list[dict[str, Any]],
    ) -> None:

        memory = self._number(
            snapshot.get("memory_percent")
        )

        if memory is None:
            return

        critical = self.thresholds[
            "memory_critical"
        ]

        warning = self.thresholds[
            "memory_warning"
        ]

        if memory >= critical:
            detections.append(
                self._detection(
                    event_type="HIGH_MEMORY_USAGE",
                    severity="CRITICAL",
                    value=memory,
                    message=(
                        f"Memory usage juda yuqori: "
                        f"{memory}%"
                    ),
                )
            )

        elif memory >= warning:
            detections.append(
                self._detection(
                    event_type="HIGH_MEMORY_USAGE",
                    severity="WARNING",
                    value=memory,
                    message=(
                        f"Memory usage yuqori: "
                        f"{memory}%"
                    ),
                )
            )

    def _check_cpu(
        self,
        snapshot: dict[str, Any],
        detections: list[dict[str, Any]],
    ) -> None:

        cpu = self._number(
            snapshot.get("cpu_percent")
        )

        if cpu is None:
            return

        critical = self.thresholds[
            "cpu_critical"
        ]

        warning = self.thresholds[
            "cpu_warning"
        ]

        if cpu >= critical:
            detections.append(
                self._detection(
                    event_type="HIGH_CPU_USAGE",
                    severity="CRITICAL",
                    value=cpu,
                    message=(
                        f"CPU usage juda yuqori: "
                        f"{cpu}%"
                    ),
                )
            )

        elif cpu >= warning:
            detections.append(
                self._detection(
                    event_type="HIGH_CPU_USAGE",
                    severity="WARNING",
                    value=cpu,
                    message=(
                        f"CPU usage yuqori: "
                        f"{cpu}%"
                    ),
                )
            )

    def _check_processes(
        self,
        snapshot: dict[str, Any],
        detections: list[dict[str, Any]],
    ) -> None:

        count = self._number(
            snapshot.get("process_count")
        )

        if count is None:
            return

        critical = self.thresholds[
            "process_critical"
        ]

        warning = self.thresholds[
            "process_warning"
        ]

        if count >= critical:
            detections.append(
                self._detection(
                    event_type="HIGH_PROCESS_COUNT",
                    severity="CRITICAL",
                    value=count,
                    message=(
                        f"Processlar soni juda yuqori: "
                        f"{int(count)}"
                    ),
                )
            )

        elif count >= warning:
            detections.append(
                self._detection(
                    event_type="HIGH_PROCESS_COUNT",
                    severity="WARNING",
                    value=count,
                    message=(
                        f"Processlar soni yuqori: "
                        f"{int(count)}"
                    ),
                )
            )

    def _check_available_memory(
        self,
        snapshot: dict[str, Any],
        detections: list[dict[str, Any]],
    ) -> None:

        available = self._number(
            snapshot.get(
                "memory_available_mb"
            )
        )

        if available is None:
            return

        critical = self.thresholds[
            "available_memory_critical"
        ]

        warning = self.thresholds[
            "available_memory_warning"
        ]

        if available <= critical:
            detections.append(
                self._detection(
                    event_type="LOW_AVAILABLE_MEMORY",
                    severity="CRITICAL",
                    value=available,
                    message=(
                        f"Available memory juda kam: "
                        f"{available} MB"
                    ),
                )
            )

        elif available <= warning:
            detections.append(
                self._detection(
                    event_type="LOW_AVAILABLE_MEMORY",
                    severity="WARNING",
                    value=available,
                    message=(
                        f"Available memory kam: "
                        f"{available} MB"
                    ),
                )
            )

    @staticmethod
    def _number(
        value: Any,
    ) -> Optional[float]:
        """
        Qiymatni xavfsiz numeric formatga o'tkazadi.
        """

        if value is None:
            return None

        try:
            number = float(value)

            if number != number:
                return None

            return number

        except (TypeError, ValueError):
            return None

    def _detection(
        self,
        event_type: str,
        severity: str,
        value: float,
        message: str,
    ) -> dict[str, Any]:

        return {
            "type": event_type,
            "severity": severity,
            "value": value,
            "source": self.NAME,
            "message": message,
        }

    def get_stats(self) -> dict[str, Any]:
        """
        Rule Engine statistikasi.
        """

        return {
            "engine": self.NAME,
            "version": self.VERSION,
            "analyzed": self._analyzed_count,
            "detections": self._detection_count,
            "thresholds": dict(
                self.thresholds
            ),
            "threat_signals": self.threat_signals.health_check(),
        }

    def health_check(self) -> dict[str, Any]:
        """Expose the existing RuleEngine health contract plus threat telemetry."""
        threat = self.threat_signals.health_check()
        return {
            "component": self.NAME,
            "version": self.VERSION,
            "status": "HEALTHY" if threat.get("status") == "HEALTHY" else "DEGRADED",
            "analyzed": self._analyzed_count,
            "detections": self._detection_count,
            "threat_signals": threat,
            "fail_closed": True,
            "authorization": "NOT_GRANTED",
        }
