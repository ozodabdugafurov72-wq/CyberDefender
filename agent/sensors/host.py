from __future__ import annotations

import time
from typing import Any, Optional

import psutil


class HostSensor:
    """
    CyberDefender Host Sensor.

    Vazifasi:
    - host tizimining asosiy holatini kuzatish
    - CPU
    - RAM
    - available RAM
    - process count
    - network I/O

    Muhim:
    - tizimni o'zgartirmaydi
    - processlarni o'ldirmaydi
    - fayllarni o'zgartirmaydi
    - network konfiguratsiyasiga tegmaydi
    - firewallga tegmaydi
    - faqat kuzatadi

    Sensor keyinchalik EventBus orqali boshqa
    modullarga ma'lumot uzatishi mumkin.
    """

    NAME = "HostSensor"
    VERSION = "1.0"

    def __init__(
        self,
        cpu_interval: Optional[float] = None,
    ):
        if cpu_interval is not None:
            if not isinstance(cpu_interval, (int, float)):
                raise TypeError(
                    "cpu_interval son bo'lishi kerak"
                )

            if cpu_interval < 0:
                raise ValueError(
                    "cpu_interval manfiy bo'lishi mumkin emas"
                )

        self.cpu_interval = cpu_interval

        self._last_network = None
        self._last_network_time = None

    def collect(self) -> dict[str, Any]:
        """
        Host snapshot qaytaradi.

        Natija:
            {
                "sensor": "HostSensor",
                "version": "1.0",
                "timestamp": ...,
                "cpu_percent": ...,
                "memory_percent": ...,
                "memory_available_mb": ...,
                "process_count": ...,
                "network_sent_mb": ...,
                "network_recv_mb": ...
            }
        """

        timestamp = time.time()

        cpu_percent = self._get_cpu_usage()
        memory = self._get_memory_usage()
        process_count = self._get_process_count()
        network = self._get_network_usage()

        return {
            "sensor": self.NAME,
            "version": self.VERSION,
            "timestamp": timestamp,

            "cpu_percent": cpu_percent,

            "memory_percent": memory["percent"],
            "memory_available_mb": memory["available_mb"],

            "process_count": process_count,

            "network_sent_mb": network["sent_mb"],
            "network_recv_mb": network["recv_mb"],
        }

    def _get_cpu_usage(self) -> float:
        """
        CPU usage.
        """

        try:
            value = psutil.cpu_percent(
                interval=self.cpu_interval
            )

            return round(float(value), 2)

        except Exception:
            return 0.0

    def _get_memory_usage(self) -> dict[str, float]:
        """
        RAM holatini oladi.
        """

        try:
            memory = psutil.virtual_memory()

            return {
                "percent": round(
                    float(memory.percent),
                    2,
                ),
                "available_mb": round(
                    float(memory.available)
                    / (1024 * 1024),
                    2,
                ),
            }

        except Exception:
            return {
                "percent": 0.0,
                "available_mb": 0.0,
            }

    def _get_process_count(self) -> int:
        """
        Ishlayotgan processlar soni.
        """

        try:
            return len(
                psutil.pids()
            )

        except Exception:
            return 0

    def _get_network_usage(self) -> dict[str, float]:
        """
        Umumiy network I/O hisoblagichlari.
        """

        try:
            counters = psutil.net_io_counters()

            return {
                "sent_mb": round(
                    float(counters.bytes_sent)
                    / (1024 * 1024),
                    2,
                ),
                "recv_mb": round(
                    float(counters.bytes_recv)
                    / (1024 * 1024),
                    2,
                ),
            }

        except Exception:
            return {
                "sent_mb": 0.0,
                "recv_mb": 0.0,
            }

    def health_check(self) -> dict[str, Any]:
        """
        Sensorning o'zi sog'lom ishlayotganini tekshiradi.

        Bu detection emas.
        Bu sensor health status.
        """

        try:
            psutil.cpu_count()

            return {
                "sensor": self.NAME,
                "status": "HEALTHY",
            }

        except Exception as error:
            return {
                "sensor": self.NAME,
                "status": "DEGRADED",
                "error": str(error),
            }