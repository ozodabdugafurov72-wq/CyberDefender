import time
import psutil


class ProcessSensor:
    """
    CyberDefender Process Sensor.

    OBSERVE-only:
    - processlarni kuzatadi
    - PID/PPID munosabatlarini yig'adi
    - CPU/RAM statistikalarini oladi
    - hech qanday processni o'zgartirmaydi yoki to'xtatmaydi
    """

    VERSION = "1.0"

    def __init__(self):
        self.name = "ProcessSensor"
        self.collect_count = 0
        self.failed_count = 0

    def health_check(self):
        return {
            "sensor": self.name,
            "status": "HEALTHY",
            "version": self.VERSION,
        }

    def collect(self):
        processes = []

        try:
            for proc in psutil.process_iter(
                [
                    "pid",
                    "ppid",
                    "name",
                    "exe",
                    "username",
                    "cmdline",
                    "create_time",
                ]
            ):
                try:
                    info = proc.info

                    # CPU va memory alohida olinadi.
                    # AccessDenied bo'lsa process o'tkazib yuboriladi.
                    cpu_percent = proc.cpu_percent(interval=None)
                    memory_percent = proc.memory_percent()

                    processes.append(
                        {
                            "pid": info.get("pid"),
                            "ppid": info.get("ppid"),
                            "name": info.get("name"),
                            "exe": info.get("exe"),
                            "username": info.get("username"),
                            "cmdline": info.get("cmdline"),
                            "create_time": info.get("create_time"),
                            "cpu_percent": cpu_percent,
                            "memory_percent": memory_percent,
                        }
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

            self.collect_count += 1

            return {
                "sensor": self.name,
                "version": self.VERSION,
                "timestamp": time.time(),
                "process_count": len(processes),
                "processes": processes,
            }

        except Exception:
            self.failed_count += 1
            raise

    def get_stats(self):
        return {
            "sensor": self.name,
            "version": self.VERSION,
            "collect_count": self.collect_count,
            "failed_count": self.failed_count,
        }