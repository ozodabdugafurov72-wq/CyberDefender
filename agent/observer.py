from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Any

import psutil


class SystemObserver:
    """
    CyberDefender System Observer.

    P11.20 Hardened Health Contract.

    Security principles:
        - OBSERVE-ONLY.
        - Tizim holatini o'zgartirmaydi.
        - Processlarni to'xtatmaydi.
        - Fayllarni o'zgartirmaydi.
        - Firewall/registry/service'ga tegmaydi.
        - Sensor xatosi agentni yiqitmaydi.
        - Partial telemetry DEGRADED holat sifatida qaytariladi.
        - Health check destructive operation bajarmaydi.

    Dashboard telemetry extension:
        - CPU
        - Memory
        - Disk usage
        - Network cumulative counters
        - Network upload/download rates
        - Process count
        - Top CPU processes
        - Snapshot timestamp
    """

    VERSION = "2.1"

    TOP_PROCESS_LIMIT = 5
    NETWORK_RATE_MIN_INTERVAL = 0.25

    def __init__(self) -> None:
        self._snapshots = 0
        self._successful_snapshots = 0
        self._partial_snapshots = 0
        self._failed_snapshots = 0

        self._cpu_failures = 0
        self._memory_failures = 0
        self._process_failures = 0
        self._network_failures = 0
        self._disk_failures = 0
        self._top_process_failures = 0

        self._health_checks = 0
        self._health_failures = 0

        self._last_snapshot_duration = 0.0
        self._last_snapshot_time: float | None = None

        self._last_error: str | None = None
        self._last_error_component: str | None = None

        self._last_snapshot: dict[str, Any] | None = None

        # Network rate state.
        self._previous_network_sent_bytes: float | None = None
        self._previous_network_recv_bytes: float | None = None
        self._previous_network_time: float | None = None

    # =========================================================
    # INTERNAL HELPERS
    # =========================================================

    @staticmethod
    def _safe_float(
        value: Any,
        default: float = 0.0,
    ) -> float:
        try:
            result = float(value)

            if not math.isfinite(result):
                return default

            return result

        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _safe_non_negative(
        value: Any,
        default: float = 0.0,
    ) -> float:
        result = SystemObserver._safe_float(
            value,
            default,
        )

        if result < 0:
            return default

        return result

    @staticmethod
    def _safe_text(
        value: Any,
        default: str = "",
    ) -> str:
        try:
            text = str(value)

            if not text:
                return default

            return text

        except Exception:
            return default

    def _record_error(
        self,
        component: str,
        exc: BaseException,
    ) -> None:
        self._last_error = (
            f"{type(exc).__name__}: {exc}"
        )

        self._last_error_component = component

    # =========================================================
    # CPU
    # =========================================================

    def _observe_cpu(self) -> tuple[float, bool]:
        try:
            value = psutil.cpu_percent(
                interval=1
            )

            value = self._safe_non_negative(
                value
            )

            if value > 100.0:
                value = 100.0

            return value, True

        except Exception as exc:
            self._cpu_failures += 1

            self._record_error(
                "CPU",
                exc,
            )

            return 0.0, False

    # =========================================================
    # MEMORY
    # =========================================================

    def _observe_memory(
        self,
    ) -> tuple[dict[str, float], bool]:
        try:
            memory = psutil.virtual_memory()

            memory_percent = (
                self._safe_non_negative(
                    getattr(
                        memory,
                        "percent",
                        0.0,
                    )
                )
            )

            if memory_percent > 100.0:
                memory_percent = 100.0

            available = (
                self._safe_non_negative(
                    getattr(
                        memory,
                        "available",
                        0,
                    )
                )
            )

            total = (
                self._safe_non_negative(
                    getattr(
                        memory,
                        "total",
                        0,
                    )
                )
            )

            used = (
                self._safe_non_negative(
                    getattr(
                        memory,
                        "used",
                        0,
                    )
                )
            )

            return {
                "memory_percent": memory_percent,
                "memory_available_mb": round(
                    available / (1024 * 1024),
                    2,
                ),
                "memory_total_mb": round(
                    total / (1024 * 1024),
                    2,
                ),
                "memory_used_mb": round(
                    used / (1024 * 1024),
                    2,
                ),
            }, True

        except Exception as exc:
            self._memory_failures += 1

            self._record_error(
                "MEMORY",
                exc,
            )

            return {
                "memory_percent": 0.0,
                "memory_available_mb": 0.0,
                "memory_total_mb": 0.0,
                "memory_used_mb": 0.0,
            }, False

    # =========================================================
    # DISK
    # =========================================================

    def _observe_disk(self) -> tuple[dict[str, float], bool]:
        try:
            # Windows: current system drive, e.g. C:\
            # Linux/macOS: root filesystem.
            drive = Path.cwd().anchor or "/"

            disk = psutil.disk_usage(drive)

            total = self._safe_non_negative(
                getattr(disk, "total", 0)
            )

            used = self._safe_non_negative(
                getattr(disk, "used", 0)
            )

            free = self._safe_non_negative(
                getattr(disk, "free", 0)
            )

            percent = self._safe_non_negative(
                getattr(disk, "percent", 0.0)
            )

            if percent > 100.0:
                percent = 100.0

            return {
                "disk_percent": round(
                    percent,
                    2,
                ),
                "disk_total_gb": round(
                    total / (1024 ** 3),
                    2,
                ),
                "disk_used_gb": round(
                    used / (1024 ** 3),
                    2,
                ),
                "disk_free_gb": round(
                    free / (1024 ** 3),
                    2,
                ),
                "disk_mount": drive,
            }, True

        except Exception as exc:
            self._disk_failures += 1

            self._record_error(
                "DISK",
                exc,
            )

            return {
                "disk_percent": 0.0,
                "disk_total_gb": 0.0,
                "disk_used_gb": 0.0,
                "disk_free_gb": 0.0,
                "disk_mount": "",
            }, False

    # =========================================================
    # PROCESS COUNT
    # =========================================================

    def _observe_processes(
        self,
    ) -> tuple[int, bool]:
        try:
            pids = psutil.pids()

            if not isinstance(
                pids,
                (list, tuple),
            ):
                pids = list(pids)

            return len(pids), True

        except Exception as exc:
            self._process_failures += 1

            self._record_error(
                "PROCESS",
                exc,
            )

            return 0, False

    # =========================================================
    # TOP PROCESSES
    # =========================================================

    def _observe_top_processes(
        self,
    ) -> tuple[list[dict[str, Any]], bool]:
        processes: list[dict[str, Any]] = []

        try:
            for process in psutil.process_iter(
                [
                    "pid",
                    "name",
                    "username",
                    "status",
                ]
            ):
                try:
                    cpu_percent = self._safe_non_negative(
                        process.cpu_percent(
                            interval=None
                        )
                    )

                    memory_percent = self._safe_non_negative(
                        process.memory_percent()
                    )

                    info = process.info

                    processes.append(
                        {
                            "pid": int(
                                info.get(
                                    "pid",
                                    process.pid,
                                )
                            ),
                            "name": self._safe_text(
                                info.get(
                                    "name"
                                ),
                                "unknown",
                            ),
                            "username": self._safe_text(
                                info.get(
                                    "username"
                                ),
                                "",
                            ),
                            "status": self._safe_text(
                                info.get(
                                    "status"
                                ),
                                "",
                            ),
                            "cpu_percent": round(
                                min(
                                    cpu_percent,
                                    100.0,
                                ),
                                2,
                            ),
                            "memory_percent": round(
                                memory_percent,
                                2,
                            ),
                        }
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

                except Exception:
                    continue

            processes.sort(
                key=lambda item: (
                    float(
                        item.get(
                            "cpu_percent",
                            0.0,
                        )
                    ),
                    float(
                        item.get(
                            "memory_percent",
                            0.0,
                        )
                    ),
                ),
                reverse=True,
            )

            return (
                processes[: self.TOP_PROCESS_LIMIT],
                True,
            )

        except Exception as exc:
            self._top_process_failures += 1

            self._record_error(
                "TOP_PROCESSES",
                exc,
            )

            return [], False

    # =========================================================
    # NETWORK
    # =========================================================

    def _observe_network(
        self,
    ) -> tuple[dict[str, float], bool]:
        try:
            network = psutil.net_io_counters()

            if network is None:
                raise RuntimeError(
                    "Network counters unavailable"
                )

            sent = self._safe_non_negative(
                getattr(
                    network,
                    "bytes_sent",
                    0,
                )
            )

            received = self._safe_non_negative(
                getattr(
                    network,
                    "bytes_recv",
                    0,
                )
            )

            now = time.time()

            upload_mbps = 0.0
            download_mbps = 0.0

            previous_time = (
                self._previous_network_time
            )

            previous_sent = (
                self._previous_network_sent_bytes
            )

            previous_received = (
                self._previous_network_recv_bytes
            )

            if (
                previous_time is not None
                and previous_sent is not None
                and previous_received is not None
            ):
                elapsed = now - previous_time

                if (
                    elapsed
                    >= self.NETWORK_RATE_MIN_INTERVAL
                ):
                    sent_delta = max(
                        0.0,
                        sent - previous_sent,
                    )

                    received_delta = max(
                        0.0,
                        received - previous_received,
                    )

                    # bytes/sec -> megabits/sec
                    upload_mbps = (
                        sent_delta
                        * 8.0
                        / elapsed
                        / 1_000_000.0
                    )

                    download_mbps = (
                        received_delta
                        * 8.0
                        / elapsed
                        / 1_000_000.0
                    )

            self._previous_network_sent_bytes = sent
            self._previous_network_recv_bytes = received
            self._previous_network_time = now

            return {
                "network_sent_mb": round(
                    sent / (1024 * 1024),
                    2,
                ),
                "network_recv_mb": round(
                    received / (1024 * 1024),
                    2,
                ),
                "network_upload_mbps": round(
                    max(0.0, upload_mbps),
                    3,
                ),
                "network_download_mbps": round(
                    max(0.0, download_mbps),
                    3,
                ),
            }, True

        except Exception as exc:
            self._network_failures += 1

            self._record_error(
                "NETWORK",
                exc,
            )

            return {
                "network_sent_mb": 0.0,
                "network_recv_mb": 0.0,
                "network_upload_mbps": 0.0,
                "network_download_mbps": 0.0,
            }, False

    # =========================================================
    # SYSTEM SNAPSHOT
    # =========================================================

    def get_system_snapshot(
        self,
    ) -> dict[str, Any]:
        """
        Backward-compatible public API.

        Har bir sensor alohida failure boundary ichida.

        Bitta psutil sensorining xatosi boshqa telemetry
        yig'ilishini to'xtatmaydi.
        """

        started = time.monotonic()

        self._snapshots += 1

        successful_components = 0

        cpu_percent, cpu_ok = (
            self._observe_cpu()
        )

        if cpu_ok:
            successful_components += 1

        memory, memory_ok = (
            self._observe_memory()
        )

        if memory_ok:
            successful_components += 1

        process_count, process_ok = (
            self._observe_processes()
        )

        if process_ok:
            successful_components += 1

        top_processes, top_processes_ok = (
            self._observe_top_processes()
        )

        if top_processes_ok:
            successful_components += 1

        network, network_ok = (
            self._observe_network()
        )

        if network_ok:
            successful_components += 1

        disk, disk_ok = (
            self._observe_disk()
        )

        if disk_ok:
            successful_components += 1

        snapshot_time = time.time()

        snapshot = {
            "timestamp": snapshot_time,

            "cpu_percent": cpu_percent,

            "memory_percent":
                memory[
                    "memory_percent"
                ],

            "memory_available_mb":
                memory[
                    "memory_available_mb"
                ],

            "memory_total_mb":
                memory[
                    "memory_total_mb"
                ],

            "memory_used_mb":
                memory[
                    "memory_used_mb"
                ],

            "process_count":
                process_count,

            "top_processes":
                top_processes,

            "network_sent_mb":
                network[
                    "network_sent_mb"
                ],

            "network_recv_mb":
                network[
                    "network_recv_mb"
                ],

            "network_upload_mbps":
                network[
                    "network_upload_mbps"
                ],

            "network_download_mbps":
                network[
                    "network_download_mbps"
                ],

            "disk_percent":
                disk[
                    "disk_percent"
                ],

            "disk_total_gb":
                disk[
                    "disk_total_gb"
                ],

            "disk_used_gb":
                disk[
                    "disk_used_gb"
                ],

            "disk_free_gb":
                disk[
                    "disk_free_gb"
                ],

            "disk_mount":
                disk[
                    "disk_mount"
                ],
        }

        self._last_snapshot_duration = (
            max(
                0.0,
                time.monotonic()
                - started,
            )
        )

        self._last_snapshot_time = (
            snapshot_time
        )

        self._last_snapshot = dict(
            snapshot
        )

        # Six telemetry groups:
        # CPU, memory, process count, top processes,
        # network, disk.
        if successful_components == 6:
            self._successful_snapshots += 1

            # Successful full snapshot clears transient
            # observer error state.
            self._last_error = None
            self._last_error_component = None

        elif successful_components > 0:
            self._partial_snapshots += 1

        else:
            self._failed_snapshots += 1

        return snapshot

    # =========================================================
    # PRINT SNAPSHOT
    # =========================================================

    def print_snapshot(
        self,
    ) -> None:
        """
        Existing console API retained for compatibility.
        """

        try:
            snapshot = (
                self.get_system_snapshot()
            )

            print()
            print("System Observer:")

            print(
                f"CPU usage: "
                f"{snapshot['cpu_percent']}%"
            )

            print(
                f"Memory usage: "
                f"{snapshot['memory_percent']}%"
            )

            print(
                f"Available memory: "
                f"{snapshot['memory_available_mb']} MB"
            )

            print(
                f"Disk usage: "
                f"{snapshot['disk_percent']}%"
            )

            print(
                f"Running processes: "
                f"{snapshot['process_count']}"
            )

            print(
                f"Network sent: "
                f"{snapshot['network_sent_mb']} MB"
            )

            print(
                f"Network received: "
                f"{snapshot['network_recv_mb']} MB"
            )

            print(
                f"Network upload: "
                f"{snapshot['network_upload_mbps']} Mbps"
            )

            print(
                f"Network download: "
                f"{snapshot['network_download_mbps']} Mbps"
            )

            print(
                "Top processes:"
            )

            for process in snapshot.get(
                "top_processes",
                [],
            ):
                print(
                    f"  "
                    f"{process.get('name', 'unknown')}"
                    f" "
                    f"PID={process.get('pid', '-')}"
                    f" "
                    f"CPU={process.get('cpu_percent', 0.0)}%"
                )

        except Exception as exc:
            # Console rendering failure must never terminate
            # the security runtime.
            self._record_error(
                "PRINT_SNAPSHOT",
                exc,
            )

    # =========================================================
    # HEALTH CHECK
    # =========================================================

    def health_check(
        self,
    ) -> dict[str, Any]:
        """
        Non-destructive observer health contract.

        IMPORTANT:
        Health check yangi snapshot yig'maydi.
        Shuning uchun startup health gate CPU sampling
        yoki boshqa telemetry operationni majburan
        bajarmaydi.
        """

        self._health_checks += 1

        try:
            required_callables = (
                "cpu_percent",
                "virtual_memory",
                "pids",
                "net_io_counters",
                "disk_usage",
                "process_iter",
            )

            for name in required_callables:
                method = getattr(
                    psutil,
                    name,
                    None,
                )

                if not callable(method):
                    raise RuntimeError(
                        f"psutil.{name} unavailable"
                    )

            # If every attempted snapshot failed, observer
            # cannot currently be considered healthy.
            if (
                self._snapshots > 0
                and self._failed_snapshots
                == self._snapshots
            ):
                return {
                    "component":
                        "SystemObserver",

                    "status":
                        "DEGRADED",

                    "version":
                        self.VERSION,

                    "snapshots":
                        self._snapshots,

                    "successful_snapshots":
                        self._successful_snapshots,

                    "partial_snapshots":
                        self._partial_snapshots,

                    "failed_snapshots":
                        self._failed_snapshots,

                    "last_snapshot_duration":
                        self._last_snapshot_duration,

                    "last_error":
                        self._last_error,

                    "last_error_component":
                        self._last_error_component,
                }

            return {
                "component":
                    "SystemObserver",

                "status":
                    "HEALTHY",

                "version":
                    self.VERSION,

                "snapshots":
                    self._snapshots,

                "successful_snapshots":
                    self._successful_snapshots,

                "partial_snapshots":
                    self._partial_snapshots,

                "failed_snapshots":
                    self._failed_snapshots,

                "cpu_failures":
                    self._cpu_failures,

                "memory_failures":
                    self._memory_failures,

                "process_failures":
                    self._process_failures,

                "network_failures":
                    self._network_failures,

                "disk_failures":
                    self._disk_failures,

                "top_process_failures":
                    self._top_process_failures,

                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_snapshot_duration":
                    self._last_snapshot_duration,

                "last_snapshot_time":
                    self._last_snapshot_time,

                "last_error":
                    self._last_error,

                "last_error_component":
                    self._last_error_component,
            }

        except Exception as exc:
            self._health_failures += 1

            self._record_error(
                "SystemObserver",
                exc,
            )

            return {
                "component":
                    "SystemObserver",

                "status":
                    "DEGRADED",

                "version":
                    self.VERSION,

                "snapshots":
                    self._snapshots,

                "successful_snapshots":
                    self._successful_snapshots,

                "partial_snapshots":
                    self._partial_snapshots,

                "failed_snapshots":
                    self._failed_snapshots,

                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_snapshot_duration":
                    self._last_snapshot_duration,

                "last_error":
                    self._last_error,

                "last_error_component":
                    self._last_error_component,
            }

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict[str, Any]:
        return {
            "component":
                "SystemObserver",

            "version":
                self.VERSION,

            "snapshots":
                self._snapshots,

            "successful_snapshots":
                self._successful_snapshots,

            "partial_snapshots":
                self._partial_snapshots,

            "failed_snapshots":
                self._failed_snapshots,

            "cpu_failures":
                self._cpu_failures,

            "memory_failures":
                self._memory_failures,

            "process_failures":
                self._process_failures,

            "network_failures":
                self._network_failures,

            "disk_failures":
                self._disk_failures,

            "top_process_failures":
                self._top_process_failures,

            "health_checks":
                self._health_checks,

            "health_failures":
                self._health_failures,

            "last_snapshot_duration":
                self._last_snapshot_duration,

            "last_snapshot_time":
                self._last_snapshot_time,

            "last_error":
                self._last_error,

            "last_error_component":
                self._last_error_component,
        }
