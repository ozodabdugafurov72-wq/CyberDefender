class DetectionEngine:
    """
    CyberDefender Detection Engine.

    Detection manbalari:
    1. Absolute threshold
    2. Baseline/anomaly

    P11.20:
    - explicit health contract
    - runtime telemetry
    - health check read-only
    - health check agentni yiqitmaydi

    Hozirgi bosqich:
    - faqat OBSERVE
    - tizimga o'zgartirish kiritmaydi
    """

    VERSION = "1.1"

    def __init__(self, config):
        self.config = config
        detection = config["detection"]

        self.memory_warning = detection["memory_warning"]
        self.memory_critical = detection["memory_critical"]

        self.cpu_warning = detection["cpu_warning"]
        self.cpu_critical = detection["cpu_critical"]

        self.process_warning = detection["process_warning"]
        self.process_critical = detection["process_critical"]

        self.available_memory_warning = (
            detection["available_memory_warning"]
        )

        self.available_memory_critical = (
            detection["available_memory_critical"]
        )

        # Baseline sozlamalari
        self.baseline_memory_percent = None
        self.baseline_cpu_percent = None

        self.memory_anomaly_delta = detection.get(
            "memory_anomaly_delta",
            10.0
        )

        self.cpu_anomaly_delta = detection.get(
            "cpu_anomaly_delta",
            30.0
        )

        # =====================================================
        # RUNTIME TELEMETRY
        # =====================================================

        self._analyze_count = 0
        self._detection_count = 0
        self._failed_count = 0
        self._invalid_input_count = 0

        # =====================================================
        # HEALTH CONTRACT TELEMETRY
        # =====================================================

        self._health_checks = 0
        self._health_failures = 0
        self._last_error = None
        self._last_error_component = None

    def set_baseline(self, snapshot):
        """
        Joriy snapshot'ni baseline sifatida saqlaydi.
        """

        self.baseline_memory_percent = (
            snapshot["memory_percent"]
        )

        self.baseline_cpu_percent = (
            snapshot["cpu_percent"]
        )

    def analyze(self, snapshot):
        """
        Snapshotni detection qoidalari orqali tahlil qiladi.

        Invalid input yoki exception asosiy agentni
        yiqitmasligi uchun xavfsiz tarzda [] qaytaradi.
        """

        if not isinstance(snapshot, dict):
            self._invalid_input_count += 1
            return []

        self._analyze_count += 1

        try:
            detections = []

            memory = snapshot["memory_percent"]
            cpu = snapshot["cpu_percent"]
            process_count = snapshot["process_count"]
            available_memory = snapshot["memory_available_mb"]

            # ==========================================
            # ABSOLUTE MEMORY
            # ==========================================

            if memory >= self.memory_critical:
                detections.append({
                    "type": "HIGH_MEMORY_USAGE",
                    "severity": "CRITICAL",
                    "value": memory,
                    "message": (
                        f"Memory usage juda yuqori: "
                        f"{memory}%"
                    )
                })

            elif memory >= self.memory_warning:
                detections.append({
                    "type": "HIGH_MEMORY_USAGE",
                    "severity": "WARNING",
                    "value": memory,
                    "message": (
                        f"Memory usage yuqori: "
                        f"{memory}%"
                    )
                })

            # ==========================================
            # ABSOLUTE CPU
            # ==========================================

            if cpu >= self.cpu_critical:
                detections.append({
                    "type": "HIGH_CPU_USAGE",
                    "severity": "CRITICAL",
                    "value": cpu,
                    "message": (
                        f"CPU usage juda yuqori: "
                        f"{cpu}%"
                    )
                })

            elif cpu >= self.cpu_warning:
                detections.append({
                    "type": "HIGH_CPU_USAGE",
                    "severity": "WARNING",
                    "value": cpu,
                    "message": (
                        f"CPU usage yuqori: "
                        f"{cpu}%"
                    )
                })

            # ==========================================
            # PROCESS COUNT
            # ==========================================

            if process_count >= self.process_critical:
                detections.append({
                    "type": "HIGH_PROCESS_COUNT",
                    "severity": "CRITICAL",
                    "value": process_count,
                    "message": (
                        "Running processlar soni "
                        f"juda yuqori: {process_count}"
                    )
                })

            elif process_count >= self.process_warning:
                detections.append({
                    "type": "HIGH_PROCESS_COUNT",
                    "severity": "WARNING",
                    "value": process_count,
                    "message": (
                        "Running processlar soni "
                        f"yuqori: {process_count}"
                    )
                })

            # ==========================================
            # AVAILABLE MEMORY
            # ==========================================

            if (
                available_memory
                <= self.available_memory_critical
            ):
                detections.append({
                    "type": "LOW_AVAILABLE_MEMORY",
                    "severity": "CRITICAL",
                    "value": available_memory,
                    "message": (
                        "Available memory juda kam: "
                        f"{available_memory} MB"
                    )
                })

            elif (
                available_memory
                <= self.available_memory_warning
            ):
                detections.append({
                    "type": "LOW_AVAILABLE_MEMORY",
                    "severity": "WARNING",
                    "value": available_memory,
                    "message": (
                        "Available memory kam: "
                        f"{available_memory} MB"
                    )
                })

            # ==========================================
            # BASELINE ANOMALY
            # ==========================================

            if self.baseline_memory_percent is not None:

                memory_delta = (
                    memory
                    - self.baseline_memory_percent
                )

                if memory_delta >= self.memory_anomaly_delta:
                    detections.append({
                        "type": "MEMORY_ANOMALY",
                        "severity": "WARNING",
                        "value": memory_delta,
                        "message": (
                            "Memory baseline'dan "
                            f"{memory_delta:.1f}% yuqori: "
                            f"{self.baseline_memory_percent:.1f}% "
                            f"-> {memory:.1f}%"
                        )
                    })

            if self.baseline_cpu_percent is not None:

                cpu_delta = (
                    cpu
                    - self.baseline_cpu_percent
                )

                if cpu_delta >= self.cpu_anomaly_delta:
                    detections.append({
                        "type": "CPU_ANOMALY",
                        "severity": "WARNING",
                        "value": cpu_delta,
                        "message": (
                            "CPU baseline'dan "
                            f"{cpu_delta:.1f}% yuqori: "
                            f"{self.baseline_cpu_percent:.1f}% "
                            f"-> {cpu:.1f}%"
                        )
                    })

            self._detection_count += len(
                detections
            )

            return detections

        except Exception as exc:

            self._failed_count += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "DetectionEngine.analyze"
            )

            return []

    # =========================================================
    # HEALTH CONTRACT
    # =========================================================

    def health_check(self) -> dict:
        """
        DetectionEngine health contract.

        Security-first qoidalar:
        - health check read-only.
        - detection yaratmaydi.
        - tizimga o'zgartirish kiritmaydi.
        - exception tashqariga chiqarmaydi.
        """

        self._health_checks += 1

        try:
            # Configuration sanity.
            required_attributes = (
                "memory_warning",
                "memory_critical",
                "cpu_warning",
                "cpu_critical",
                "process_warning",
                "process_critical",
                "available_memory_warning",
                "available_memory_critical",
            )

            for attribute in required_attributes:
                if not hasattr(
                    self,
                    attribute,
                ):
                    raise RuntimeError(
                        f"Missing detector configuration: "
                        f"{attribute}"
                    )

            # Threshold sanity.
            if (
                self.memory_warning
                > self.memory_critical
            ):
                raise RuntimeError(
                    "Memory threshold order invalid"
                )

            if (
                self.cpu_warning
                > self.cpu_critical
            ):
                raise RuntimeError(
                    "CPU threshold order invalid"
                )

            if (
                self.process_warning
                > self.process_critical
            ):
                raise RuntimeError(
                    "Process threshold order invalid"
                )

            if (
                self.available_memory_critical
                > self.available_memory_warning
            ):
                raise RuntimeError(
                    "Available memory threshold order invalid"
                )

            self._last_error = None
            self._last_error_component = None

            return {
                "component": "DetectionEngine",
                "status": "HEALTHY",
                "version": self.VERSION,

                "configuration": {
                    "thresholds_valid": True,
                    "baseline_enabled": (
                        self.baseline_memory_percent
                        is not None
                        or
                        self.baseline_cpu_percent
                        is not None
                    ),
                },

                "counters": {
                    "analyze": self._analyze_count,
                    "detections": self._detection_count,
                    "failed": self._failed_count,
                    "invalid_input":
                        self._invalid_input_count,
                },

                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_error":
                    self._last_error,

                "last_error_component":
                    self._last_error_component,
            }

        except Exception as exc:

            self._health_failures += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "DetectionEngine.health_check"
            )

            return {
                "component": "DetectionEngine",
                "status": "DEGRADED",
                "version": self.VERSION,

                "configuration": {
                    "thresholds_valid": False,
                    "baseline_enabled": False,
                },

                "counters": {
                    "analyze": self._analyze_count,
                    "detections": self._detection_count,
                    "failed": self._failed_count,
                    "invalid_input":
                        self._invalid_input_count,
                },

                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_error":
                    self._last_error,

                "last_error_component":
                    self._last_error_component,
            }

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(self) -> dict:
        """
        DetectionEngine runtime statistikasi.
        """

        return {
            "component": "DetectionEngine",
            "version": self.VERSION,

            "analyze_count":
                self._analyze_count,

            "detection_count":
                self._detection_count,

            "failed_count":
                self._failed_count,

            "invalid_input_count":
                self._invalid_input_count,

            "health_checks":
                self._health_checks,

            "health_failures":
                self._health_failures,

            "last_error":
                self._last_error,

            "last_error_component":
                self._last_error_component,
        }

    def print_detections(self, detections):
        print()
        print("Detection Engine:")

        if not detections:
            print("No detections.")
            return

        for detection in detections:
            print(
                f"[{detection['severity']}] "
                f"{detection['type']}: "
                f"{detection['message']}"
            )
