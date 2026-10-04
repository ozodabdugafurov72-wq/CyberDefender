from __future__ import annotations

from typing import Any

from agent.detection.rules import RuleEngine


class Detector:
    """
    CyberDefender Detection Orchestrator v2.

    Vazifasi:
    - EventBus'dan kelgan eventlarni qabul qilish
    - event turiga qarab mos detection engine'ga yuborish
    - detection natijalarini qaytarish
    - dependency health holatini tekshirish
    - detection xatolarini local containment qilish

    Hozir:
    - RuleEngine

    Keyinchalik:
    - BehavioralEngine
    - AnomalyEngine
    - AI Analysis

    Security-first invariants:
    - Detector tizimga to'g'ridan-to'g'ri o'zgartirish kiritmaydi.
    - Detection xatosi agent supervisor'ini yiqitmaydi.
    - Invalid event detection'ga o'tkazilmaydi.
    - RuleEngine mavjud bo'lmasa Detector HEALTHY bo'lmaydi.
    - health_check() event yaratmaydi.
    - health_check() detection yaratmaydi.
    - health_check() state mutation qilmaydi.
    """

    VERSION = "2.0"

    def __init__(
        self,
        rule_engine: RuleEngine,
    ):
        if rule_engine is None:
            raise ValueError(
                "rule_engine berilishi kerak"
            )

        self.rule_engine = rule_engine

        # -----------------------------------------------------
        # Runtime telemetry
        # -----------------------------------------------------

        self._events_processed = 0
        self._events_ignored = 0
        self._detections_generated = 0
        self._failed = 0

        # -----------------------------------------------------
        # Detailed failure telemetry
        # -----------------------------------------------------

        self._invalid_events = 0
        self._unsupported_events = 0
        self._rule_engine_failures = 0
        self._invalid_detection_results = 0

        # -----------------------------------------------------
        # Health contract telemetry
        # -----------------------------------------------------

        self._health_checks = 0
        self._health_failures = 0

        self._last_error = None
        self._last_error_component = None

    # =========================================================
    # DEPENDENCY HEALTH
    # =========================================================

    def _check_rule_engine_health(
        self,
    ) -> dict[str, Any]:
        """
        RuleEngine health holatini xavfsiz tarzda tekshiradi.

        RuleEngine'da health_check() bo'lmasa ham Detector
        darhol yiqilmaydi. Bunday holatda dependency contract
        mavjud emasligi sababli DEGRADED qaytariladi.
        """

        try:
            health_method = getattr(
                self.rule_engine,
                "health_check",
                None,
            )

            if not callable(
                health_method
            ):
                return {
                    "component": "RuleEngine",
                    "status": "DEGRADED",
                    "health_contract": "MISSING",
                }

            result = health_method()

            if not isinstance(
                result,
                dict,
            ):
                return {
                    "component": "RuleEngine",
                    "status": "DEGRADED",
                    "health_contract": "INVALID",
                }

            status = result.get(
                "status"
            )

            if status not in {
                "HEALTHY",
                "DEGRADED",
            }:
                return {
                    **result,
                    "component": result.get(
                        "component",
                        "RuleEngine",
                    ),
                    "status": "DEGRADED",
                    "health_contract": "INVALID_STATUS",
                }

            return result

        except Exception as exc:
            return {
                "component": "RuleEngine",
                "status": "DEGRADED",
                "health_contract": "EXCEPTION",
                "last_error": (
                    f"{type(exc).__name__}: {exc}"
                ),
            }

    # =========================================================
    # HEALTH CONTRACT
    # =========================================================

    def health_check(
        self,
    ) -> dict[str, Any]:
        """
        Detector health contract.

        Security-first qoidalar:
        - Health check event yaratmaydi.
        - Detection ishlatmaydi.
        - RuleEngine dependency'sini tekshiradi.
        - Exception tashqariga chiqmaydi.
        - Faqat diagnostika holatini qaytaradi.
        """

        self._health_checks += 1

        try:
            # -------------------------------------------------
            # 01. Detector dependency mavjudligi
            # -------------------------------------------------

            if self.rule_engine is None:
                raise RuntimeError(
                    "RuleEngine dependency mavjud emas"
                )

            # -------------------------------------------------
            # 02. RuleEngine health
            # -------------------------------------------------

            rule_health = (
                self._check_rule_engine_health()
            )

            rule_status = rule_health.get(
                "status"
            )

            if rule_status != "HEALTHY":
                self._health_failures += 1

                self._last_error = (
                    "RuleEngine dependency HEALTHY emas"
                )

                self._last_error_component = (
                    "RuleEngine"
                )

                return {
                    "component": "Detector",
                    "status": "DEGRADED",
                    "version": self.VERSION,
                    "dependencies": {
                        "rule_engine":
                            rule_health,
                    },
                    "counters": {
                        "events_processed":
                            self._events_processed,
                        "events_ignored":
                            self._events_ignored,
                        "detections_generated":
                            self._detections_generated,
                        "failed":
                            self._failed,
                        "invalid_events":
                            self._invalid_events,
                        "unsupported_events":
                            self._unsupported_events,
                        "rule_engine_failures":
                            self._rule_engine_failures,
                        "invalid_detection_results":
                            self._invalid_detection_results,
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

            # -------------------------------------------------
            # 03. HEALTHY
            # -------------------------------------------------

            return {
                "component": "Detector",
                "status": "HEALTHY",
                "version": self.VERSION,
                "dependencies": {
                    "rule_engine":
                        rule_health,
                },
                "counters": {
                    "events_processed":
                        self._events_processed,
                    "events_ignored":
                        self._events_ignored,
                    "detections_generated":
                        self._detections_generated,
                    "failed":
                        self._failed,
                    "invalid_events":
                        self._invalid_events,
                    "unsupported_events":
                        self._unsupported_events,
                    "rule_engine_failures":
                        self._rule_engine_failures,
                    "invalid_detection_results":
                        self._invalid_detection_results,
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
                "Detector"
            )

            return {
                "component": "Detector",
                "status": "DEGRADED",
                "version": self.VERSION,
                "dependencies": {
                    "rule_engine": {
                        "component": "RuleEngine",
                        "status": "DEGRADED",
                    },
                },
                "counters": {
                    "events_processed":
                        self._events_processed,
                    "events_ignored":
                        self._events_ignored,
                    "detections_generated":
                        self._detections_generated,
                    "failed":
                        self._failed,
                    "invalid_events":
                        self._invalid_events,
                    "unsupported_events":
                        self._unsupported_events,
                    "rule_engine_failures":
                        self._rule_engine_failures,
                    "invalid_detection_results":
                        self._invalid_detection_results,
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
    # EVENT HANDLER
    # =========================================================

    def handle_event(
        self,
        event: Any,
    ) -> list[dict]:
        """
        Eventni qabul qiladi va tahlil qiladi.

        Har qanday xato agentning asosiy
        pipeline'ini yiqitmasligi kerak.
        """

        # -----------------------------------------------------
        # STRUCTURE VALIDATION
        # -----------------------------------------------------

        if not isinstance(
            event,
            dict,
        ):
            self._events_ignored += 1
            self._invalid_events += 1
            return []

        event_type = event.get(
            "event_type"
        )

        if not isinstance(
            event_type,
            str,
        ):
            self._events_ignored += 1
            self._invalid_events += 1
            return []

        event_type = event_type.strip()

        if not event_type:
            self._events_ignored += 1
            self._invalid_events += 1
            return []

        self._events_processed += 1

        # -----------------------------------------------------
        # ANALYSIS
        # -----------------------------------------------------

        try:
            detections = self._analyze_event(
                event
            )

        except Exception as exc:
            self._failed += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "Detector"
            )

            return []

        # -----------------------------------------------------
        # RESULT VALIDATION
        # -----------------------------------------------------

        if not isinstance(
            detections,
            list,
        ):
            self._failed += 1
            self._invalid_detection_results += 1

            self._last_error = (
                "Detection engine list qaytarmadi"
            )

            self._last_error_component = (
                "RuleEngine"
            )

            return []

        # -----------------------------------------------------
        # Detection result structure validation.
        #
        # Invalid detection objectlarni yuqoriga o'tkazmaymiz.
        # -----------------------------------------------------

        valid_detections: list[
            dict
        ] = []

        for detection in detections:

            if not isinstance(
                detection,
                dict,
            ):
                self._invalid_detection_results += 1
                continue

            valid_detections.append(
                detection
            )

        self._detections_generated += len(
            valid_detections
        )

        return valid_detections

    # =========================================================
    # ANALYSIS ROUTER
    # =========================================================

    def _analyze_event(
        self,
        event: dict,
    ) -> list[dict]:
        """
        Event turiga qarab kerakli detection logic tanlaydi.
        """

        event_type = event.get(
            "event_type"
        )

        data = event.get(
            "data",
            {},
        )

        if not isinstance(
            data,
            dict,
        ):
            self._invalid_events += 1
            return []

        if event_type in {"HOST_SNAPSHOT", "RESOURCE_STATUS", "PROCESS_SNAPSHOT", "PROCESS_START", "FILE_ACTIVITY", "SCRIPT_ACTIVITY", "FILE_INDICATOR"}:
            analyze_event = getattr(self.rule_engine, "analyze_event", None)
            if callable(analyze_event):
                return analyze_event(event)
            if event_type == "HOST_SNAPSHOT":
                return self._analyze_host(data)
            if event_type == "RESOURCE_STATUS":
                return self._analyze_resource(data)
            if event_type == "PROCESS_SNAPSHOT":
                return self._analyze_process(data)

        self._events_ignored += 1
        self._unsupported_events += 1

        return []

    # =========================================================
    # HOST ANALYSIS
    # =========================================================

    def _analyze_host(
        self,
        data: dict,
    ) -> list[dict]:

        try:
            result = self.rule_engine.analyze(
                data
            )

        except Exception as exc:
            self._rule_engine_failures += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "RuleEngine"
            )

            return []

        return (
            result
            if isinstance(result, list)
            else []
        )

    # =========================================================
    # RESOURCE ANALYSIS
    # =========================================================

    def _analyze_resource(
        self,
        data: dict,
    ) -> list[dict]:
        """
        ResourceGuard eventlari.

        Hozircha faqat ichki holatni
        RuleEngine orqali tekshirish.
        """

        resource = data.get(
            "resource",
            {},
        )

        if not isinstance(
            resource,
            dict,
        ):
            self._invalid_events += 1
            return []

        try:
            result = self.rule_engine.analyze(
                resource
            )

        except Exception as exc:
            self._rule_engine_failures += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "RuleEngine"
            )

            return []

        return (
            result
            if isinstance(result, list)
            else []
        )

    # =========================================================
    # PROCESS ANALYSIS
    # =========================================================

    def _analyze_process(
        self,
        data: dict,
    ) -> list[dict]:
        """
        Process snapshot.

        Hozircha process_count
        kabi umumiy ko'rsatkichlar.

        Keyinchalik:
        - ProcessGraph
        - parent/child analysis
        - suspicious execution chain
        - behavioral detection
        """

        try:
            result = self.rule_engine.analyze(
                data
            )

        except Exception as exc:
            self._rule_engine_failures += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "RuleEngine"
            )

            return []

        return (
            result
            if isinstance(result, list)
            else []
        )

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict[str, Any]:

        return {
            "component":
                "Detector",

            "version":
                self.VERSION,

            "events_processed":
                self._events_processed,

            "events_ignored":
                self._events_ignored,

            "detections_generated":
                self._detections_generated,

            "failed":
                self._failed,

            "invalid_events":
                self._invalid_events,

            "unsupported_events":
                self._unsupported_events,

            "rule_engine_failures":
                self._rule_engine_failures,

            "invalid_detection_results":
                self._invalid_detection_results,

            "health_checks":
                self._health_checks,

            "health_failures":
                self._health_failures,

            "last_error":
                self._last_error,

            "last_error_component":
                self._last_error_component,
        }
