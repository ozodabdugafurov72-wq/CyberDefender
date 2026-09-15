from __future__ import annotations

from typing import Any, Optional

from .rules import RuleEngine


class RuleAdapter:
    """
    Adapter between CyberDefender Agent and RuleEngine.

    P11.20 Health Contract Integration v1.1.

    Vazifasi:
    - RuleEngine'ni konfiguratsiya bilan ishga tushirish
    - snapshotlarni RuleEngine orqali tahlil qilish
    - agent uchun yagona detection interfeysini taqdim etish
    - deterministic health contract taqdim etish

    Security-first:
    - health_check() event yaratmaydi
    - health_check() detection ishlatmaydi
    - health_check() tizimni o'zgartirmaydi
    - health_check() exceptionni tashqariga chiqarmaydi
    - RuleEngine mavjudligi va health contracti tekshiriladi
    """

    NAME = "RuleAdapter"
    VERSION = "1.1"

    def __init__(
        self,
        config: Optional[dict[str, Any]] = None,
        rule_engine: Optional[RuleEngine] = None,
    ) -> None:

        self.engine = (
            rule_engine
            if rule_engine is not None
            else RuleEngine(config)
        )

        # Health contract telemetry.
        self._health_checks = 0
        self._health_failures = 0
        self._last_error: Optional[str] = None
        self._last_error_component: Optional[str] = None

    def analyze(
        self,
        snapshot: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        System snapshotni RuleEngine orqali tahlil qiladi.
        """

        return self.engine.analyze(snapshot)

    def analyze_event(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        HOST_SNAPSHOT eventni RuleEngine orqali tahlil qiladi.
        """

        return self.engine.analyze_event(event)

    # =========================================================
    # HEALTH CONTRACT
    # =========================================================

    def health_check(
        self,
    ) -> dict[str, Any]:
        """
        RuleAdapter health contract.

        Security-first qoidalar:
        - event yaratmaydi
        - detection ishga tushirmaydi
        - tizimni o'zgartirmaydi
        - RuleEngine holatini tekshiradi
        - exceptionni tashqariga chiqarmaydi
        """

        self._health_checks += 1

        try:
            # -------------------------------------------------
            # 01. Adapter engine mavjudligi
            # -------------------------------------------------

            if self.engine is None:
                raise RuntimeError(
                    "RuleEngine mavjud emas"
                )

            # -------------------------------------------------
            # 02. RuleEngine analyze contract
            # -------------------------------------------------

            analyze_method = getattr(
                self.engine,
                "analyze",
                None,
            )

            if not callable(analyze_method):
                raise RuntimeError(
                    "RuleEngine.analyze mavjud emas"
                )

            # -------------------------------------------------
            # 03. RuleEngine health contract
            #
            # Agar RuleEngine o'z health_check() metodiga ega
            # bo'lsa, undan foydalanamiz.
            #
            # Agar hali health contract bo'lmasa, adapter
            # mavjud RuleEngine bilan ishlashni davom ettiradi.
            # Bu RuleAdapter'ni keraksiz ravishda UNKNOWN
            # holatiga tushirmaydi.
            # -------------------------------------------------

            engine_health_method = getattr(
                self.engine,
                "health_check",
                None,
            )

            engine_health = None

            if callable(
                engine_health_method
            ):

                engine_health = (
                    engine_health_method()
                )

                if not isinstance(
                    engine_health,
                    dict,
                ):
                    raise RuntimeError(
                        "RuleEngine health response invalid"
                    )

                engine_status = engine_health.get(
                    "status"
                )

                if engine_status not in {
                    "HEALTHY",
                    "DEGRADED",
                }:
                    raise RuntimeError(
                        "RuleEngine health status invalid"
                    )

                if engine_status == "DEGRADED":
                    self._health_failures += 1

                    self._last_error = (
                        "RuleEngine DEGRADED"
                    )

                    self._last_error_component = (
                        "RuleEngine"
                    )

                    return {
                        "component":
                            self.NAME,

                        "status":
                            "DEGRADED",

                        "version":
                            self.VERSION,

                        "engine":
                            engine_health,

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
            # HEALTHY
            # -------------------------------------------------

            self._last_error = None
            self._last_error_component = None

            result = {
                "component":
                    self.NAME,

                "status":
                    "HEALTHY",

                "version":
                    self.VERSION,

                "engine":
                    engine_health
                    if engine_health is not None
                    else {
                        "component":
                            "RuleEngine",

                        "status":
                            "AVAILABLE",
                    },

                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_error":
                    None,

                "last_error_component":
                    None,
            }

            return result

        except Exception as exc:

            self._health_failures += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "RuleAdapter"
            )

            return {
                "component":
                    self.NAME,

                "status":
                    "DEGRADED",

                "version":
                    self.VERSION,

                "engine":
                    {
                        "component":
                            "RuleEngine",

                        "status":
                            "UNAVAILABLE",
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

    def get_stats(
        self,
    ) -> dict[str, Any]:
        """
        RuleEngine statistikasi + RuleAdapter health telemetry.
        """

        engine_stats = {}

        try:
            result = self.engine.get_stats()

            if isinstance(
                result,
                dict,
            ):
                engine_stats = result

        except Exception:
            engine_stats = {}

        return {
            "component":
                self.NAME,

            "version":
                self.VERSION,

            "engine":
                engine_stats,

            "health_checks":
                self._health_checks,

            "health_failures":
                self._health_failures,

            "last_error":
                self._last_error,

            "last_error_component":
                self._last_error_component,
        }

    def get_engine(
        self,
    ) -> RuleEngine:
        """
        Ichki RuleEngine obyektini qaytaradi.
        """

        return self.engine


def create_rule_adapter(
    config: Optional[dict[str, Any]] = None,
) -> RuleAdapter:
    """
    RuleAdapter yaratish uchun factory.
    """

    return RuleAdapter(
        config=config
    )


__all__ = [
    "RuleAdapter",
    "create_rule_adapter",
]
