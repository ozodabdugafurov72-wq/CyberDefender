from __future__ import annotations

from typing import Any, Callable, Optional

from agent.event import SecurityEvent


class SecurityEventBridge:
    """
    CyberDefender SecurityEvent -> DETECTION bridge v1.1.

    Responsibilities:

        SecurityEvent
             |
             v
        integrity verification
             |
             v
        DETECTION dictionary
             |
             v
        downstream consumer

    Bridge hech qanday:
        - system modification
        - network operation
        - persistence operation
        - security action

    bajarmaydi.

    U faqat trusted event contract transformation
    uchun javob beradi.
    """

    VERSION = "1.1"

    def __init__(
        self,
        output_callback: Optional[
            Callable[[dict[str, Any]], Any]
        ] = None,
    ):
        if (
            output_callback is not None
            and not callable(output_callback)
        ):
            raise TypeError(
                "output_callback callable bo'lishi kerak"
            )

        self.output_callback = output_callback

        self._received = 0
        self._converted = 0
        self._ignored = 0
        self._rejected = 0
        self._failed = 0

    # =========================================================
    # STATIC CONVERSION
    # =========================================================

    @staticmethod
    def to_detection(
        event: SecurityEvent,
    ) -> dict[str, Any]:
        """
        SecurityEvent v2 -> Correlation DETECTION contract.

        Integrity invalid bo'lsa event reject qilinadi.
        """

        if not isinstance(
            event,
            SecurityEvent,
        ):
            raise TypeError(
                "SecurityEvent kerak"
            )

        if not event.verify_integrity():
            raise ValueError(
                "SecurityEvent integrity invalid"
            )

        return {
            "event_type": "DETECTION",
            "event_id": event.event_id,
            "timestamp": event.timestamp,

            "data": {
                "type": event.event_type,
                "severity": event.severity,
                "source": event.source,
                "value": event.value,
                "message": event.message,

                "host_id": event.host_id,

                "process_id": getattr(
                    event,
                    "process_id",
                    None,
                ),

                "parent_process_id": getattr(
                    event,
                    "parent_process_id",
                    None,
                ),

                "user_id": getattr(
                    event,
                    "user_id",
                    None,
                ),

                "session_id": getattr(
                    event,
                    "session_id",
                    None,
                ),

                "entity_id": getattr(
                    event,
                    "entity_id",
                    None,
                ),

                "asset_id": getattr(
                    event,
                    "asset_id",
                    None,
                ),

                "sensor_id": getattr(
                    event,
                    "sensor_id",
                    None,
                ),

                "tenant_id": getattr(
                    event,
                    "tenant_id",
                    None,
                ),

                "correlation_keys": list(
                    getattr(
                        event,
                        "correlation_keys",
                        [],
                    )
                    or []
                ),
            },
        }

    # =========================================================
    # EVENTBUS SUBSCRIBER
    # =========================================================

    def handle_event(
        self,
        event: Any,
    ) -> None:
        """
        EventBus subscriber.

        Faqat SecurityEvent qabul qiladi.

        Boshqa event turlari ignore qilinadi.
        """

        if not isinstance(
            event,
            SecurityEvent,
        ):
            self._ignored += 1
            return

        self._received += 1

        try:
            detection = (
                self.to_detection(
                    event
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            self._rejected += 1
            return

        except Exception:
            self._failed += 1
            return

        self._converted += 1

        if self.output_callback is None:
            return

        try:
            self.output_callback(
                detection
            )

        except Exception:
            self._failed += 1

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(
        self,
    ) -> dict[str, Any]:
        return {
            "component": (
                "SecurityEventBridge"
            ),
            "status": "HEALTHY",
            "version": self.VERSION,
            "callback_enabled": (
                self.output_callback is not None
            ),
        }

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict[str, Any]:
        return {
            "component": (
                "SecurityEventBridge"
            ),
            "version": self.VERSION,
            "received": self._received,
            "converted": self._converted,
            "ignored": self._ignored,
            "rejected": self._rejected,
            "failed": self._failed,
            "callback_enabled": (
                self.output_callback is not None
            ),
        }
