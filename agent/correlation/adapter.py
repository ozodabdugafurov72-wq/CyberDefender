from __future__ import annotations

from typing import Any, Callable, Optional

from agent.bus.event_bus import EventBus
from agent.correlation.engine import CorrelationEngine


class CorrelationAdapter:
    """
    CyberDefender CorrelationAdapter v1.1

    Vazifasi:

        DETECTION
            ↓
        CorrelationEngine
            ↓
        INCIDENT
            ↓
        EventBus

    Durable pipeline bilan ishlaganda:

        successful processing
            ↓
        ACK callback

    Muhim invariant:

        - engine failure        -> NO ACK
        - incident publish fail -> NO ACK
        - successful processing -> ACK
        - duplicate/rejected   -> ACK
          (event consumer tomonidan qayta ishlanib,
           xavfsiz ravishda discard qilingan)
    """

    VERSION = "1.1"

    def __init__(
        self,
        engine: CorrelationEngine,
        event_bus: EventBus,
        ack_callback: Optional[
            Callable[[str], bool]
        ] = None,
    ):
        if engine is None:
            raise ValueError(
                "engine berilishi kerak"
            )

        if event_bus is None:
            raise ValueError(
                "event_bus berilishi kerak"
            )

        if (
            ack_callback is not None
            and not callable(ack_callback)
        ):
            raise TypeError(
                "ack_callback callable bo'lishi kerak"
            )

        self.engine = engine
        self.event_bus = event_bus
        self.ack_callback = ack_callback

        self._received = 0
        self._published = 0
        self._ignored = 0
        self._failed = 0

        self._acked = 0
        self._ack_failed = 0
# =========================================================
    # HEALTH
    # =========================================================

    def health_check(self) -> dict:
        return {
            "adapter": "CorrelationAdapter",
            "status": "HEALTHY",
            "version": self.VERSION,
            "ack_enabled": (
                self.ack_callback is not None
            ),
        }

    # =========================================================
    # EVENT HANDLER
    # =========================================================

    def handle_event(
        self,
        event: Any,
    ) -> None:
        """
        EventBus'dan DETECTION eventlarini qabul qiladi.

        INCIDENT eventlari ignore qilinadi.

        ACK faqat:
            1. event valid consumer input bo'lsa
            2. engine processing muvaffaqiyatli tugasa
            3. kerakli INCIDENT publish muvaffaqiyatli bo'lsa

        Engine exception yoki INCIDENT publish failure
        bo'lsa ACK qilinmaydi.
        """

        if not isinstance(event, dict):
            self._ignored += 1
            return

        if event.get("event_type") != "DETECTION":
            self._ignored += 1
            return

        self._received += 1

        event_id = event.get(
            "event_id"
        )

        try:
            incident = self.engine.ingest(
                event
            )

            # -------------------------------------------------
            # Duplicate / rejected event
            # -------------------------------------------------
            #
            # Engine exception bermadi.
            # Demak consumer eventni xavfsiz tarzda
            # qayta ishladi yoki reject qildi.
            #
            # Bunday poison/duplicate eventni abadiy
            # replay qilish kerak emas.
            #
            if incident is None:
                self._ack_event(
                    event_id
                )
                return

            # -------------------------------------------------
            # Publish INCIDENT
            # -------------------------------------------------

            published = self.event_bus.publish(
                incident
            )

            if not published:
                self._failed += 1
                return

            self._published += 1

            # -------------------------------------------------
            # ACK faqat INCIDENT publish muvaffaqiyatli
            # bo'lgandan keyin.
            # -------------------------------------------------

            self._ack_event(
                event_id
            )

        except Exception:
            # Engine yoki boshqa processing xatosi.
            #
            # Eng muhim invariant:
            #
            #     EXCEPTION -> NO ACK
            #
            # Event durable spool'da qoladi.
            self._failed += 1

    # =========================================================
    # ACK
    # =========================================================

    def _ack_event(
        self,
        event_id: Any,
    ) -> bool:
        """
        Eventni durable pipeline orqali ACK qiladi.

        event_id mavjud bo'lmasa:
            ACK qilinmaydi.

        ack callback mavjud bo'lmasa:
            adapter standalone mode'da ishlaydi.
        """

        if self.ack_callback is None:
            return True

        if not event_id:
            self._ack_failed += 1
            return False

        try:
            result = self.ack_callback(
                str(event_id)
            )

            if result:
                self._acked += 1
                return True

            self._ack_failed += 1
            return False

        except Exception:
            self._ack_failed += 1
            return False

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(self) -> dict:
        return {
            "adapter": "CorrelationAdapter",
            "version": self.VERSION,
            "received": self._received,
            "published": self._published,
            "ignored": self._ignored,
            "failed": self._failed,
            "acked": self._acked,
            "ack_failed": self._ack_failed,
            "ack_enabled": (
                self.ack_callback is not None
            ),
        }

