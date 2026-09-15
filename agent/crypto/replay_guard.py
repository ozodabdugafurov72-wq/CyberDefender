from __future__ import annotations

from collections import OrderedDict
from threading import Lock
from typing import Optional


class ReplayGuard:
    """
    CyberDefender P11.2 - Replay Protection.

    Maqsad:
        Cryptographically valid event qayta yuborilganda,
        uni yangi event sifatida qabul qilmaslik.

    Model:

        Event ID
            |
            v
        Already seen?
          /       \
        YES       NO
         |         |
       REJECT    ACCEPT
                   |
                   v
              remember ID

    Muhim:
    - ReplayGuard signature verification o'rnini bosmaydi.
    - U faqat event identity/replay holatini boshqaradi.
    - Production'da persistent/redundant state kerak bo'ladi.
    """

    VERSION = "1.0"

    def __init__(
        self,
        max_entries: int = 100_000,
    ):
        if not isinstance(max_entries, int):
            raise TypeError(
                "max_entries integer bo'lishi kerak"
            )

        if max_entries <= 0:
            raise ValueError(
                "max_entries 0 dan katta bo'lishi kerak"
            )

        self._max_entries = max_entries

        self._seen: OrderedDict[str, None] = (
            OrderedDict()
        )

        self._lock = Lock()

        self._accepted = 0
        self._duplicates = 0
        self._invalid_ids = 0
        self._evictions = 0

    def check_and_remember(
        self,
        event_id: Optional[str],
    ) -> bool:
        """
        Event ID yangi bo'lsa ACCEPT.

        Event ID oldin ko'rilgan bo'lsa REJECT.

        Returns:
            True  -> yangi event
            False -> replay/invalid
        """

        if not isinstance(
            event_id,
            str,
        ):
            with self._lock:
                self._invalid_ids += 1

            return False

        event_id = event_id.strip()

        if not event_id:
            with self._lock:
                self._invalid_ids += 1

            return False

        with self._lock:
            if event_id in self._seen:
                self._duplicates += 1

                # LRU behavior:
                # qayta ko'rilgan ID'ni oxiriga o'tkazmaymiz.
                # U original acceptance vaqtini saqlab qoladi.
                return False

            self._seen[event_id] = None
            self._accepted += 1

            if len(self._seen) > self._max_entries:
                self._seen.popitem(
                    last=False
                )

                self._evictions += 1

            return True

    def contains(
        self,
        event_id: Optional[str],
    ) -> bool:
        if not isinstance(
            event_id,
            str,
        ):
            return False

        event_id = event_id.strip()

        if not event_id:
            return False

        with self._lock:
            return event_id in self._seen

    def remove(
        self,
        event_id: Optional[str],
    ) -> bool:
        """
        Faqat explicit administrative/test cleanup uchun.

        Oddiy replay flow'da remove qilinmasligi kerak.
        """

        if not isinstance(
            event_id,
            str,
        ):
            return False

        event_id = event_id.strip()

        if not event_id:
            return False

        with self._lock:
            if event_id not in self._seen:
                return False

            del self._seen[event_id]

            return True

    def size(self) -> int:
        with self._lock:
            return len(self._seen)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "component": "ReplayGuard",
                "version": self.VERSION,
                "max_entries": self._max_entries,
                "tracked": len(self._seen),
                "accepted": self._accepted,
                "duplicates": self._duplicates,
                "invalid_ids": self._invalid_ids,
                "evictions": self._evictions,
            }

    def health_check(self) -> dict:
        return {
            "component": "ReplayGuard",
            "status": "HEALTHY",
            "version": self.VERSION,
            "max_entries": self._max_entries,
        }
