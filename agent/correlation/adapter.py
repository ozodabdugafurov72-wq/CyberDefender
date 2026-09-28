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
        *,
        incident_outbox: Any | None = None,
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
        self.incident_outbox = incident_outbox
        self.ack_callback = ack_callback

        self._received = 0
        self._published = 0
        self._ignored = 0
        self._failed = 0

        self._acked = 0
        self._ack_failed = 0
        self._outbox_failures = 0
# =========================================================
    # HEALTH
    # =========================================================

    def health_check(self) -> dict:
        outbox_health = None
        if self.incident_outbox is not None:
            health = getattr(self.incident_outbox, "health_snapshot", None)
            if not callable(health):
                return {
                    "adapter": "CorrelationAdapter",
                    "status": "DEGRADED",
                    "version": self.VERSION,
                    "ack_enabled": self.ack_callback is not None,
                    "outbox": {"status": "UNKNOWN"},
                }
            try:
                outbox_health = health()
            except Exception:
                outbox_health = {"status": "FAILED"}
        adapter_status = "HEALTHY"
        if isinstance(outbox_health, dict) and outbox_health.get("status") not in {None, "HEALTHY"}:
            adapter_status = "FAILED" if outbox_health.get("status") == "FAILED" else "DEGRADED"
        return {
            "adapter": "CorrelationAdapter",
            "status": adapter_status,
            "version": self.VERSION,
            "ack_enabled": (
                self.ack_callback is not None
            ),
            "outbox": outbox_health,
        }

    # =========================================================
    # EVENT HANDLER
    # =========================================================

    def handle_event(self, event: Any) -> bool:
        """Return explicit consumption success; contain all downstream errors.

        Publication runs before the engine commits duplicate suppression.
        No callback means the caller owns durable ACK (the canonical runtime).
        """
        if not isinstance(event, dict) or event.get("event_type") != "DETECTION":
            self._ignored += 1
            return False
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            self._ignored += 1
            return False
        self._received += 1
        try:
            tenant_id = None
            data = event.get("data")
            if isinstance(data, dict):
                tenant_id = data.get("tenant_id")
            if self.incident_outbox is not None and (
                not isinstance(tenant_id, str) or not tenant_id.strip()
            ):
                raise ValueError("tenant identity required for durable incident outbox")

            published_before = self._published
            source_event_id = event_id.strip()
            incident = self.engine.ingest(
                event,
                strict=True,
                publish=(
                    lambda candidate: self._persist_then_publish(
                        candidate,
                        tenant_id=tenant_id,
                        source_event_id=source_event_id,
                    )
                    if self.incident_outbox is not None
                    else self._publish_incident(candidate)
                ),
            )
            if incident is not None and (
                not isinstance(incident, dict)
                or incident.get("event_type") != "INCIDENT"
                or self._published != published_before + 1
            ):
                raise RuntimeError("unknown correlation result")
            if incident is None and self.incident_outbox is not None:
                if not self._confirm_replay_outbox(
                    tenant_id=tenant_id,
                    source_event_id=source_event_id,
                ):
                    raise RuntimeError("durable incident outbox replay not confirmed")
            # In strict mode None means an existing duplicate, never an error.
            return self._ack_event(event_id)
        except Exception:
            self._failed += 1
            if self.incident_outbox is not None:
                self._outbox_failures += 1
            return False

    def _publish_incident(self, incident: dict) -> bool:
        if self.event_bus.publish(incident) is not True:
            return False
        self._published += 1
        return True

    def _persist_then_publish(
        self,
        incident: dict,
        *,
        tenant_id: Any,
        source_event_id: str,
    ) -> bool:
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            return False
        if incident.get("source_event_id") != source_event_id:
            return False
        incident_id = incident.get("incident_id")
        idempotency_key = incident.get("idempotency_key")
        if not isinstance(incident_id, str) or not incident_id.strip():
            return False
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            return False
        put = getattr(self.incident_outbox, "put_if_absent", None)
        if not callable(put):
            return False
        try:
            stored, reused = put(
                tenant_id=tenant_id.strip(),
                source_event_id=source_event_id,
                incident_id=incident_id.strip(),
                idempotency_key=idempotency_key.strip(),
                incident_payload=dict(incident),
            )
            if not isinstance(stored, dict) or stored.get("state") == "CORRUPT":
                return False
            if stored.get("tenant_id") != tenant_id.strip():
                return False
            if stored.get("source_event_id") != source_event_id:
                return False
        except Exception:
            return False
        return self._publish_incident(incident)

    def _confirm_replay_outbox(
        self,
        *,
        tenant_id: Any,
        source_event_id: str,
    ) -> bool:
        scan = getattr(self.incident_outbox, "scan", None)
        if not callable(scan) or not isinstance(tenant_id, str):
            return False
        try:
            records = scan()
        except Exception:
            return False
        return any(
            isinstance(record, dict)
            and record.get("tenant_id") == tenant_id.strip()
            and record.get("source_event_id") == source_event_id
            and record.get("state") in {"PENDING", "DISPATCHING", "DELIVERED", "REVIEW_REQUIRED"}
            for record in records
        )

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

            if result is True:
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
            "outbox_failures": self._outbox_failures,
            "ack_enabled": (
                self.ack_callback is not None
            ),
        }

