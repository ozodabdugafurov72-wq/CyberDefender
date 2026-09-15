from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable, Optional

from agent.bus.event_bus import EventBus
from agent.event import SecurityEvent
from agent.storage.durable_spool import (
    DurableEventSpool,
    SpoolError,
)


@dataclass(frozen=True)
class DurableTransportResult:
    """P0.3B tri-state durable transport result.

    ADMITTED:
        Event is durably persisted and immediately published.

    PERSISTED_DEFERRED:
        Event is durably persisted, but delivery is deferred.  This is not a
        security rejection and must not be confused with a failed durable
        commit.

    REJECTED:
        Event did not enter the durable trusted boundary.
    """

    disposition: str
    accepted: bool
    durable: bool
    published: bool
    retryable: bool
    reason: str
    event_id: Optional[str]
    fail_closed: bool = True
    component: str = "DurableEventPipeline"
    version: str = "1.3"
    transport_contract_version: str = "P0.3B-1"


class DurableEventPipeline:
    """
    CyberDefender Durable Event Pipeline v1.3 + P0.3B transport contract.

    Hardened runtime delivery boundary.

    Security flow:

        SecurityEvent
             |
             v
        INPUT VALIDATION
             |
             v
        INTEGRITY CHECK
             |
             v
        DURABLE SPOOL
             |
             v
        EVENT BUS
             |
             v
        CONSUMER
             |
             v
        EXPLICIT ACK
             |
             v
        TERMINAL ACKED

    Failure principle:

        ANY uncertain state
             |
             v
        FAIL CLOSED / KEEP PENDING

    Delivery semantics:

        AT-LEAST-ONCE

    Important:

        publish != processing success
        publish != ACK

    ACK is performed only after successful consumer processing.

    This component does not depend on network/cloud availability.
    """

    VERSION = "1.3"
    TRANSPORT_CONTRACT_VERSION = "P0.3B-1"

    STATUS_HEALTHY = "HEALTHY"
    STATUS_DEGRADED = "DEGRADED"
    STATUS_FAILED = "FAILED"

    # =========================================================
    # INIT
    # =========================================================

    def __init__(
        self,
        spool: DurableEventSpool,
        event_bus: EventBus,
        delivery_gateway: Any | None = None,
    ):
        if spool is None:
            raise ValueError(
                "spool berilishi kerak"
            )

        if event_bus is None:
            raise ValueError(
                "event_bus berilishi kerak"
            )

        self.spool = spool
        self.event_bus = event_bus
        # Optional P0.3B/P0.4 delivery boundary.  The durable spool remains
        # authoritative; this component never lets delivery deferral erase a
        # successfully persisted event.
        self.delivery_gateway = delivery_gateway

        self._lock = RLock()

        # -----------------------------------------------------
        # INGEST
        # -----------------------------------------------------

        self._spooled = 0
        self._duplicates = 0
        self._rejected = 0

        # -----------------------------------------------------
        # INPUT / INTEGRITY
        # -----------------------------------------------------

        self._invalid_events = 0
        self._integrity_rejected = 0

        # -----------------------------------------------------
        # STORAGE
        # -----------------------------------------------------

        self._spool_failed = 0

        # -----------------------------------------------------
        # TRANSPORT
        # -----------------------------------------------------

        self._published = 0
        self._publish_failed = 0
        self._persisted_deferred = 0
        self._delivery_deferred = 0

        # -----------------------------------------------------
        # ACK
        # -----------------------------------------------------

        self._acked = 0
        self._ack_failed = 0

        # -----------------------------------------------------
        # RECOVERY
        # -----------------------------------------------------

        self._replayed = 0
        self._replay_failed = 0

        # -----------------------------------------------------
        # EXCEPTIONS
        # -----------------------------------------------------

        self._exceptions = 0

        # -----------------------------------------------------
        # HEALTH / DIAGNOSTICS
        # -----------------------------------------------------

        self._health_checks = 0
        self._health_failures = 0

        self._last_error: Optional[str] = None
        self._last_error_component: Optional[str] = None

    # =========================================================
    # ERROR RECORDING
    # =========================================================

    def _record_error(
        self,
        component: str,
        error: BaseException | str,
    ) -> None:
        with self._lock:
            self._exceptions += 1
            self._last_error_component = component

            if isinstance(error, BaseException):
                self._last_error = (
                    f"{type(error).__name__}: {error}"
                )
            else:
                self._last_error = str(error)

    # =========================================================
    # EVENT VALIDATION
    # =========================================================

    @staticmethod
    def _valid_event(
        event: Any,
    ) -> bool:
        return isinstance(
            event,
            SecurityEvent,
        )

    # =========================================================
    # EVENT ID
    # =========================================================

    @staticmethod
    def _event_id(
        event: Any,
    ) -> Optional[str]:

        event_id = getattr(
            event,
            "event_id",
            None,
        )

        if not isinstance(
            event_id,
            str,
        ):
            return None

        event_id = event_id.strip()

        if not event_id:
            return None

        return event_id

    # =========================================================
    # INTEGRITY
    # =========================================================

    @staticmethod
    def _verify_integrity(
        event: SecurityEvent,
    ) -> bool:

        try:
            return bool(
                event.verify_integrity()
            )
        except Exception:
            return False

    # =========================================================
    # P0.3B TRANSPORT RESULT HELPERS
    # =========================================================

    DISPOSITION_ADMITTED = "ADMITTED"
    DISPOSITION_PERSISTED_DEFERRED = "PERSISTED_DEFERRED"
    DISPOSITION_REJECTED = "REJECTED"

    @classmethod
    def _transport_result(
        cls,
        *,
        disposition: str,
        accepted: bool,
        durable: bool,
        published: bool,
        retryable: bool,
        reason: str,
        event_id: Optional[str],
    ) -> DurableTransportResult:
        return DurableTransportResult(
            disposition=disposition,
            accepted=accepted,
            durable=durable,
            published=published,
            retryable=retryable,
            reason=reason,
            event_id=event_id,
        )

    def _delivery_target(self) -> Any:
        return self.delivery_gateway if self.delivery_gateway is not None else self.event_bus

    def _publish_detailed(self, event: SecurityEvent) -> tuple[bool, str, bool]:
        """Return (published, reason, retryable) for immediate delivery.

        Delivery failure after durable persistence is always retryable from the
        spool.  A detailed resource gate may distinguish policy deferral from
        hard input rejection; invalid input is impossible here because the
        SecurityEvent already passed pipeline validation and integrity checks.
        """
        target = self._delivery_target()
        detailed = getattr(target, "publish_detailed", None)

        if callable(detailed):
            result = detailed(event)
            delivered = bool(getattr(result, "delivered", False))
            reason = str(getattr(result, "reason", "DELIVERY_DEFERRED"))
            retryable = bool(getattr(result, "retryable", not delivered))
            return delivered, reason, retryable

        published = target.publish(event)
        if published is True:
            return True, "ADMITTED", False
        return False, "EVENTBUS_DEFERRED", True

    def ingest_detailed(
        self,
        event: SecurityEvent,
    ) -> DurableTransportResult:
        """P0.3B tri-state durable admission contract.

        A post-persistence delivery deferral is represented as
        PERSISTED_DEFERRED, never as a durable/security rejection.
        """

        if not self._valid_event(event):
            with self._lock:
                self._invalid_events += 1
                self._rejected += 1
            return self._transport_result(
                disposition=self.DISPOSITION_REJECTED,
                accepted=False,
                durable=False,
                published=False,
                retryable=False,
                reason="INVALID_SECURITY_EVENT",
                event_id=None,
            )

        event_id = self._event_id(event)
        if event_id is None:
            with self._lock:
                self._invalid_events += 1
                self._rejected += 1
            return self._transport_result(
                disposition=self.DISPOSITION_REJECTED,
                accepted=False,
                durable=False,
                published=False,
                retryable=False,
                reason="INVALID_EVENT_ID",
                event_id=None,
            )

        if not self._verify_integrity(event):
            with self._lock:
                self._integrity_rejected += 1
                self._rejected += 1
            return self._transport_result(
                disposition=self.DISPOSITION_REJECTED,
                accepted=False,
                durable=False,
                published=False,
                retryable=False,
                reason="INTEGRITY_REJECTED",
                event_id=event_id,
            )

        try:
            append_detailed = getattr(self.spool, "append_with_result", None)
            if callable(append_detailed):
                stored_result = append_detailed(event)
                stored = bool(getattr(stored_result, "accepted", False))
                durable = bool(getattr(stored_result, "durable", stored))
                storage_reason = str(getattr(stored_result, "reason", "SPOOL_REJECTED"))
            else:
                stored = self.spool.append(event) is True
                durable = stored
                storage_reason = "ADMITTED" if stored else "SPOOL_REJECTED"
        except SpoolError as exc:
            self._record_error("spool", exc)
            with self._lock:
                self._spool_failed += 1
                self._rejected += 1
            return self._transport_result(
                disposition=self.DISPOSITION_REJECTED,
                accepted=False,
                durable=False,
                published=False,
                retryable=True,
                reason="DURABLE_WRITE_FAILED",
                event_id=event_id,
            )
        except Exception as exc:
            self._record_error("spool", exc)
            with self._lock:
                self._spool_failed += 1
                self._rejected += 1
            return self._transport_result(
                disposition=self.DISPOSITION_REJECTED,
                accepted=False,
                durable=False,
                published=False,
                retryable=True,
                reason=f"SPOOL_EXCEPTION:{type(exc).__name__}",
                event_id=event_id,
            )

        if not stored or not durable:
            # A duplicate PENDING record means the exact event already crossed
            # the durable boundary earlier.  Treating that as a new security
            # rejection would be wrong after restart/retry; it is an
            # idempotent persisted deferral.
            if storage_reason == "DUPLICATE_PENDING":
                with self._lock:
                    self._duplicates += 1
                    self._persisted_deferred += 1
                return self._transport_result(
                    disposition=self.DISPOSITION_PERSISTED_DEFERRED,
                    accepted=True,
                    durable=True,
                    published=False,
                    retryable=True,
                    reason="ALREADY_PENDING",
                    event_id=event_id,
                )

            with self._lock:
                if storage_reason.startswith("DUPLICATE"):
                    self._duplicates += 1
                else:
                    self._rejected += 1
            return self._transport_result(
                disposition=self.DISPOSITION_REJECTED,
                accepted=False,
                durable=False,
                published=False,
                retryable=storage_reason in {
                    "PROTECTED_RESERVE",
                    "TOTAL_CAPACITY_EXHAUSTED",
                    "RECOVERY_SCAN_LIMIT_EXCEEDED",
                    "DURABLE_WRITE_FAILED",
                },
                reason=storage_reason,
                event_id=event_id,
            )

        with self._lock:
            self._spooled += 1

        try:
            published, delivery_reason, retryable = self._publish_detailed(event)
        except Exception as exc:
            self._record_error("delivery", exc)
            published = False
            delivery_reason = f"DELIVERY_EXCEPTION:{type(exc).__name__}"
            retryable = True

        if published:
            with self._lock:
                self._published += 1
            return self._transport_result(
                disposition=self.DISPOSITION_ADMITTED,
                accepted=True,
                durable=True,
                published=True,
                retryable=False,
                reason="EVENT_ADMITTED",
                event_id=event_id,
            )

        # The event is already durable.  Keeping it pending is the correct
        # security action.  This is not a rejection and not a false failure.
        with self._lock:
            self._persisted_deferred += 1
            self._delivery_deferred += 1

        return self._transport_result(
            disposition=self.DISPOSITION_PERSISTED_DEFERRED,
            accepted=True,
            durable=True,
            published=False,
            retryable=True if retryable is not False else True,
            reason=delivery_reason,
            event_id=event_id,
        )

    # =========================================================
    # INGEST
    # =========================================================

    def ingest(
        self,
        event: SecurityEvent,
    ) -> bool:
        """
        Securely admit an event into durable transport.

        Success:

            valid event
                ↓
            integrity valid
                ↓
            durable spool
                ↓
            EventBus publish
                ↓
            True

        IMPORTANT:

            True does NOT mean ACK.

        ACK must be performed later by the consumer.
        """

        # -----------------------------------------------------
        # INPUT TYPE
        # -----------------------------------------------------

        if not self._valid_event(event):
            with self._lock:
                self._invalid_events += 1
                self._rejected += 1

            return False

        # -----------------------------------------------------
        # EVENT ID
        # -----------------------------------------------------

        event_id = self._event_id(event)

        if event_id is None:
            with self._lock:
                self._invalid_events += 1
                self._rejected += 1

            return False

        # -----------------------------------------------------
        # INTEGRITY
        # -----------------------------------------------------

        try:
            valid = self._verify_integrity(
                event
            )

        except Exception as exc:
            self._record_error(
                "integrity",
                exc,
            )

            valid = False

        if not valid:
            with self._lock:
                self._integrity_rejected += 1
                self._rejected += 1

            return False

        # -----------------------------------------------------
        # DURABLE STORAGE
        # -----------------------------------------------------

        try:
            stored = self.spool.append(
                event
            )

        except SpoolError as exc:
            self._record_error(
                "spool",
                exc,
            )

            with self._lock:
                self._spool_failed += 1
                self._rejected += 1

            return False

        except Exception as exc:
            self._record_error(
                "spool",
                exc,
            )

            with self._lock:
                self._spool_failed += 1
                self._rejected += 1

            return False

        # -----------------------------------------------------
        # DUPLICATE
        # -----------------------------------------------------

        if stored is not True:
            with self._lock:
                self._duplicates += 1

            return False

        with self._lock:
            self._spooled += 1

        # -----------------------------------------------------
        # EVENT BUS
        # -----------------------------------------------------

        try:
            published = self.event_bus.publish(
                event
            )

        except Exception as exc:
            self._record_error(
                "event_bus",
                exc,
            )

            published = False

        # -----------------------------------------------------
        # BUS FAILURE
        #
        # Event is already durable.
        # DO NOT ACK.
        # DO NOT delete.
        # DO NOT lose event.
        # -----------------------------------------------------

        if published is not True:
            with self._lock:
                self._publish_failed += 1

            return False

        with self._lock:
            self._published += 1

        # -----------------------------------------------------
        # IMPORTANT:
        #
        # NO ACK HERE.
        #
        # Consumer must call:
        #
        #     pipeline.ack(event.event_id)
        #
        # after successful processing.
        # -----------------------------------------------------

        return True

    # =========================================================
    # ACK
    # =========================================================

    def ack(
        self,
        event_id: str,
    ) -> bool:
        """
        Durable terminal acknowledgement.

        ACK is accepted only when DurableEventSpool
        confirms the terminal transition.
        """

        if not isinstance(
            event_id,
            str,
        ):
            with self._lock:
                self._ack_failed += 1

            return False

        event_id = event_id.strip()

        if not event_id:
            with self._lock:
                self._ack_failed += 1

            return False

        try:
            result = self.spool.ack(
                event_id
            )

        except SpoolError as exc:
            self._record_error(
                "spool_ack",
                exc,
            )

            with self._lock:
                self._ack_failed += 1

            return False

        except Exception as exc:
            self._record_error(
                "spool_ack",
                exc,
            )

            with self._lock:
                self._ack_failed += 1

            return False

        if result is True:
            with self._lock:
                self._acked += 1

            return True

        with self._lock:
            self._ack_failed += 1

        return False

    # =========================================================
    # BOUNDED RECOVERY SNAPSHOT
    # =========================================================

    def _pending_recovery_records(
        self,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get a bounded replay batch when the spool exposes that contract.

        Compatibility spools used by older tests may only expose
        pending_records(); those remain supported.
        """
        batch_method = getattr(self.spool, "pending_batch", None)
        if callable(batch_method):
            try:
                return batch_method(limit) if limit is not None else batch_method()
            except TypeError:
                return batch_method()

        records = self.spool.pending_records()
        if not isinstance(records, list):
            return []
        if limit is None:
            return records
        return records[: max(0, int(limit))]

    # =========================================================
    # PUBLISH PENDING
    # =========================================================

    def publish_pending(
        self,
        max_events: int | None = None,
    ) -> int:
        """
        Republish pending events.

        IMPORTANT:

            publish != ACK

        Therefore this method NEVER ACKs events.

        Invalid/corrupted records are isolated.
        One bad event must not terminate the entire
        recovery loop.
        """

        try:
            records = self._pending_recovery_records(max_events)

        except Exception as exc:
            self._record_error(
                "spool_pending_records",
                exc,
            )

            with self._lock:
                self._replay_failed += 1

            return 0

        published_count = 0

        for record in records:

            # -------------------------------------------------
            # STRUCTURE
            # -------------------------------------------------

            if not isinstance(
                record,
                dict,
            ):
                with self._lock:
                    self._replay_failed += 1

                continue

            event_id = record.get(
                "event_id"
            )

            event_data = record.get(
                "event"
            )

            if not isinstance(
                event_id,
                str,
            ):
                with self._lock:
                    self._replay_failed += 1
                    self._integrity_rejected += 1

                continue

            event_id = event_id.strip()

            if not event_id:
                with self._lock:
                    self._replay_failed += 1
                    self._integrity_rejected += 1

                continue

            if not isinstance(
                event_data,
                dict,
            ):
                with self._lock:
                    self._replay_failed += 1
                    self._integrity_rejected += 1

                continue

            # -------------------------------------------------
            # DESERIALIZATION
            # -------------------------------------------------

            try:
                event = SecurityEvent.from_dict(
                    event_data
                )

            except Exception as exc:
                self._record_error(
                    "event_deserialization",
                    exc,
                )

                with self._lock:
                    self._integrity_rejected += 1
                    self._replay_failed += 1

                continue

            # -------------------------------------------------
            # ID BINDING
            # -------------------------------------------------

            if event.event_id != event_id:
                with self._lock:
                    self._integrity_rejected += 1
                    self._replay_failed += 1

                continue

            # -------------------------------------------------
            # INTEGRITY
            # -------------------------------------------------

            try:
                valid = bool(
                    event.verify_integrity()
                )

            except Exception as exc:
                self._record_error(
                    "replay_integrity",
                    exc,
                )

                valid = False

            if not valid:
                with self._lock:
                    self._integrity_rejected += 1
                    self._replay_failed += 1

                continue

            # -------------------------------------------------
            # DELIVERY BOUNDARY
            # -------------------------------------------------

            try:
                delivered, _reason, _retryable = self._publish_detailed(event)

            except Exception as exc:
                self._record_error(
                    "delivery_replay",
                    exc,
                )
                delivered = False

            if not delivered:
                # Already-durable recovery work remains pending.  Delivery
                # pressure is not counted as a corrupted replay failure.
                with self._lock:
                    self._delivery_deferred += 1

                continue

            with self._lock:
                self._published += 1
                self._replayed += 1

            published_count += 1

        return published_count

    # =========================================================
    # REPLAY ALIAS
    # =========================================================

    def replay_pending(
        self,
    ) -> int:
        """
        Backward-compatible replay alias.

        Equivalent to publish_pending().
        """

        return self.publish_pending()

    # =========================================================
    # DEPENDENCY HEALTH
    # =========================================================

    @staticmethod
    def _dependency_health(
        component: Any,
        name: str,
    ) -> dict[str, Any]:

        health_method = getattr(
            component,
            "health_check",
            None,
        )

        # -----------------------------------------------------
        # Explicit health contract
        # -----------------------------------------------------

        if callable(health_method):
            try:
                result = health_method()

                if isinstance(
                    result,
                    dict,
                ):
                    return result

            except Exception as exc:
                return {
                    "component": name,
                    "status": "FAILED",
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    ),
                }

        # -----------------------------------------------------
        # Compatibility fallback
        #
        # Existing components may not yet expose health_check().
        # We use observable statistics rather than pretending
        # that the dependency is HEALTHY.
        # -----------------------------------------------------

        stats_method = getattr(
            component,
            "get_stats",
            None,
        )

        if callable(stats_method):
            try:
                stats = stats_method()

                if isinstance(
                    stats,
                    dict,
                ):
                    return {
                        "component": name,
                        "status": "DEGRADED",
                        "health_contract": "MISSING",
                        "stats_available": True,
                    }

            except Exception as exc:
                return {
                    "component": name,
                    "status": "FAILED",
                    "health_contract": "MISSING",
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    ),
                }

        return {
            "component": name,
            "status": "UNKNOWN",
            "health_contract": "MISSING",
        }

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(
        self,
    ) -> dict[str, Any]:
        """
        Full pipeline health.

        The pipeline never claims HEALTHY merely because
        the object exists.

        Dependency states are inspected independently.
        """

        with self._lock:
            self._health_checks += 1

        spool_health = self._dependency_health(
            self.spool,
            "DurableEventSpool",
        )

        bus_health = self._dependency_health(
            self.event_bus,
            "EventBus",
        )

        delivery_health = None
        if self.delivery_gateway is not None:
            delivery_health = self._dependency_health(
                self.delivery_gateway,
                "DeliveryGateway",
            )

        spool_status = spool_health.get(
            "status",
            "UNKNOWN",
        )

        bus_status = bus_health.get(
            "status",
            "UNKNOWN",
        )

        delivery_status = (
            self.STATUS_HEALTHY
            if delivery_health is None
            else delivery_health.get("status", "UNKNOWN")
        )

        # -----------------------------------------------------
        # FAILED
        # -----------------------------------------------------

        if (
            spool_status == self.STATUS_FAILED
            or bus_status == self.STATUS_FAILED
            or delivery_status == self.STATUS_FAILED
        ):
            status = self.STATUS_FAILED

        # -----------------------------------------------------
        # HEALTHY
        # -----------------------------------------------------

        elif (
            spool_status == self.STATUS_HEALTHY
            and bus_status == self.STATUS_HEALTHY
            and delivery_status == self.STATUS_HEALTHY
        ):
            status = self.STATUS_HEALTHY

        # -----------------------------------------------------
        # Everything else is DEGRADED.
        # -----------------------------------------------------

        else:
            status = self.STATUS_DEGRADED

        if status != self.STATUS_HEALTHY:
            with self._lock:
                self._health_failures += 1

        return {
            "pipeline": "DurableEventPipeline",
            "component": "DurableEventPipeline",
            "version": self.VERSION,
            "status": status,

            "dependencies": {
                "spool": spool_health,
                "event_bus": bus_health,
                "delivery_gateway": delivery_health,
            },

            "counters": {
                "spooled": self._spooled,
                "duplicates": self._duplicates,
                "rejected": self._rejected,
                "invalid_events": self._invalid_events,
                "integrity_rejected": (
                    self._integrity_rejected
                ),
                "spool_failed": (
                    self._spool_failed
                ),
                "published": self._published,
                "publish_failed": (
                    self._publish_failed
                ),
                "persisted_deferred": self._persisted_deferred,
                "delivery_deferred": self._delivery_deferred,
                "acked": self._acked,
                "ack_failed": self._ack_failed,
                "replayed": self._replayed,
                "replay_failed": (
                    self._replay_failed
                ),
                "exceptions": self._exceptions,
                "health_checks": (
                    self._health_checks
                ),
                "health_failures": (
                    self._health_failures
                ),
            },

            "last_error": self._last_error,
            "last_error_component": (
                self._last_error_component
            ),
        }

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict[str, Any]:
        """
        Complete pipeline observability statistics.
        """

        with self._lock:
            return {
                "pipeline":
                    "DurableEventPipeline",

                "version":
                    self.VERSION,

                # Durable ingest
                "spooled":
                    self._spooled,

                "duplicates":
                    self._duplicates,

                "rejected":
                    self._rejected,

                "invalid_events":
                    self._invalid_events,

                # Integrity
                "integrity_rejected":
                    self._integrity_rejected,

                # Storage
                "spool_failed":
                    self._spool_failed,

                # Transport
                "published":
                    self._published,

                "publish_failed":
                    self._publish_failed,

                "persisted_deferred":
                    self._persisted_deferred,

                "delivery_deferred":
                    self._delivery_deferred,

                # ACK
                "acked":
                    self._acked,

                "ack_failed":
                    self._ack_failed,

                # Replay
                "replayed":
                    self._replayed,

                "replay_failed":
                    self._replay_failed,

                # Exceptions
                "exceptions":
                    self._exceptions,

                # Health
                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_error":
                    self._last_error,

                "last_error_component":
                    self._last_error_component,
            }