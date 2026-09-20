from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from agent.crypto.key_manager import KeyManager
from agent.crypto.replay_guard import ReplayGuard
from agent.crypto.trust_decision_boundary import (
    TrustDecisionBoundary,
)


@dataclass(frozen=True)
class AdmissionDecision:
    """
    CyberDefender P11.19.1

    Detailed admission decision.

    Security boundary ichidagi qarorni
    yuqori runtime qatlamlariga xavfsiz
    va aniq ko'rinishda uzatadi.

    Boolean compatibility:
        accepted=True / False

    Detailed contract:
        reason
        stage
        retryable
        fail_closed
        error_code
        event_id
        key_id
    """

    accepted: bool
    reason: str
    stage: str

    event_id: Optional[str] = None
    key_id: Optional[str] = None

    retryable: bool = False
    fail_closed: bool = True

    error_code: Optional[str] = None

    # P0.4 transport semantics.  Defaults preserve all legacy callers.
    disposition: Optional[str] = None
    durable: bool = False
    published: bool = False
    replay_reservation_kept: bool = False
    durability_uncertain: bool = False

    component: str = (
        "CryptoReplayAdmissionGateway"
    )

    version: str = "1.2"


class CryptoReplayAdmissionGateway:
    """
    CyberDefender P11.19.1

    Cryptographic Trust
        +
    Replay Protection
        +
    Durable Pipeline Admission

    Security order:

        SecurityEvent
             |
             v
        Canonicalize
             |
             v
        Cryptographic Trust
             |
       +-----+------+
       |            |
    REJECT        ACCEPT
       |            |
       X            v
               ReplayGuard
                   |
             +-----+------+
             |            |
          REPLAY         NEW
             |            |
             X            v
                     DurablePipeline
                           |
                    +------+------+
                    |             |
                  FAIL          SUCCESS
                    |             |
                    v             v
                 ROLLBACK       ACCEPT

    Security invariants:

    1. Crypto rejection -> no replay reservation.
    2. Replay rejection -> no durable ingestion.
    3. Durable failure -> replay reservation rollback.
    4. Exception after replay reservation -> rollback.
    5. Fail closed by default.
    6. Existing bool API remains compatible.
    7. Detailed API exposes exact security stage.
    """

    VERSION = "1.2"
    RUNTIME_TRANSPORT_CONTRACT_VERSION = "P0.4-1"

    # =========================================================
    # STAGES
    # =========================================================

    STAGE_INPUT = "INPUT_VALIDATION"
    STAGE_CRYPTO = "CRYPTO_TRUST"
    STAGE_REPLAY = "REPLAY_PROTECTION"
    STAGE_DURABLE = "DURABLE_PIPELINE"
    STAGE_ADMITTED = "ADMITTED"
    STAGE_ADMISSION = "ADMISSION"

    # =========================================================
    # REASONS
    # =========================================================

    REASON_ADMITTED = "EVENT_ADMITTED"

    REASON_INVALID_EVENT = (
        "INVALID_SECURITY_EVENT"
    )

    REASON_KEY_MANAGER_DEGRADED = (
        "KEY_MANAGER_DEGRADED"
    )

    REASON_ACTIVE_KEY_UNAVAILABLE = (
        "ACTIVE_KEY_UNAVAILABLE"
    )

    REASON_UNKNOWN_KEY = (
        "UNKNOWN_KEY"
    )

    REASON_REVOKED_KEY = (
        "REVOKED_KEY"
    )

    REASON_RETIRED_KEY = (
        "RETIRED_KEY"
    )

    REASON_INVALID_KEY_STATE = (
        "INVALID_KEY_STATE"
    )

    REASON_INVALID_SIGNATURE = (
        "INVALID_SIGNATURE"
    )

    REASON_REPLAY = (
        "REPLAY_REJECTED"
    )

    REASON_PIPELINE_FAILURE = (
        "DURABLE_PIPELINE_FAILED"
    )

    REASON_PERSISTED_DEFERRED = (
        "EVENT_PERSISTED_DEFERRED"
    )

    REASON_EXCEPTION = (
        "ADMISSION_EXCEPTION"
    )

    # =========================================================
    # INIT
    # =========================================================

    def __init__(
        self,
        key_manager: KeyManager,
        replay_guard: ReplayGuard,
        pipeline: Any,
        *,
        use_detailed_transport: bool = False,
    ):
        if key_manager is None:
            raise ValueError(
                "key_manager kerak"
            )

        if replay_guard is None:
            raise ValueError(
                "replay_guard kerak"
            )

        if pipeline is None:
            raise ValueError(
                "pipeline kerak"
            )

        self.key_manager = key_manager
        self.replay_guard = replay_guard
        self.pipeline = pipeline
        self.use_detailed_transport = bool(use_detailed_transport)

        self.boundary = (
            TrustDecisionBoundary(
                key_manager
            )
        )

        self.received = 0
        self.accepted = 0
        self.rejected = 0

        self.crypto_rejected = 0
        self.replay_rejected = 0
        self.pipeline_failed = 0
        self.persisted_deferred = 0
        self.replay_rollbacks = 0
        self.replay_rollback_failures = 0
        self.degraded = 0

        self.invalid_events = 0
        self.exceptions = 0

    ADMISSION_DOMAIN = b"CyberDefender/admitted-security-event/v1\x00"

    def verify_admission_receipt(self, event, receipt) -> bool:
        """Verify persisted admission proof; confers no response authority."""
        try:
            if not isinstance(receipt, dict) or set(receipt) != {"key_id", "signature"}:
                return False

            if not all(
                isinstance(value, str) and 0 < len(value) <= 256
                for value in receipt.values()
            ):
                return False

            verify_recovery = getattr(
                self.key_manager,
                "verify_for_recovery",
                None,
            )

            if not callable(verify_recovery):
                return False

            return verify_recovery(
                self.ADMISSION_DOMAIN + self.canonicalize_event(event),
                receipt["signature"],
                receipt["key_id"],
            ) is True

        except Exception:
            return False

    # =========================================================
    # CANONICAL EVENT REPRESENTATION
    # =========================================================

    @staticmethod
    def canonicalize_event(
        event: Any,
    ) -> bytes:

        if event is None:
            raise ValueError(
                "event kerak"
            )

        if not hasattr(
            event,
            "to_dict",
        ):
            raise TypeError(
                "event.to_dict() mavjud bo'lishi kerak"
            )

        data = event.to_dict()

        if not isinstance(
            data,
            dict,
        ):
            raise TypeError(
                "event.to_dict() dict qaytarishi kerak"
            )

        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    # =========================================================
    # RESULT BUILDER
    # =========================================================

    @staticmethod
    def _decision(
        *,
        accepted: bool,
        reason: str,
        stage: str,
        event_id: Optional[str] = None,
        key_id: Optional[str] = None,
        retryable: bool = False,
        fail_closed: bool = True,
        error_code: Optional[str] = None,
        disposition: Optional[str] = None,
        durable: bool = False,
        published: bool = False,
        replay_reservation_kept: bool = False,
        durability_uncertain: bool = False,
    ) -> AdmissionDecision:

        return AdmissionDecision(
            accepted=accepted,
            reason=reason,
            stage=stage,
            event_id=event_id,
            key_id=key_id,
            retryable=retryable,
            fail_closed=fail_closed,
            error_code=error_code,
            disposition=disposition,
            durable=durable,
            published=published,
            replay_reservation_kept=replay_reservation_kept,
            durability_uncertain=durability_uncertain,
        )

    # =========================================================
    # REPLAY RESERVATION ROLLBACK
    # =========================================================

    def _rollback_replay_reservation(
        self,
        event_id: str,
    ) -> bool:
        """Rollback only when durability is known not to have happened.

        P0.4 never rolls back a replay reservation for an event that has
        crossed the durable boundary.  That prevents a persisted-but-deferred
        event from being admitted a second time during the same process.
        """
        remove = getattr(self.replay_guard, "remove", None)

        if not callable(remove):
            self.degraded += 1
            self.replay_rollback_failures += 1
            return False

        try:
            removed = bool(remove(event_id))
        except Exception:
            self.degraded += 1
            self.replay_rollback_failures += 1
            return False

        if removed:
            self.replay_rollbacks += 1
            return True

        # Reservation was expected to exist.  Failure to remove it is a
        # degraded condition because retry semantics can no longer be proven.
        self.degraded += 1
        self.replay_rollback_failures += 1
        return False

    # =========================================================
    # SIGN EVENT
    # =========================================================

    def sign_event(
        self,
        event: Any,
    ) -> dict:

        if not self.key_manager.is_ready():
            self.degraded += 1
            raise RuntimeError("KeyManager DEGRADED")

        payload = self.canonicalize_event(event)

        signed = self.key_manager.sign_with_active_key_id(payload)

        if (
            not isinstance(signed, tuple)
            or len(signed) != 2
            or not isinstance(signed[0], str)
            or not signed[0]
            or not isinstance(signed[1], str)
            or not signed[1]
        ):
            self.degraded += 1
            raise RuntimeError("Event signing failed")

        key_id, signature = signed

        return {
            "event_id": event.event_id,
            "key_id": key_id,
            "signature": signature,
            "algorithm": "HMAC-SHA256",
            "payload": payload,
        }

    # =========================================================
    # DETAILED CRYPTO + REPLAY + DURABLE ADMISSION
    # =========================================================

    def admit_detailed(
        self,
        event: Any,
        key_id: str,
        signature: str,
    ) -> AdmissionDecision:

        self.received += 1

        event_id = getattr(
            event,
            "event_id",
            None,
        )

        # -----------------------------------------------------
        # INPUT VALIDATION
        # -----------------------------------------------------

        if event is None:

            self.invalid_events += 1
            self.rejected += 1

            return self._decision(
                accepted=False,
                reason=self.REASON_INVALID_EVENT,
                stage=self.STAGE_INPUT,
                event_id=None,
                key_id=key_id,
                retryable=False,
                fail_closed=True,
                error_code="EVENT_NONE",
            )

        if not isinstance(
            event_id,
            str,
        ) or not event_id.strip():

            self.invalid_events += 1
            self.rejected += 1

            return self._decision(
                accepted=False,
                reason=self.REASON_INVALID_EVENT,
                stage=self.STAGE_INPUT,
                event_id=None,
                key_id=key_id,
                retryable=False,
                fail_closed=True,
                error_code="INVALID_EVENT_ID",
            )

        # -----------------------------------------------------
        # KEY MANAGER
        # -----------------------------------------------------

        if not self.key_manager.is_ready():

            self.degraded += 1
            self.rejected += 1

            return self._decision(
                accepted=False,
                reason=self.REASON_KEY_MANAGER_DEGRADED,
                stage=self.STAGE_CRYPTO,
                event_id=event_id,
                key_id=key_id,
                retryable=True,
                fail_closed=True,
                error_code="KEY_MANAGER_DEGRADED",
            )

        replay_reserved = False

        try:

            # =================================================
            # STEP 1 — CRYPTOGRAPHIC TRUST
            # =================================================

            payload = (
                self.canonicalize_event(
                    event
                )
            )

            decision = (
                self.boundary.verify(
                    payload,
                    signature,
                    key_id,
                )
            )

            if not decision.accepted:

                self.crypto_rejected += 1
                self.rejected += 1

                if (
                    decision.reason
                    == "KEY_MANAGER_DEGRADED"
                ):
                    self.degraded += 1

                    retryable = True

                else:
                    retryable = False

                return self._decision(
                    accepted=False,
                    reason=decision.reason,
                    stage=self.STAGE_CRYPTO,
                    event_id=event_id,
                    key_id=key_id,
                    retryable=retryable,
                    fail_closed=True,
                    error_code=decision.reason,
                )

            # =================================================
            # STEP 2 — REPLAY PROTECTION
            # =================================================

            replay_accepted = (
                self.replay_guard.check_and_remember(
                    event_id
                )
            )

            if not replay_accepted:

                self.replay_rejected += 1
                self.rejected += 1

                return self._decision(
                    accepted=False,
                    reason=self.REASON_REPLAY,
                    stage=self.STAGE_REPLAY,
                    event_id=event_id,
                    key_id=key_id,
                    retryable=False,
                    fail_closed=True,
                    error_code="EVENT_ALREADY_SEEN",
                )

            replay_reserved = True

            # =================================================
            # STEP 3 — DURABLE PIPELINE
            # =================================================

            detailed_ingest = getattr(
                self.pipeline,
                "ingest_detailed",
                None,
            )

            if self.use_detailed_transport and callable(detailed_ingest):
                if getattr(self.pipeline, "require_admission", False) is True:
                    # Mint only after crypto/trust and replay acceptance. Domain
                    # separation prevents an ordinary event signature being used
                    # as proof of completed admission.
                    receipt_payload = (
                        self.ADMISSION_DOMAIN
                        + self.canonicalize_event(event)
                    )

                    receipt_signed = (
                        self.key_manager.sign_with_active_key_id(
                            receipt_payload
                        )
                    )

                    if (
                        not isinstance(receipt_signed, tuple)
                        or len(receipt_signed) != 2
                        or not isinstance(receipt_signed[0], str)
                        or not receipt_signed[0]
                        or not isinstance(receipt_signed[1], str)
                        or not receipt_signed[1]
                    ):
                        raise RuntimeError(
                            "Admission receipt signing failed"
                        )

                    receipt = {
                        "key_id": receipt_signed[0],
                        "signature": receipt_signed[1],
                    }

                    transport = detailed_ingest(
                        event,
                        admission=receipt,
                    )
                else:
                    transport = detailed_ingest(event)

                disposition = str(
                    getattr(transport, "disposition", "REJECTED")
                ).strip().upper()
                transport_accepted = bool(
                    getattr(transport, "accepted", False)
                )
                durable = bool(getattr(transport, "durable", False))
                published = bool(getattr(transport, "published", False))
                transport_retryable = bool(
                    getattr(transport, "retryable", False)
                )
                transport_reason = str(
                    getattr(transport, "reason", self.REASON_PIPELINE_FAILURE)
                )

                # -------------------------------------------------
                # DURABLE ACCEPTANCE
                # -------------------------------------------------
                if (
                    transport_accepted
                    and durable
                    and disposition in {"ADMITTED", "PERSISTED_DEFERRED"}
                ):
                    self.accepted += 1
                    replay_reserved = False

                    if disposition == "PERSISTED_DEFERRED":
                        self.persisted_deferred += 1
                        return self._decision(
                            accepted=True,
                            reason=self.REASON_PERSISTED_DEFERRED,
                            stage=self.STAGE_DURABLE,
                            event_id=event_id,
                            key_id=key_id,
                            retryable=True,
                            fail_closed=True,
                            error_code=transport_reason,
                            disposition=disposition,
                            durable=True,
                            published=False,
                            replay_reservation_kept=True,
                        )

                    return self._decision(
                        accepted=True,
                        reason=self.REASON_ADMITTED,
                        stage=self.STAGE_ADMITTED,
                        event_id=event_id,
                        key_id=key_id,
                        retryable=False,
                        fail_closed=True,
                        error_code=None,
                        disposition=disposition,
                        durable=True,
                        published=published,
                        replay_reservation_kept=True,
                    )

                # -------------------------------------------------
                # PRE-DURABLE REJECTION
                # -------------------------------------------------
                self.pipeline_failed += 1
                self.rejected += 1

                # Rollback is permitted only when the detailed transport
                # explicitly proves the event did not cross durability.
                if durable is False:
                    if self._rollback_replay_reservation(event_id):
                        replay_reserved = False

                else:
                    # Inconsistent result: durable evidence may exist.  Keep
                    # the replay reservation and fail closed rather than risk
                    # duplicate durable admission.
                    self.degraded += 1
                    replay_reserved = False

                return self._decision(
                    accepted=False,
                    reason=self.REASON_PIPELINE_FAILURE,
                    stage=self.STAGE_DURABLE,
                    event_id=event_id,
                    key_id=key_id,
                    retryable=transport_retryable,
                    fail_closed=True,
                    error_code=transport_reason,
                    disposition=disposition,
                    durable=durable,
                    published=published,
                    replay_reservation_kept=durable,
                )

            # =================================================
            # LEGACY BOOLEAN PIPELINE CONTRACT
            # =================================================

            pipeline_result = self.pipeline.ingest(event)

            if not pipeline_result:

                self.pipeline_failed += 1
                self.rejected += 1

                if self._rollback_replay_reservation(event_id):
                    replay_reserved = False

                return self._decision(
                    accepted=False,
                    reason=self.REASON_PIPELINE_FAILURE,
                    stage=self.STAGE_DURABLE,
                    event_id=event_id,
                    key_id=key_id,
                    retryable=True,
                    fail_closed=True,
                    error_code="PIPELINE_INGEST_REJECTED",
                )

            # =================================================
            # LEGACY SUCCESS
            # =================================================

            self.accepted += 1
            replay_reserved = False

            return self._decision(
                accepted=True,
                reason=self.REASON_ADMITTED,
                stage=self.STAGE_ADMITTED,
                event_id=event_id,
                key_id=key_id,
                retryable=False,
                fail_closed=True,
                error_code=None,
            )

        except Exception as exc:

            self.exceptions += 1
            self.rejected += 1

            # =================================================
            # TRANSACTIONAL REPLAY ROLLBACK
            # =================================================

            if replay_reserved:
                # Legacy mode preserves the historical rollback contract.
                # In detailed P0.4 mode an exception may have occurred after
                # persistence, so blindly rolling back could permit duplicate
                # durable admission.  Keep the reservation and fail closed.
                if not self.use_detailed_transport:
                    if self._rollback_replay_reservation(event_id):
                        replay_reserved = False
                else:
                    self.degraded += 1
                    replay_reserved = False

            return self._decision(
                accepted=False,
                reason=self.REASON_EXCEPTION,
                stage=self.STAGE_ADMISSION,
                event_id=event_id,
                key_id=key_id,
                # In detailed mode an unexpected exception can occur after
                # persistence.  Until durability is proven, retrying the same
                # event ID would conflict with the retained replay reservation.
                retryable=(not self.use_detailed_transport),
                fail_closed=True,
                error_code=(
                    type(exc).__name__
                ),
                replay_reservation_kept=(
                    self.use_detailed_transport
                ),
                durability_uncertain=(
                    self.use_detailed_transport
                ),
            )

    # =========================================================
    # BOOLEAN COMPATIBILITY API
    # =========================================================

    def admit(
        self,
        event: Any,
        key_id: str,
        signature: str,
    ) -> bool:

        decision = (
            self.admit_detailed(
                event,
                key_id,
                signature,
            )
        )

        return decision.accepted

    # =========================================================
    # SIGN + DETAILED ADMISSION
    # =========================================================

    def sign_and_admit_detailed(
        self,
        event: Any,
    ) -> AdmissionDecision:

        event_id = getattr(
            event,
            "event_id",
            None,
        )

        try:

            envelope = (
                self.sign_event(
                    event
                )
            )

        except Exception as exc:

            self.rejected += 1
            self.exceptions += 1

            return self._decision(
                accepted=False,
                reason=self.REASON_EXCEPTION,
                stage=self.STAGE_CRYPTO,
                event_id=event_id,
                key_id=None,
                retryable=True,
                fail_closed=True,
                error_code=(
                    type(exc).__name__
                ),
            )

        return self.admit_detailed(
            event,
            envelope["key_id"],
            envelope["signature"],
        )

    # =========================================================
    # BOOLEAN SIGN + ADMIT COMPATIBILITY
    # =========================================================

    def sign_and_admit(
        self,
        event: Any,
    ) -> bool:

        decision = (
            self.sign_and_admit_detailed(
                event
            )
        )

        return decision.accepted

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(
        self,
    ) -> dict:

        manager_health = (
            self.key_manager.health_check()
        )

        replay_health = {}

        health_method = getattr(
            self.replay_guard,
            "health_check",
            None,
        )

        if callable(
            health_method
        ):

            try:

                replay_health = (
                    health_method()
                )

            except Exception as exc:

                replay_health = {
                    "status":
                        "DEGRADED",
                    "error":
                        type(exc).__name__,
                }

        pipeline_health = {}

        pipeline_health_method = getattr(
            self.pipeline,
            "health_check",
            None,
        )

        if callable(
            pipeline_health_method
        ):

            try:

                pipeline_health = (
                    pipeline_health_method()
                )

            except Exception as exc:

                pipeline_health = {
                    "status":
                        "DEGRADED",
                    "error":
                        type(exc).__name__,
                }

        healthy = (
            manager_health.get(
                "status"
            )
            == "HEALTHY"
            and replay_health.get(
                "status",
                "HEALTHY",
            )
            == "HEALTHY"
            and pipeline_health.get(
                "status",
                "HEALTHY",
            )
            == "HEALTHY"
        )

        return {
            "component":
                "CryptoReplayAdmissionGateway",

            "status":
                (
                    "HEALTHY"
                    if healthy
                    else "DEGRADED"
                ),

            "version":
                self.VERSION,

            "runtime_transport_contract_version":
                self.RUNTIME_TRANSPORT_CONTRACT_VERSION,

            "use_detailed_transport":
                self.use_detailed_transport,

            "key_manager":
                manager_health,

            "replay_guard":
                replay_health,

            "pipeline":
                pipeline_health,

            "counters": {
                "received":
                    self.received,

                "accepted":
                    self.accepted,

                "rejected":
                    self.rejected,

                "crypto_rejected":
                    self.crypto_rejected,

                "replay_rejected":
                    self.replay_rejected,

                "pipeline_failed":
                    self.pipeline_failed,

                "persisted_deferred":
                    self.persisted_deferred,

                "replay_rollbacks":
                    self.replay_rollbacks,

                "replay_rollback_failures":
                    self.replay_rollback_failures,

                "degraded":
                    self.degraded,

                "invalid_events":
                    self.invalid_events,

                "exceptions":
                    self.exceptions,
            },
        }

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict:

        replay_stats = {}

        replay_stats_method = getattr(
            self.replay_guard,
            "get_stats",
            None,
        )

        if callable(
            replay_stats_method
        ):

            replay_stats = (
                replay_stats_method()
            )

        return {
            "component":
                "CryptoReplayAdmissionGateway",

            "version":
                self.VERSION,

            "runtime_transport_contract_version":
                self.RUNTIME_TRANSPORT_CONTRACT_VERSION,

            "use_detailed_transport":
                self.use_detailed_transport,

            "received":
                self.received,

            "accepted":
                self.accepted,

            "rejected":
                self.rejected,

            "crypto_rejected":
                self.crypto_rejected,

            "replay_rejected":
                self.replay_rejected,

            "pipeline_failed":
                self.pipeline_failed,

            "persisted_deferred":
                self.persisted_deferred,

            "replay_rollbacks":
                self.replay_rollbacks,

            "replay_rollback_failures":
                self.replay_rollback_failures,

            "degraded":
                self.degraded,

            "invalid_events":
                self.invalid_events,

            "exceptions":
                self.exceptions,

            "replay_guard":
                replay_stats,
        }