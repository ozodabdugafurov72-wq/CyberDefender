from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from agent.event import SecurityEvent
from agent.core.crypto_replay_admission_gateway import (
    CryptoReplayAdmissionGateway,
)


@dataclass(frozen=True)
class RuntimePipelineResult:
    """
    P11.19+ Runtime admission result.

    Security decision'ni tashqi runtime'ga
    yo'qotmasdan yetkazadi.
    """

    accepted: bool
    reason: str
    event_id: Optional[str]
    stage: str

    retryable: bool = False
    fail_closed: bool = True
    error_code: Optional[str] = None
    key_id: Optional[str] = None

    # P0.4 transport visibility. Defaults preserve legacy callers.
    disposition: Optional[str] = None
    durable: bool = False
    published: bool = False
    replay_reservation_kept: bool = False
    durability_uncertain: bool = False

    component: str = (
        "RuntimeSecurityPipeline"
    )

    version: str = "1.2"


class RuntimeSecurityPipeline:
    """
    CyberDefender Runtime Security Pipeline.

    Security flow:

        SecurityEvent
             |
             v
        Input Validation
             |
             v
        CryptoReplayAdmissionGateway
             |
       +-----+------+----------------+
       |            |                |
       v            v                v
     CRYPTO       REPLAY          DURABLE
       |            |                |
       +------------+----------------+
                    |
                    v
              TRUSTED EVENT

    Important:

    - Existing gateway security logic o'zgartirilmaydi.
    - Existing bool API compatibility saqlanadi.
    - Detailed admission result qo'shiladi.
    - Fail-closed default.
    - Pipeline failure retryable bo'lishi mumkin.
    - Crypto/replay rejection retryable emas.
    """

    VERSION = "1.2"
    RUNTIME_TRANSPORT_CONTRACT_VERSION = "P0.4-1"

    # =========================================================
    # REASONS
    # =========================================================

    REASON_EVENT_ADMITTED = (
        "EVENT_ADMITTED"
    )

    REASON_INVALID_EVENT = (
        "INVALID_SECURITY_EVENT"
    )

    REASON_CRYPTO_REJECTED = (
        "CRYPTO_ADMISSION_REJECTED"
    )

    REASON_REPLAY_REJECTED = (
        "REPLAY_REJECTED"
    )

    REASON_PIPELINE_FAILED = (
        "DURABLE_PIPELINE_FAILED"
    )

    REASON_ADMISSION_EXCEPTION = (
        "ADMISSION_EXCEPTION"
    )

    REASON_GATEWAY_UNAVAILABLE = (
        "ADMISSION_GATEWAY_UNAVAILABLE"
    )

    # =========================================================
    # STAGES
    # =========================================================

    STAGE_INPUT_VALIDATION = (
        "INPUT_VALIDATION"
    )

    STAGE_CRYPTO_TRUST = (
        "CRYPTO_TRUST"
    )

    STAGE_REPLAY = (
        "REPLAY_PROTECTION"
    )

    STAGE_DURABLE_PIPELINE = (
        "DURABLE_PIPELINE"
    )

    STAGE_ADMITTED = (
        "ADMITTED"
    )

    STAGE_ADMISSION = (
        "ADMISSION"
    )

    # =========================================================
    # INIT
    # =========================================================

    def __init__(
        self,
        admission_gateway: (
            CryptoReplayAdmissionGateway
        ),
    ):
        if admission_gateway is None:
            raise ValueError(
                "admission_gateway kerak"
            )

        self.admission_gateway = (
            admission_gateway
        )

        self.accepted = 0
        self.rejected = 0
        self.failed = 0

        self.invalid_events = 0
        self.crypto_rejected = 0
        self.replay_rejected = 0
        self.pipeline_failed = 0
        self.persisted_deferred = 0
        self.published = 0

    # =========================================================
    # RESULT HELPERS
    # =========================================================

    @staticmethod
    def _result(
        *,
        accepted: bool,
        reason: str,
        event_id: Optional[str],
        stage: str,
        retryable: bool = False,
        fail_closed: bool = True,
        error_code: Optional[str] = None,
        key_id: Optional[str] = None,
        disposition: Optional[str] = None,
        durable: bool = False,
        published: bool = False,
        replay_reservation_kept: bool = False,
        durability_uncertain: bool = False,
    ) -> RuntimePipelineResult:

        return RuntimePipelineResult(
            accepted=accepted,
            reason=reason,
            event_id=event_id,
            stage=stage,
            retryable=retryable,
            fail_closed=fail_closed,
            error_code=error_code,
            key_id=key_id,
            disposition=disposition,
            durable=durable,
            published=published,
            replay_reservation_kept=replay_reservation_kept,
            durability_uncertain=durability_uncertain,
        )

    # =========================================================
    # RESULT NORMALIZATION
    # =========================================================

    def _normalize_gateway_result(
        self,
        result,
        event_id: Optional[str],
    ) -> RuntimePipelineResult:
        """
        Gateway'dan kelgan detailed resultni
        RuntimePipelineResult'ga normalize qiladi.

        Bu future gateway versiyalariga
        backward-compatible bo'lish uchun kerak.
        """

        accepted = bool(
            getattr(
                result,
                "accepted",
                False,
            )
        )

        reason = str(
            getattr(
                result,
                "reason",
                self.REASON_ADMISSION_EXCEPTION,
            )
        )

        stage = str(
            getattr(
                result,
                "stage",
                self.STAGE_ADMISSION,
            )
        )

        retryable = bool(
            getattr(
                result,
                "retryable",
                False,
            )
        )

        fail_closed = bool(
            getattr(
                result,
                "fail_closed",
                True,
            )
        )

        error_code = getattr(
            result,
            "error_code",
            None,
        )

        key_id = getattr(
            result,
            "key_id",
            None,
        )

        disposition = getattr(
            result,
            "disposition",
            None,
        )

        durable = bool(
            getattr(
                result,
                "durable",
                False,
            )
        )

        published = bool(
            getattr(
                result,
                "published",
                False,
            )
        )

        replay_reservation_kept = bool(
            getattr(
                result,
                "replay_reservation_kept",
                False,
            )
        )

        durability_uncertain = bool(
            getattr(
                result,
                "durability_uncertain",
                False,
            )
        )

        return self._result(
            accepted=accepted,
            reason=reason,
            event_id=event_id,
            stage=stage,
            retryable=retryable,
            fail_closed=fail_closed,
            error_code=error_code,
            key_id=key_id,
            disposition=disposition,
            durable=durable,
            published=published,
            replay_reservation_kept=replay_reservation_kept,
            durability_uncertain=durability_uncertain,
        )

    # =========================================================
    # DETAILED INGEST
    # =========================================================

    def ingest_detailed(
        self,
        event: SecurityEvent,
    ) -> RuntimePipelineResult:
        """
        Main runtime admission entrypoint.

        Detailed security decision qaytaradi.
        """

        # -----------------------------------------------------
        # INPUT VALIDATION
        # -----------------------------------------------------

        if not isinstance(
            event,
            SecurityEvent,
        ):
            self.rejected += 1
            self.invalid_events += 1

            return self._result(
                accepted=False,
                reason=self.REASON_INVALID_EVENT,
                event_id=None,
                stage=self.STAGE_INPUT_VALIDATION,
                retryable=False,
                fail_closed=True,
                error_code="INVALID_EVENT_TYPE",
            )

        event_id = getattr(
            event,
            "event_id",
            None,
        )

        if not isinstance(
            event_id,
            str,
        ) or not event_id.strip():

            self.rejected += 1
            self.invalid_events += 1

            return self._result(
                accepted=False,
                reason=self.REASON_INVALID_EVENT,
                event_id=None,
                stage=self.STAGE_INPUT_VALIDATION,
                retryable=False,
                fail_closed=True,
                error_code="INVALID_EVENT_ID",
            )

        # -----------------------------------------------------
        # GATEWAY AVAILABILITY
        # -----------------------------------------------------

        gateway = (
            self.admission_gateway
        )

        if gateway is None:

            self.rejected += 1
            self.failed += 1

            return self._result(
                accepted=False,
                reason=self.REASON_GATEWAY_UNAVAILABLE,
                event_id=event_id,
                stage=self.STAGE_ADMISSION,
                retryable=True,
                fail_closed=True,
                error_code="GATEWAY_UNAVAILABLE",
            )

        # -----------------------------------------------------
        # DETAILED GATEWAY API
        # -----------------------------------------------------

        detailed_method = getattr(
            gateway,
            "sign_and_admit_detailed",
            None,
        )

        try:

            if callable(
                detailed_method
            ):

                gateway_result = (
                    detailed_method(
                        event
                    )
                )

                result = (
                    self._normalize_gateway_result(
                        gateway_result,
                        event_id,
                    )
                )

            else:
                # -------------------------------------------------
                # BACKWARD COMPATIBILITY
                # -------------------------------------------------

                accepted = (
                    gateway.sign_and_admit(
                        event
                    )
                )

                if accepted:

                    result = self._result(
                        accepted=True,
                        reason=(
                            self.REASON_EVENT_ADMITTED
                        ),
                        event_id=event_id,
                        stage=self.STAGE_ADMITTED,
                        retryable=False,
                        fail_closed=True,
                    )

                else:

                    result = self._result(
                        accepted=False,
                        reason=(
                            "EVENT_REJECTED"
                        ),
                        event_id=event_id,
                        stage=(
                            "ADMISSION_REJECTED"
                        ),
                        retryable=False,
                        fail_closed=True,
                    )

        except Exception as exc:

            self.failed += 1
            self.rejected += 1

            return self._result(
                accepted=False,
                reason=(
                    self.REASON_ADMISSION_EXCEPTION
                ),
                event_id=event_id,
                stage=self.STAGE_ADMISSION,
                retryable=False,
                fail_closed=True,
                error_code=(
                    type(exc).__name__
                ),
            )

        # -----------------------------------------------------
        # FINAL ACCOUNTING
        # -----------------------------------------------------

        if result.accepted:

            self.accepted += 1

            if result.disposition == "PERSISTED_DEFERRED":
                self.persisted_deferred += 1

            if result.published:
                self.published += 1

            return result

        self.rejected += 1

        reason = result.reason

        if (
            "REPLAY" in reason
            or "replay" in reason
        ):
            self.replay_rejected += 1

        elif (
            "CRYPTO" in reason
            or "SIGNATURE" in reason
            or "KEY" in reason
            or "TRUST" in reason
        ):
            self.crypto_rejected += 1

        elif (
            "PIPELINE" in reason
            or "DURABLE" in reason
        ):
            self.pipeline_failed += 1

        return result

    # =========================================================
    # COMPATIBLE INGEST
    # =========================================================

    def ingest(
        self,
        event: SecurityEvent,
    ) -> RuntimePipelineResult:
        """
        Existing public API.

        Old callers continue to work.
        """

        return self.ingest_detailed(
            event
        )

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(
        self,
    ) -> dict:

        gateway_health = {}

        health_method = getattr(
            self.admission_gateway,
            "health_check",
            None,
        )

        if callable(
            health_method
        ):

            try:

                gateway_health = (
                    health_method()
                )

            except Exception as exc:

                gateway_health = {
                    "status":
                        "DEGRADED",
                    "error":
                        type(exc).__name__,
                }

        gateway_status = (
            gateway_health.get(
                "status",
                "UNKNOWN",
            )
        )

        return {
            "component":
                "RuntimeSecurityPipeline",

            "version":
                self.VERSION,

            "runtime_transport_contract_version":
                self.RUNTIME_TRANSPORT_CONTRACT_VERSION,

            "status":
                (
                    "HEALTHY"
                    if gateway_status
                    == "HEALTHY"
                    else "DEGRADED"
                ),

            "accepted":
                self.accepted,

            "rejected":
                self.rejected,

            "failed":
                self.failed,

            "invalid_events":
                self.invalid_events,

            "crypto_rejected":
                self.crypto_rejected,

            "replay_rejected":
                self.replay_rejected,

            "pipeline_failed":
                self.pipeline_failed,

            "persisted_deferred":
                self.persisted_deferred,

            "published":
                self.published,

            "gateway":
                gateway_health,
        }

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict:

        return {
            "component":
                "RuntimeSecurityPipeline",

            "version":
                self.VERSION,

            "runtime_transport_contract_version":
                self.RUNTIME_TRANSPORT_CONTRACT_VERSION,

            "accepted":
                self.accepted,

            "rejected":
                self.rejected,

            "failed":
                self.failed,

            "invalid_events":
                self.invalid_events,

            "crypto_rejected":
                self.crypto_rejected,

            "replay_rejected":
                self.replay_rejected,

            "pipeline_failed":
                self.pipeline_failed,

            "persisted_deferred":
                self.persisted_deferred,

            "published":
                self.published,
        }