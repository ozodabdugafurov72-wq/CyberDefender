from __future__ import annotations

import json
from typing import Any

from agent.crypto.key_manager import KeyManager
from agent.crypto.trust_decision_boundary import (
    TrustDecisionBoundary,
)


class CryptoAdmissionGateway:
    """
    CyberDefender P11.8

    Cryptographic Trust -> Durable Pipeline admission boundary.

    Muhim invariant:

        Event faqat cryptographic trust tekshiruvidan
        o'tgandan keyin DurableEventPipeline'ga beriladi.

    AI bu qarorga aralasha olmaydi.

    Flow:

        SecurityEvent
             |
             v
        Canonical JSON
             |
             v
        KeyManager / TrustDecisionBoundary
             |
        +----+----+
        |         |
      REJECT    ACCEPT
        |         |
        X         v
             DurableEventPipeline
    """

    VERSION = "1.0"

    def __init__(
        self,
        key_manager: KeyManager,
        pipeline: Any,
    ):
        if key_manager is None:
            raise ValueError(
                "key_manager kerak"
            )

        if pipeline is None:
            raise ValueError(
                "pipeline kerak"
            )

        self.key_manager = key_manager
        self.pipeline = pipeline

        self.boundary = (
            TrustDecisionBoundary(
                key_manager
            )
        )

        self.received = 0
        self.accepted = 0
        self.rejected = 0
        self.invalid_signature = 0
        self.degraded = 0
        self.pipeline_failed = 0

    # =========================================================
    # Canonical event representation
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

        return (
            json.dumps(
                data,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        ).encode("utf-8")

    # =========================================================
    # Sign event using ACTIVE key
    # =========================================================

    def sign_event(
        self,
        event: Any,
    ) -> dict:

        if not self.key_manager.is_ready():
            self.degraded += 1

            raise RuntimeError(
                "KeyManager DEGRADED"
            )

        key_id = (
            self.key_manager.active_key_id()
        )

        if not key_id:
            self.degraded += 1

            raise RuntimeError(
                "ACTIVE trust key mavjud emas"
            )

        payload = (
            self.canonicalize_event(
                event
            )
        )

        mac = self.key_manager.sign(
            payload
        )

        if not isinstance(
            mac,
            str,
        ) or not mac:
            raise RuntimeError(
                "Event signing failed"
            )

        return {
            "event_id":
                event.event_id,
            "key_id":
                key_id,
            "signature":
                mac,
            "algorithm":
                "HMAC-SHA256",
            "payload":
                payload,
        }

    # =========================================================
    # Admission
    # =========================================================

    def admit(
        self,
        event: Any,
        key_id: str,
        signature: str,
    ) -> bool:

        self.received += 1

        if not self.key_manager.is_ready():
            self.degraded += 1
            self.rejected += 1

            return False

        try:
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

                self.rejected += 1

                if (
                    decision.reason
                    == "INVALID_SIGNATURE"
                ):
                    self.invalid_signature += 1

                if (
                    decision.reason
                    == "KEY_MANAGER_DEGRADED"
                ):
                    self.degraded += 1

                return False

            # -------------------------------------------------
            # Cryptographically trusted.
            # ONLY NOW enter durable pipeline.
            # -------------------------------------------------

            accepted = (
                self.pipeline.ingest(
                    event
                )
            )

            if not accepted:
                self.pipeline_failed += 1

                return False

            self.accepted += 1

            return True

        except Exception:
            self.rejected += 1

            return False

    # =========================================================
    # Convenience: sign + admit
    # =========================================================

    def sign_and_admit(
        self,
        event: Any,
    ) -> bool:

        try:
            envelope = (
                self.sign_event(
                    event
                )
            )

            return self.admit(
                event,
                envelope["key_id"],
                envelope["signature"],
            )

        except Exception:
            self.rejected += 1

            return False

    # =========================================================
    # Health
    # =========================================================

    def health_check(
        self,
    ) -> dict:

        manager_health = (
            self.key_manager.health_check()
        )

        pipeline_health = {}

        if hasattr(
            self.pipeline,
            "health_check",
        ):
            pipeline_health = (
                self.pipeline.health_check()
            )

        manager_ok = (
            manager_health.get(
                "status"
            )
            == "HEALTHY"
        )

        return {
            "component":
                "CryptoAdmissionGateway",
            "status":
                (
                    "HEALTHY"
                    if manager_ok
                    else "DEGRADED"
                ),
            "version":
                self.VERSION,
            "key_manager":
                manager_health,
            "pipeline":
                pipeline_health,
        }

    # =========================================================
    # Stats
    # =========================================================

    def get_stats(
        self,
    ) -> dict:

        return {
            "component":
                "CryptoAdmissionGateway",
            "version":
                self.VERSION,
            "received":
                self.received,
            "accepted":
                self.accepted,
            "rejected":
                self.rejected,
            "invalid_signature":
                self.invalid_signature,
            "degraded":
                self.degraded,
            "pipeline_failed":
                self.pipeline_failed,
        }
