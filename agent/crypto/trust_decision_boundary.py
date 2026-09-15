from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from agent.crypto.key_manager import KeyManager


@dataclass(frozen=True)
class TrustDecision:
    accepted: bool
    reason: str
    key_id: Optional[str]
    component: str = "TrustDecisionBoundary"
    version: str = "1.0"


class TrustDecisionBoundary:
    """
    CyberDefender P11.7

    Final cryptographic trust decision boundary.

    Signature validity alone is NOT sufficient.

    The key must also be ACTIVE.

    Decision:

        valid signature
              +
        ACTIVE key
              =
           ACCEPT

    Everything else is REJECT.
    """

    VERSION = "1.0"

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"

    def __init__(
        self,
        key_manager: KeyManager,
    ):
        if key_manager is None:
            raise ValueError(
                "key_manager kerak"
            )

        self.key_manager = key_manager

        self.accepted = 0
        self.rejected = 0

        self.invalid_signature = 0
        self.retired_key = 0
        self.revoked_key = 0
        self.unknown_key = 0
        self.degraded = 0

    # =========================================================
    # Decision
    # =========================================================

    def verify(
        self,
        payload: bytes,
        mac: str,
        key_id: str,
    ) -> TrustDecision:

        if not self.key_manager.is_ready():

            self.degraded += 1
            self.rejected += 1

            return TrustDecision(
                accepted=False,
                reason="KEY_MANAGER_DEGRADED",
                key_id=key_id,
            )

        metadata = (
            self.key_manager.get_key_metadata(
                key_id
            )
        )

        if metadata is None:

            self.unknown_key += 1
            self.rejected += 1

            return TrustDecision(
                accepted=False,
                reason="UNKNOWN_KEY",
                key_id=key_id,
            )

        status = metadata.get(
            "status"
        )

        if status == "REVOKED":

            self.revoked_key += 1
            self.rejected += 1

            return TrustDecision(
                accepted=False,
                reason="REVOKED_KEY",
                key_id=key_id,
            )

        if status == "RETIRED":

            self.retired_key += 1
            self.rejected += 1

            return TrustDecision(
                accepted=False,
                reason="RETIRED_KEY",
                key_id=key_id,
            )

        if status != "ACTIVE":

            self.rejected += 1

            return TrustDecision(
                accepted=False,
                reason="INVALID_KEY_STATE",
                key_id=key_id,
            )

        valid = self.key_manager.verify(
            payload,
            mac,
            key_id,
        )

        if not valid:

            self.invalid_signature += 1
            self.rejected += 1

            return TrustDecision(
                accepted=False,
                reason="INVALID_SIGNATURE",
                key_id=key_id,
            )

        self.accepted += 1

        return TrustDecision(
            accepted=True,
            reason="TRUSTED_ACTIVE_KEY",
            key_id=key_id,
        )

    # =========================================================
    # Health
    # =========================================================

    def health_check(self) -> dict:
        manager_health = (
            self.key_manager.health_check()
        )

        healthy = (
            manager_health.get(
                "status"
            )
            == "HEALTHY"
        )

        return {
            "component":
                "TrustDecisionBoundary",
            "status":
                (
                    "HEALTHY"
                    if healthy
                    else "DEGRADED"
                ),
            "version":
                self.VERSION,
            "accepted":
                self.accepted,
            "rejected":
                self.rejected,
        }

    def get_stats(self) -> dict:
        return {
            "component":
                "TrustDecisionBoundary",
            "version":
                self.VERSION,
            "accepted":
                self.accepted,
            "rejected":
                self.rejected,
            "invalid_signature":
                self.invalid_signature,
            "retired_key":
                self.retired_key,
            "revoked_key":
                self.revoked_key,
            "unknown_key":
                self.unknown_key,
            "degraded":
                self.degraded,
        }
