from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ContinuityMode(str, Enum):
    FULL_CONNECTED = "FULL_CONNECTED"
    CLOUD_ISOLATED = "CLOUD_ISOLATED"
    PRIMARY_ISOLATED = "PRIMARY_ISOLATED"
    FULL_ISOLATED = "FULL_ISOLATED"
    RECONCILING = "RECONCILING"
    SAFE_DEGRADED = "SAFE_DEGRADED"


@dataclass(frozen=True)
class ContinuityInputs:
    """
    Evidence supplied to the continuity state machine.

    This object carries observations only.  It grants no authority.

    reconciliation_required MUST ultimately come from durable,
    authenticated reconciliation state.  It is deliberately explicit
    rather than inferred from process-local history so a service restart
    cannot silently clear reconciliation requirements.
    """

    cloud_reachable: Optional[bool]
    primary_reachable: Optional[bool]
    lan_reachable: Optional[bool]

    safety_healthy: bool
    trust_healthy: bool
    crypto_healthy: bool
    storage_healthy: bool

    offline_policy_valid: bool

    reconciliation_required: Optional[bool] = None


@dataclass(frozen=True)
class ContinuityDecision:
    mode: ContinuityMode
    reason: str

    local_protection_required: bool = True

    authority: str = "NONE"
    authorization: str = "NOT_GRANTED"
    authority_increase_allowed: bool = False

    fail_closed: bool = True


class ContinuityController:
    """
    CyberDefender Autonomous Continuity Plane state classifier.

    Security invariants:

        NETWORK LOST != PROTECTION LOST
        CLOUD LOST != TELEMETRY LOST
        NETWORK LOSS NEVER INCREASES AUTHORITY

    v0.2 remains classification-only.

    It does not:
      - execute operating-system actions;
      - modify policy;
      - grant authorization;
      - alter firewall/services/registry;
      - perform network requests;
      - clear durable reconciliation state.
    """

    VERSION = "0.3"

    def __init__(self) -> None:
        self._last_decision = ContinuityDecision(
            mode=ContinuityMode.SAFE_DEGRADED,
            reason="NOT_EVALUATED",
        )

    @staticmethod
    def _decision(
        mode: ContinuityMode,
        reason: str,
    ) -> ContinuityDecision:
        return ContinuityDecision(
            mode=mode,
            reason=reason,
        )

    @staticmethod
    def _tier0_failure_reason(
        inputs: ContinuityInputs,
    ) -> str | None:

        if not inputs.safety_healthy:
            return "SAFETY_UNHEALTHY"

        if not inputs.trust_healthy:
            return "TRUST_UNHEALTHY"

        if not inputs.crypto_healthy:
            return "CRYPTO_UNHEALTHY"

        if not inputs.storage_healthy:
            return "STORAGE_UNHEALTHY"

        return None

    def evaluate(
        self,
        inputs: ContinuityInputs,
    ) -> ContinuityDecision:

        if not isinstance(inputs, ContinuityInputs):
            raise TypeError(
                "inputs ContinuityInputs bo'lishi kerak"
            )

        # -----------------------------------------------------
        # Tier-0 trust / safety dominates connectivity.
        # -----------------------------------------------------

        tier0_failure = self._tier0_failure_reason(
            inputs
        )

        if tier0_failure is not None:
            decision = self._decision(
                ContinuityMode.SAFE_DEGRADED,
                tier0_failure,
            )

            self._last_decision = decision
            return decision

        # -----------------------------------------------------
        # Unknown primary state is never interpreted as trusted.
        # -----------------------------------------------------

        if inputs.primary_reachable is None:
            decision = self._decision(
                ContinuityMode.SAFE_DEGRADED,
                "PRIMARY_REACHABILITY_UNKNOWN",
            )

            self._last_decision = decision
            return decision

        # -----------------------------------------------------
        # Primary is reachable.
        #
        # Reconciliation is controlled by explicit durable state.
        # Repeated evaluate() calls MUST remain RECONCILING while
        # reconciliation_required remains true.
        # -----------------------------------------------------

        if inputs.primary_reachable is True:

            if inputs.reconciliation_required is True:
                decision = self._decision(
                    ContinuityMode.RECONCILING,
                    "DURABLE_RECONCILIATION_REQUIRED",
                )

                self._last_decision = decision
                return decision

            if inputs.reconciliation_required is None:
                decision = self._decision(
                    ContinuityMode.SAFE_DEGRADED,
                    "RECONCILIATION_STATE_UNKNOWN",
                )

                self._last_decision = decision
                return decision

            if inputs.cloud_reachable is True:
                decision = self._decision(
                    ContinuityMode.FULL_CONNECTED,
                    "PRIMARY_AND_CLOUD_REACHABLE",
                )

                self._last_decision = decision
                return decision

            if inputs.cloud_reachable is False:
                decision = self._decision(
                    ContinuityMode.CLOUD_ISOLATED,
                    "CLOUD_UNREACHABLE",
                )

                self._last_decision = decision
                return decision

            decision = self._decision(
                ContinuityMode.CLOUD_ISOLATED,
                "CLOUD_REACHABILITY_NOT_PROVEN",
            )

            self._last_decision = decision
            return decision

        # -----------------------------------------------------
        # Primary is unavailable.
        #
        # Offline/local autonomous classification requires a
        # verified offline policy.  No policy => fail closed.
        # -----------------------------------------------------

        if not inputs.offline_policy_valid:
            decision = self._decision(
                ContinuityMode.SAFE_DEGRADED,
                "OFFLINE_POLICY_NOT_VALID",
            )

            self._last_decision = decision
            return decision

        if inputs.lan_reachable is True:
            decision = self._decision(
                ContinuityMode.PRIMARY_ISOLATED,
                "PRIMARY_UNREACHABLE_LAN_AVAILABLE",
            )

            self._last_decision = decision
            return decision

        if inputs.lan_reachable is False:
            decision = self._decision(
                ContinuityMode.FULL_ISOLATED,
                "PRIMARY_AND_LAN_UNREACHABLE",
            )

            self._last_decision = decision
            return decision

        decision = self._decision(
            ContinuityMode.SAFE_DEGRADED,
            "LAN_REACHABILITY_UNKNOWN",
        )

        self._last_decision = decision
        return decision

    def health_snapshot(self) -> dict[str, object]:
        """
        Component health is distinct from continuity mode.

        The controller itself may be healthy while the endpoint is in
        SAFE_DEGRADED because required trust/connectivity evidence is
        missing or unhealthy.
        """

        decision = self._last_decision

        return {
            "component": "ContinuityController",
            "version": self.VERSION,
            "status": "HEALTHY",
            "mode": decision.mode.value,
            "reason": decision.reason,

            "local_protection_required":
                decision.local_protection_required,

            "authority":
                decision.authority,

            "authorization":
                decision.authorization,

            "authority_increase_allowed":
                decision.authority_increase_allowed,

            "fail_closed":
                decision.fail_closed,

            "authoritative": False,

            # agent.main overrides this with OBSERVE_ONLY when
            # presented on the runtime health surface.
            "runtime_wired": False,

            "reconciliation_state_source":
                "EXTERNAL_DURABLE_REQUIRED",

            "unknown_reconciliation_fails_closed":
                True,
        }
