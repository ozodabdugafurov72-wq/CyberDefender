from __future__ import annotations

"""Trust-state transition boundary for CyberDefender v6 Phase 1.

Phase 1 deliberately has no authority capable of changing trust state. The
function below makes that absence explicit and testable.
"""

from dataclasses import dataclass

from .contracts import IdentityContractError, TrustState


@dataclass(frozen=True, slots=True)
class TrustTransitionDecision:
    allowed: bool
    current: TrustState
    requested: TrustState
    reason: str


def evaluate_phase1_trust_transition(current: TrustState, requested: TrustState) -> TrustTransitionDecision:
    if not isinstance(current, TrustState) or not isinstance(requested, TrustState):
        raise IdentityContractError("invalid trust transition state")
    if current is requested:
        return TrustTransitionDecision(True, current, requested, "NO_STATE_CHANGE")
    return TrustTransitionDecision(
        False,
        current,
        requested,
        "PHASE1_TRUST_TRANSITION_AUTHORITY_NOT_IMPLEMENTED",
    )
