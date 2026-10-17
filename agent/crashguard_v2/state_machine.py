"""Pure CrashGuard v2 lifecycle and health state machines (no I/O)."""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import math


class Lifecycle(str, Enum):
    INIT = "INIT"
    READY = "READY"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    LATCHED = "LATCHED"
    SAFE_HOLD = "SAFE_HOLD"
    RECOVERY_AUTHORIZED = "RECOVERY_AUTHORIZED"
    RECOVERY_PROBING = "RECOVERY_PROBING"


class Health(str, Enum):
    UNKNOWN = "UNKNOWN"
    UNHEALTHY = "UNHEALTHY"
    DEGRADED = "DEGRADED"
    HEALTHY = "HEALTHY"
    STABLE = "STABLE"


class Event(str, Enum):
    INITIALIZE = "INITIALIZE"
    START_REQUESTED = "START_REQUESTED"
    START_CONFIRMED = "START_CONFIRMED"
    STOP_REQUESTED = "STOP_REQUESTED"
    STOP_CONFIRMED = "STOP_CONFIRMED"
    ATTEMPT_FAILED = "ATTEMPT_FAILED"
    RUNTIME_EXITED = "RUNTIME_EXITED"
    LATCH_REQUIRED = "LATCH_REQUIRED"
    BOOT_OBSERVED = "BOOT_OBSERVED"
    RECOVERY_AUTHORIZED = "RECOVERY_AUTHORIZED"
    RECOVERY_STARTED = "RECOVERY_STARTED"
    RECOVERY_VERIFIED = "RECOVERY_VERIFIED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    HEALTH_OBSERVED = "HEALTH_OBSERVED"


@dataclass(frozen=True)
class Transition:
    state: Lifecycle
    effects: tuple[str, ...]


class TransitionRejected(RuntimeError):
    pass


def _t(state: Lifecycle, *effects: str) -> Transition:
    return Transition(state, tuple(effects))


TRANSITIONS: dict[tuple[Lifecycle, Event], Transition] = {
    (Lifecycle.INIT, Event.INITIALIZE): _t(Lifecycle.READY, "PERSIST_INITIAL_STATE", "PUBLISH_STATUS"),
    (Lifecycle.READY, Event.START_REQUESTED): _t(Lifecycle.STARTING, "RESERVE_ATTEMPT", "PUBLISH_STATUS"),
    (Lifecycle.STOPPED, Event.START_REQUESTED): _t(Lifecycle.STARTING, "RESERVE_ATTEMPT", "PUBLISH_STATUS"),
    (Lifecycle.STARTING, Event.START_CONFIRMED): _t(Lifecycle.RUNNING, "BIND_RUNTIME_IDENTITY", "PUBLISH_STATUS"),
    (Lifecycle.READY, Event.STOP_REQUESTED): _t(Lifecycle.STOPPING, "REQUEST_HOST_STOP"),
    (Lifecycle.STARTING, Event.STOP_REQUESTED): _t(Lifecycle.STOPPING, "REQUEST_RUNTIME_STOP"),
    (Lifecycle.RUNNING, Event.STOP_REQUESTED): _t(Lifecycle.STOPPING, "REQUEST_RUNTIME_STOP"),
    (Lifecycle.LATCHED, Event.STOP_REQUESTED): _t(Lifecycle.STOPPING, "REQUEST_HOST_STOP"),
    (Lifecycle.SAFE_HOLD, Event.STOP_REQUESTED): _t(Lifecycle.STOPPING, "REQUEST_HOST_STOP"),
    (Lifecycle.RECOVERY_AUTHORIZED, Event.STOP_REQUESTED): _t(Lifecycle.STOPPING, "REQUEST_HOST_STOP"),
    (Lifecycle.RECOVERY_PROBING, Event.STOP_REQUESTED): _t(
        Lifecycle.STOPPING, "REQUEST_RUNTIME_STOP", "PRESERVE_RECOVERY_DEBIT"
    ),
    (Lifecycle.STOPPING, Event.STOP_CONFIRMED): _t(Lifecycle.STOPPED, "PERSIST_STOP", "PUBLISH_STATUS"),
    (Lifecycle.STARTING, Event.ATTEMPT_FAILED): _t(
        Lifecycle.LATCHED, "RECORD_FAILURE", "EXIT_HOST_NONZERO", "PUBLISH_STATUS"
    ),
    (Lifecycle.RUNNING, Event.ATTEMPT_FAILED): _t(
        Lifecycle.LATCHED, "RECORD_FAILURE", "EXIT_HOST_NONZERO", "PUBLISH_STATUS"
    ),
    (Lifecycle.RECOVERY_PROBING, Event.ATTEMPT_FAILED): _t(
        Lifecycle.LATCHED, "RECORD_RECOVERY_FAILURE", "EXIT_HOST_NONZERO", "PUBLISH_STATUS"
    ),
    (Lifecycle.STARTING, Event.RUNTIME_EXITED): _t(
        Lifecycle.LATCHED, "RECORD_RUNTIME_FATAL", "EXIT_HOST_NONZERO", "PUBLISH_STATUS"
    ),
    (Lifecycle.RUNNING, Event.RUNTIME_EXITED): _t(
        Lifecycle.LATCHED, "RECORD_RUNTIME_FATAL", "EXIT_HOST_NONZERO", "PUBLISH_STATUS"
    ),
    (Lifecycle.READY, Event.LATCH_REQUIRED): _t(Lifecycle.LATCHED, "PERSIST_LATCH", "PUBLISH_STATUS"),
    (Lifecycle.STARTING, Event.LATCH_REQUIRED): _t(Lifecycle.LATCHED, "PERSIST_LATCH", "PUBLISH_STATUS"),
    (Lifecycle.RUNNING, Event.LATCH_REQUIRED): _t(Lifecycle.LATCHED, "PERSIST_LATCH", "PUBLISH_STATUS"),
    (Lifecycle.STOPPED, Event.LATCH_REQUIRED): _t(Lifecycle.LATCHED, "PERSIST_LATCH", "PUBLISH_STATUS"),
    (Lifecycle.LATCHED, Event.BOOT_OBSERVED): _t(
        Lifecycle.SAFE_HOLD, "NO_BUDGET_DEBIT", "DO_NOT_START_PRIVILEGED_RUNTIME", "SIGNAL_LATCHED"
    ),
    (Lifecycle.SAFE_HOLD, Event.BOOT_OBSERVED): _t(
        Lifecycle.SAFE_HOLD, "NO_BUDGET_DEBIT", "DO_NOT_START_PRIVILEGED_RUNTIME", "SIGNAL_LATCHED"
    ),
    (Lifecycle.STOPPED, Event.BOOT_OBSERVED): _t(Lifecycle.READY, "NO_BUDGET_DEBIT", "PUBLISH_STATUS"),
    (Lifecycle.READY, Event.BOOT_OBSERVED): _t(Lifecycle.READY, "NO_BUDGET_DEBIT", "PUBLISH_STATUS"),
    (Lifecycle.LATCHED, Event.RECOVERY_AUTHORIZED): _t(
        Lifecycle.RECOVERY_AUTHORIZED, "VERIFY_RECOVERY_AUTHORIZATION", "PUBLISH_STATUS"
    ),
    (Lifecycle.SAFE_HOLD, Event.RECOVERY_AUTHORIZED): _t(
        Lifecycle.RECOVERY_AUTHORIZED, "VERIFY_RECOVERY_AUTHORIZATION", "PUBLISH_STATUS"
    ),
    (Lifecycle.RECOVERY_AUTHORIZED, Event.RECOVERY_STARTED): _t(
        Lifecycle.RECOVERY_PROBING, "ATOMIC_RESERVE_BUDGET_AND_NONCE", "PUBLISH_STATUS"
    ),
    (Lifecycle.RECOVERY_PROBING, Event.RECOVERY_VERIFIED): _t(
        Lifecycle.RUNNING, "PRESERVE_FAILURE_HISTORY", "BEGIN_HEALTH_VERIFICATION", "PUBLISH_STATUS"
    ),
    (Lifecycle.RECOVERY_PROBING, Event.RECOVERY_FAILED): _t(
        Lifecycle.LATCHED, "RECORD_RECOVERY_FAILURE", "PRESERVE_RECOVERY_DEBIT", "PUBLISH_STATUS"
    ),
    (Lifecycle.STARTING, Event.HEALTH_OBSERVED): _t(Lifecycle.STARTING, "EVALUATE_HEALTH_SAMPLE"),
    (Lifecycle.RUNNING, Event.HEALTH_OBSERVED): _t(Lifecycle.RUNNING, "EVALUATE_HEALTH_SAMPLE"),
    (Lifecycle.RECOVERY_PROBING, Event.HEALTH_OBSERVED): _t(
        Lifecycle.RECOVERY_PROBING, "EVALUATE_HEALTH_SAMPLE"
    ),
}


def transition(state: Lifecycle, event: Event) -> Transition:
    try:
        return TRANSITIONS[(Lifecycle(state), Event(event))]
    except (KeyError, ValueError):
        raise TransitionRejected("CG2_TRANSITION_UNDEFINED") from None


@dataclass(frozen=True)
class HealthEvidence:
    last_sequence: int = -1
    last_observed_at: float = -1.0
    healthy_samples: tuple[float, ...] = ()


@dataclass(frozen=True)
class HealthSample:
    sequence: int
    observed_at: float
    fresh: bool
    progress: bool
    invariants_ok: bool
    degraded: bool = False


def observe_health(evidence: HealthEvidence, sample: HealthSample) -> tuple[HealthEvidence, Health]:
    if (
        type(sample.sequence) is not int
        or sample.sequence <= evidence.last_sequence
        or type(sample.observed_at) not in (int, float)
        or not math.isfinite(sample.observed_at)
        or sample.observed_at < 0
        or sample.observed_at < evidence.last_observed_at
    ):
        raise TransitionRejected("CG2_HEALTH_SAMPLE_INVALID")
    base = replace(
        evidence,
        last_sequence=sample.sequence,
        last_observed_at=float(sample.observed_at),
    )
    if not (sample.fresh and sample.progress and sample.invariants_ok):
        return replace(base, healthy_samples=()), Health.DEGRADED if sample.degraded else Health.UNHEALTHY
    accepted = evidence.healthy_samples
    if len(accepted) < 3 and (not accepted or sample.observed_at - accepted[-1] >= 60.0):
        accepted = (*accepted, float(sample.observed_at))
    updated = replace(base, healthy_samples=accepted)
    if len(accepted) == 3 and sample.observed_at - accepted[-1] >= 900.0:
        return updated, Health.STABLE
    return updated, Health.HEALTHY

