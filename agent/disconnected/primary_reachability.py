from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Callable, Optional
import time


@dataclass(frozen=True)
class PrimaryReachabilitySnapshot:
    reachable: Optional[bool]
    source: str | None
    evidence_available: bool
    stale: bool
    age_seconds: float | None
    observations: int
    successes: int
    failures: int


class PrimaryReachabilityTracker:
    """
    CyberDefender ACP Primary Reachability Tracker v0.1.

    Receives outcomes from existing authenticated fleet
    register/heartbeat traffic.

    It performs NO network request itself.

    Security semantics:
      True  = recent authenticated fleet operation succeeded.
      False = recent fleet operation was attempted and failed/rejected.
      None  = no usable evidence or evidence is stale.

    Reachability evidence NEVER grants authorization.
    """

    VERSION = "0.1"

    def __init__(
        self,
        *,
        stale_after_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:

        stale_after = float(stale_after_seconds)

        if stale_after <= 0:
            raise ValueError(
                "stale_after_seconds must be > 0"
            )

        self._stale_after = stale_after
        self._clock = clock
        self._lock = RLock()

        self._reachable: Optional[bool] = None
        self._source: str | None = None
        self._observed_at: float | None = None

        self._observations = 0
        self._successes = 0
        self._failures = 0

    def record(
        self,
        reachable: Optional[bool],
        *,
        source: str,
    ) -> None:

        if reachable not in (True, False, None):
            raise TypeError(
                "reachable must be True, False or None"
            )

        source_value = str(source or "").strip()

        if not source_value:
            raise ValueError(
                "source is required"
            )

        now = float(self._clock())

        with self._lock:
            self._reachable = reachable
            self._source = source_value
            self._observed_at = now
            self._observations += 1

            if reachable is True:
                self._successes += 1

            elif reachable is False:
                self._failures += 1

    def snapshot(
        self,
    ) -> PrimaryReachabilitySnapshot:

        now = float(self._clock())

        with self._lock:
            reachable = self._reachable
            source = self._source
            observed_at = self._observed_at

            observations = self._observations
            successes = self._successes
            failures = self._failures

        if observed_at is None:
            return PrimaryReachabilitySnapshot(
                reachable=None,
                source=None,
                evidence_available=False,
                stale=False,
                age_seconds=None,
                observations=observations,
                successes=successes,
                failures=failures,
            )

        age = max(
            0.0,
            now - observed_at,
        )

        stale = age > self._stale_after

        return PrimaryReachabilitySnapshot(
            reachable=None if stale else reachable,
            source=source,
            evidence_available=True,
            stale=stale,
            age_seconds=age,
            observations=observations,
            successes=successes,
            failures=failures,
        )

    def current(
        self,
    ) -> Optional[bool]:
        return self.snapshot().reachable

    def health_snapshot(
        self,
    ) -> dict[str, object]:

        snap = self.snapshot()

        return {
            "component":
                "PrimaryReachabilityTracker",

            "version":
                self.VERSION,

            "status":
                "HEALTHY",

            "mode":
                "PASSIVE_OBSERVER",

            "reachable":
                snap.reachable,

            "source":
                snap.source,

            "evidence_available":
                snap.evidence_available,

            "stale":
                snap.stale,

            "age_seconds":
                snap.age_seconds,

            "observations":
                snap.observations,

            "successes":
                snap.successes,

            "failures":
                snap.failures,

            "stale_after_seconds":
                self._stale_after,

            "authority":
                "NONE",

            "authorization":
                "NOT_GRANTED",

            "authoritative":
                False,

            "network_probe":
                False,

            "os_actions":
                False,
        }
