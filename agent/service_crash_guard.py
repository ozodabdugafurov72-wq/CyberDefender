"""Bounded lifecycle accounting, independent of application authorization.

No OS actions, wall-clock resets, or SafetyCore reset capability live here.
The store is held exclusively by one service host for its entire lifetime.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import secrets
import threading
import time

SERVICES = ("CyberDefenderAgent", "CyberDefenderControlPlane", "CyberDefenderOwnerUI")
SCHEMA = "cd.service-crash.v1"
HISTORY_LIMIT = 32


@dataclass(frozen=True)
class CrashPolicy:
    # Staging defaults: 3 matches existing SCM attempt sequence; 60 seconds
    # matches its final delay and the sensor stability window. These are NOT
    # calibrated production SLOs. Integration must validate them before rollout.
    attempts: int = 3
    stable_seconds: float = 60.0
    stable_checks: int = 3
    cooldown_seconds: float = 60.0
    probes: int = 1

    def __post_init__(self):
        import math
        if any(type(x) is not int or not 1 <= x <= 32 for x in (self.attempts, self.stable_checks, self.probes)):
            raise ValueError("CRASH_POLICY_COUNT_INVALID")
        if any(not math.isfinite(x) or not 1 <= x <= 86400 for x in (self.stable_seconds, self.cooldown_seconds)):
            raise ValueError("CRASH_POLICY_DURATION_INVALID")


def fresh_record(service):
    if service not in SERVICES: raise ValueError("SERVICE_ID_INVALID")
    return dict(schema=SCHEMA, service=service, revision=0, boot="", session="",
                generation=0, recent_failures=[], cumulative_failures=0,
                clean_stop=True, active_attempt=False, last_progress=0.0,
                state="READY", attempts_since_stable=0, probes_used=0,
                repair_count=0, progress_count=0)


class CrashGuard:
    def __init__(self, store, *, boot: str, policy=CrashPolicy(), clock=time.monotonic):
        self.store, self.policy, self.clock = store, policy, clock
        self.lock = threading.RLock()
        self.record = store.load()
        self.allow_optional = (self.record["clean_stop"] and self.record["attempts_since_stable"] == 0
                               and self.record["state"] in {"READY", "RUNNING"})
        self._stable_since = None
        self._checks = 0
        self._hold_since = clock()
        self._attached_at = clock()
        self._last_tick = clock()
        self._store_failed = False
        self.watchdog = None
        if self.record["active_attempt"]:
            self._failure("PREVIOUS_ATTEMPT_INTERRUPTED")
        self.record.update(boot=boot, session=secrets.token_hex(16), clean_stop=False, active_attempt=False)
        self._commit()

    def _commit(self):
        if self._store_failed: raise RuntimeError("CRASH_STORE_UNAVAILABLE")
        try:
            self.record = self.store.write(copy.deepcopy(self.record))
        except Exception:
            self._store_failed = True
            self.record["state"] = "UNAVAILABLE"
            if self.watchdog is not None: self.watchdog.unavailable()
            raise RuntimeError("CRASH_STORE_UNAVAILABLE") from None

    def _now(self):
        now = self.clock()
        if now < self._last_tick:
            # An unexpected monotonic rollback earns no recovery credit.
            self._stable_since = None; self._checks = 0; self._hold_since = now
        self._last_tick = now
        return now

    def _failure(self, code):
        self.allow_optional = False
        r = self.record
        r["cumulative_failures"] += 1
        r["recent_failures"] = (r["recent_failures"] + [dict(
            generation=r["generation"], boot=r["boot"], code=code,
            tick=max(0.0, self.clock()))])[-HISTORY_LIMIT:]
        r["active_attempt"] = False
        if r["state"] != "UNAVAILABLE":
            r["state"] = "LATCHED" if r["attempts_since_stable"] >= self.policy.attempts or r["state"] == "PROBE" else "READY"
        self._hold_since = self.clock()
        self._stable_since = None; self._checks = 0

    def admit(self):
        with self.lock:
            now = self._now(); r = self.record
            if self._store_failed or r["active_attempt"] or r["state"] == "UNAVAILABLE": return False
            if r["attempts_since_stable"] >= self.policy.attempts and r["state"] != "LATCHED":
                r["state"] = "LATCHED"
                self._commit()
            if r["state"] == "LATCHED":
                # Cooldown belongs to this continuously responsive host, not
                # attacker-controlled wall time or a prior process uptime.
                if now - self._hold_since < self.policy.cooldown_seconds or r["probes_used"] >= self.policy.probes:
                    return False
                r["probes_used"] += 1; r["state"] = "PROBE"
            else:
                if r["attempts_since_stable"] and now - self._hold_since < self.policy.cooldown_seconds: return False
                r["state"] = "STARTING"
            r["generation"] += 1; r["attempts_since_stable"] += 1
            r["active_attempt"] = True; r["clean_stop"] = False
            self._stable_since = None; self._checks = 0
            self._commit()  # Durable debit must complete before the factory runs.
            if self.watchdog is not None: self.watchdog.begin()
            return True

    def progress(self, *, healthy: bool):
        with self.lock:
            now = self._now(); r = self.record
            if not r["active_attempt"] or self._store_failed: return
            if healthy:
                r["last_progress"] = max(0.0, now); r["progress_count"] += 1
            if self.watchdog is not None: self.watchdog.progress(healthy)
            if healthy:
                self._checks += 1
                if self._stable_since is None: self._stable_since = now
                if self._checks >= self.policy.stable_checks and now - self._stable_since >= self.policy.stable_seconds:
                    r["state"] = "RUNNING"; r["attempts_since_stable"] = 0; r["probes_used"] = 0
            else:
                self._stable_since = None; self._checks = 0
            self._commit()

    def failed(self, code="ATTEMPT_FAILED"):
        with self.lock:
            # Allowlisted reason codes only: never accept an exception string.
            if code not in {"ATTEMPT_FAILED", "WORK_UNHEALTHY", "CLEANUP_UNVERIFIED"}: code = "ATTEMPT_FAILED"
            self._failure(code)
            if self.watchdog is not None: self.watchdog.unavailable()
            if code == "CLEANUP_UNVERIFIED": self.record["state"] = "UNAVAILABLE"
            self._commit()

    def stop(self):
        with self.lock:
            self.record["clean_stop"] = True; self.record["active_attempt"] = False
            if self.watchdog is not None: self.watchdog.unavailable()
            self._commit()  # Preserve all counts, including short healthy starts.

    def snapshot(self):
        with self.lock:
            return {k: self.record[k] for k in ("service", "state", "generation", "cumulative_failures",
                    "attempts_since_stable", "probes_used", "clean_stop", "last_progress", "progress_count")}
