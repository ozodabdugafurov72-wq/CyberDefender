"""Independent completed-work observer. Never terminates threads/processes."""
from __future__ import annotations
import ctypes
import os
import threading
import time


def active_time():
    if os.name != "nt": return time.monotonic()
    value=ctypes.c_ulonglong()
    query=ctypes.WinDLL("kernel32",use_last_error=True).QueryUnbiasedInterruptTime
    query.argtypes=[ctypes.POINTER(ctypes.c_ulonglong)]; query.restype=ctypes.c_int
    if not query(ctypes.byref(value)): raise RuntimeError("ACTIVE_CLOCK_UNAVAILABLE")
    return value.value / 10_000_000.0


class ProgressWatchdog:
    def __init__(self, *, deadline=60.0, clock=active_time):
        import math
        if not math.isfinite(deadline) or not 1 <= deadline <= 86400: raise ValueError("WATCHDOG_DEADLINE_INVALID")
        self.deadline=deadline; self.clock=clock; self.lock=threading.Lock()
        self.last=clock(); self.completed=0; self.healthy=False; self.enabled=False

    def begin(self):
        with self.lock:
            self.last=self.clock(); self.enabled=True; self.healthy=False

    def progress(self, healthy):
        with self.lock:
            self.healthy=healthy is True
            if self.healthy:
                self.last=self.clock(); self.completed+=1

    def unavailable(self):
        with self.lock: self.enabled=False; self.healthy=False

    def snapshot(self):
        with self.lock:
            now=self.clock()
            if now < self.last:
                self.last=now; self.healthy=False
            age=max(0.0,now-self.last)
            state="UNAVAILABLE" if not self.enabled else "STALLED" if age > self.deadline else "HEALTHY" if self.healthy else "DEGRADED"
            return dict(state=state,completed=self.completed,age_seconds=round(age,3),deadline_seconds=self.deadline,
                        action="OBSERVE_ONLY",authorization="NOT_GRANTED")

    def monitor(self, stop_event, callback):
        last=None
        while not stop_event.wait(1.0):
            try: state=self.snapshot()["state"]
            except Exception: state="UNAVAILABLE"
            if state != last:
                callback(state); last=state
