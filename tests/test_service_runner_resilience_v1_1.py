from __future__ import annotations

from agent.service_runner import ServiceRunner


class FakeSafety:
    def __init__(self): self.reasons=[]
    def enter_safe_mode(self, reason): self.reasons.append(reason)


class FakeRuntime:
    VERSION="2.4"
    def __init__(self):
        self.cycles=0; self.running=False; self.shutdown_requested=False
        self.closed=False; self.stopped=False; self.safety=FakeSafety(); self.last_error=None
    def begin_managed_loop(self): self.running=True; self.shutdown_requested=False
    def run_cycle(self): self.cycles += 1
    def health_snapshot(self): return {"runtime":{"status":"DEGRADED"},"resource_guard":{"state":"DEGRADED"}}
    def stop(self, reason=""): self.stopped=True; self.running=False; self.shutdown_requested=True
    def close(self): self.closed=True


class FailingTelemetry:
    def register(self, **kwargs): raise ConnectionError("control plane unavailable")
    def heartbeat(self, **kwargs): raise TimeoutError("heartbeat timeout")


rt=FakeRuntime()
runner=ServiceRunner(lambda: rt, interval_seconds=.01, telemetry_client=FailingTelemetry())
runner.run(max_cycles=2)
checks={
    "non-authoritative telemetry outage does not stop core service loop": runner.cycles == 2,
    "telemetry failures are observable": runner.telemetry_failures >= 3,
    "telemetry failure is not counted as core cycle failure": runner.failures == 0,
    "authoritative health_snapshot path is supported": rt.cycles == 2,
    "managed lifecycle exits cleanly": rt.stopped and rt.closed and not rt.running,
}
failures=0
for label,ok in checks.items():
    print(("PASS" if ok else "FAIL") + " | " + label)
    failures += 0 if ok else 1
print(f"RESULT: {'PASS' if failures == 0 else 'FAIL'}")
raise SystemExit(0 if failures == 0 else 1)
