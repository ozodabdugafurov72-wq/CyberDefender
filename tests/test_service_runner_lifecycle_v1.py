from __future__ import annotations

from agent.service_runner import ServiceRunner


class FakeSafety:
    def __init__(self): self.reasons=[]
    def enter_safe_mode(self, reason): self.reasons.append(reason)

class FakeRuntime:
    VERSION="2.4"
    def __init__(self):
        self.cycles=0; self.closed=False; self.stopped=False; self.safety=FakeSafety(); self.last_error=None
    def run_cycle(self): self.cycles += 1
    def health_check(self): return {"runtime":{"status":"HEALTHY"},"resource_guard":{"state":"NORMAL"}}
    def stop(self, reason=""): self.stopped=True
    def close(self): self.closed=True

class FakeTelemetry:
    def __init__(self): self.registered=0; self.heartbeats=0
    def register(self, **kwargs): self.registered += 1; return True
    def heartbeat(self, **kwargs): self.heartbeats += 1; return True

rt=FakeRuntime(); tel=FakeTelemetry()
runner=ServiceRunner(lambda: rt, interval_seconds=.01, telemetry_client=tel)
runner.run(max_cycles=3)
assert runner.cycles == 3
assert runner.failures == 0
assert rt.cycles == 3
assert rt.stopped and rt.closed
assert tel.registered == 1 and tel.heartbeats == 3
print("PASS | ServiceRunner owns runtime lifecycle")
print("PASS | graceful stop/close is deterministic")
print("PASS | non-authoritative fleet telemetry is emitted")
print("RESULT: PASS")
