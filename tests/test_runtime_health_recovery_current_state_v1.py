from agent.main import CyberDefenderRuntime
from agent.service_runner import ServiceRunner


resolve = CyberDefenderRuntime._resolve_degraded_state

# A historical failure count cannot keep a recovered runtime degraded.
assert resolve(
    current_degraded=True,
    active_degradation=False,
    cycle_failures=7,
    component_failures=12,
    last_error=None,
) is False

# A current error remains fail-closed.
assert resolve(
    current_degraded=True,
    active_degradation=False,
    cycle_failures=7,
    component_failures=12,
    last_error="CURRENT_RUNTIME_ERROR",
) is True


class Runtime:
    VERSION = "2.4"

    def __init__(self):
        self.cycles = 0
        self.last_error = None
        self.safety = type("Safety", (), {"enter_safe_mode": lambda *_: None})()

    def begin_managed_loop(self):
        pass

    def run_cycle(self):
        self.cycles += 1

    def health_snapshot(self):
        status = "DEGRADED" if self.cycles == 1 else "HEALTHY"
        return {
            "runtime": {"status": status},
            "resource_guard": {"state": "NORMAL"},
        }

    def stop(self, _reason):
        pass

    def close(self):
        pass


class Telemetry:
    def __init__(self):
        self.heartbeats = []

    def register(self, **_kwargs):
        return True

    def heartbeat(self, **kwargs):
        self.heartbeats.append(kwargs)
        return True


runtime = Runtime()
telemetry = Telemetry()
runner = ServiceRunner(lambda: runtime, telemetry_client=telemetry, interval_seconds=0.01)
runner.run(max_cycles=2)

assert [item["health_state"] for item in telemetry.heartbeats] == [
    "DEGRADED",
    "HEALTHY",
]
assert telemetry.heartbeats[-1]["resource_state"] == "NORMAL"
print("RUNTIME_CURRENT_HEALTH_RECOVERY=PASS")
