from __future__ import annotations

import tempfile
import time
from pathlib import Path

from agent.service_runner import ServiceRunner
from control_plane.distribution_repository import DistributionRepository
from dashboard_owner.fleet_read_model import FleetReadModel


class Runtime:
    VERSION = "2.4"

    def __init__(self, delay: float = 0.0):
        self.delay = delay
        self.cycles = 0
        self.last_error = None
        self.safety = type("Safety", (), {"enter_safe_mode": lambda *_: None})()

    def begin_managed_loop(self):
        pass

    def run_cycle(self):
        if self.delay:
            time.sleep(self.delay)
        self.cycles += 1

    def health_snapshot(self):
        return {"runtime": {"status": "HEALTHY"}, "resource_guard": {"state": "NORMAL"}}

    def stop(self, _reason):
        pass

    def close(self):
        pass


class Client:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.heartbeats = []
        self.failures = 0

    def register(self, **_kwargs):
        return True

    def heartbeat(self, **kwargs):
        self.heartbeats.append(kwargs)
        result = self.results.pop(0) if self.results else True
        if isinstance(result, Exception):
            self.failures += 1
            raise result
        if result is False:
            self.failures += 1
        return result


# A slow cycle no longer starves the fleet heartbeat. While it is stale, the
# watchdog reports DEGRADED; after completion the normal heartbeat reports the
# verified runtime state.
slow_runtime = Runtime(delay=0.15)
slow_client = Client()
slow_runner = ServiceRunner(lambda: slow_runtime, interval_seconds=0.02, telemetry_client=slow_client)
slow_runner.RUNTIME_FRESHNESS_SECONDS = 0.05
slow_runner.run(max_cycles=1)
assert any(item["health_state"] == "DEGRADED" and item["last_error"] == "RUNTIME_CYCLE_STALE" for item in slow_client.heartbeats)
assert slow_client.heartbeats[-1]["health_state"] == "HEALTHY"

# Telemetry rejection/failure is retried and never stops local cycles.
retry_runtime = Runtime()
retry_client = Client([True, False, False, True])
retry_runner = ServiceRunner(lambda: retry_runtime, interval_seconds=0.01, telemetry_client=retry_client)
retry_runner.run(max_cycles=4)
assert retry_runtime.cycles == 4
assert retry_client.failures == 2
assert retry_client.heartbeats[-1]["health_state"] == "HEALTHY"
assert retry_runner.last_telemetry_error is None

# Duplicate hostnames remain separate by endpoint_id.
with tempfile.TemporaryDirectory() as td:
    db = Path(td) / "distribution.db"
    repo = DistributionRepository(db)
    repo.heartbeat(endpoint_id="A", hostname="PC-JDU", runtime_version="2.4", health_state="HEALTHY", service_state="RUNNING")
    repo.heartbeat(endpoint_id="B", hostname="PC-JDU", runtime_version="2.4", health_state="DEGRADED", service_state="RUNNING")
    rows = {row["endpoint_id"]: row for row in repo.recent_endpoints()}
    assert set(rows) == {"A", "B"}
    assert rows["A"]["health_state"] == "HEALTHY"
    assert rows["B"]["health_state"] == "DEGRADED"
    repo.close()

# Owner freshness uses the configured 90-second cutoff without fabricating
# liveness from historical health/service fields.
with tempfile.TemporaryDirectory() as td:
    db = Path(td) / "distribution.db"
    repo = DistributionRepository(db)
    repo.heartbeat(endpoint_id="fresh", hostname="h", runtime_version="2.4", health_state="HEALTHY", service_state="RUNNING")
    repo.heartbeat(endpoint_id="stale", hostname="h", runtime_version="2.4", health_state="HEALTHY", service_state="RUNNING")
    repo._conn.execute("UPDATE fleet_endpoints SET last_seen=? WHERE endpoint_id='stale'", (time.time() - 91.0,))
    snapshot = FleetReadModel(db).snapshot(online_after_seconds=90.0)
    assert snapshot["summary"]["online"] == 1
    assert snapshot["summary"]["offline"] == 1
    repo.close()

print("FLEET_HEARTBEAT_STARVATION=PASS")
