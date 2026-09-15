from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.correlation.engine import CorrelationEngine


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def detection(*, kind: str, source: str, value, host_id=None, severity="WARNING") -> dict:
    return {
        "event_type": "DETECTION",
        "source": "TEST",
        "data": {
            "type": kind,
            "severity": severity,
            "source": source,
            "value": value,
            "message": f"{kind} from {source}",
            "host_id": host_id,
        },
    }


def main() -> None:
    engine = CorrelationEngine(window_seconds=60)

    first = engine.ingest(detection(kind="HIGH_MEMORY_USAGE", source="SystemObserver", value=91.0))
    second = engine.ingest(detection(kind="LOW_AVAILABLE_MEMORY", source="RuleEngine", value=780.0))
    third = engine.ingest(detection(kind="HIGH_MEMORY_USAGE_RECOVERED", source="EventState", value=0, severity="INFO"))

    check(first is not None and second is not None and third is not None, "All independent memory-pressure signals correlate")
    check(first["incident_id"] == second["incident_id"] == third["incident_id"], "SystemObserver, RuleEngine and EventState share one memory incident")
    check(third["correlation_key"] == "resource:agent-local:MEMORY_PRESSURE", "Local resource family uses source-independent bounded key")
    check(third["incident_family"] == "MEMORY_PRESSURE", "Incident exposes normalized resource family")
    check(set(third["sources"]) == {"SystemObserver", "RuleEngine", "EventState"}, "Incident preserves contributing source diversity")
    check(set(third["detection_types"]) == {"HIGH_MEMORY_USAGE", "LOW_AVAILABLE_MEMORY", "HIGH_MEMORY_USAGE_RECOVERED"}, "Incident preserves distinct memory signal types")
    check(third["event_count"] == 3, "Coalescing preserves cumulative occurrence count")

    cpu = engine.ingest(detection(kind="HIGH_CPU_USAGE", source="SystemObserver", value=96.0))
    check(cpu is not None and cpu["incident_id"] != third["incident_id"], "Different resource families do not merge")
    check(cpu["correlation_key"] == "resource:agent-local:CPU_PRESSURE", "CPU pressure receives independent resource family")

    host_a = CorrelationEngine(window_seconds=60)
    a = host_a.ingest(detection(kind="HIGH_MEMORY_USAGE", source="SystemObserver", value=91.1, host_id="host-a"))
    b = host_a.ingest(detection(kind="LOW_AVAILABLE_MEMORY", source="RuleEngine", value=700.0, host_id="host-b"))
    check(a is not None and b is not None and a["incident_id"] != b["incident_id"], "Different explicit hosts never coalesce")
    check(a["correlation_key"] == "resource:host:host-a:MEMORY_PRESSURE", "Host A is endpoint scoped")
    check(b["correlation_key"] == "resource:host:host-b:MEMORY_PRESSURE", "Host B is endpoint scoped")

    security = CorrelationEngine(window_seconds=60)
    s1 = security.ingest(detection(kind="PROCESS_CHAIN_ANOMALY", source="SensorA", value=1, severity="HIGH"))
    s2 = security.ingest(detection(kind="PROCESS_CHAIN_ANOMALY", source="SensorB", value=2, severity="HIGH"))
    check(s1 is not None and s2 is not None and s1["incident_id"] != s2["incident_id"], "Unknown/security fallback remains source-isolated")
    check(s1["correlation_key"] == "agent-local:SensorA" and s2["correlation_key"] == "agent-local:SensorB", "Security fallback key contract is unchanged")

    stats = engine.get_stats()
    check(stats["failed"] == 0, "Resource coalescing introduces no correlation failures")
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
