from __future__ import annotations

from agent.correlation.engine import CorrelationEngine


def check(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


engine = CorrelationEngine(window_seconds=60)
last = None
submitted = CorrelationEngine.MAX_EVENTS_PER_INCIDENT + 75

for index in range(submitted):
    last = engine.ingest({
        "event_type": "DETECTION",
        "source": "TEST",
        "data": {
            "type": "HIGH_MEMORY_USAGE",
            "severity": "WARNING",
            "source": "SystemObserver",
            "value": 80.0 + index / 1000.0,
            "message": f"memory pressure sample {index}",
            "host_id": "host-a",
        },
    })

check(last is not None, "Incident remains available after sustained observations")
check(last["event_count"] == submitted, "event_count preserves cumulative occurrence total")
check(last["evidence_count"] == CorrelationEngine.MAX_EVENTS_PER_INCIDENT, "Stored evidence remains bounded")
check(len(last["detections"]) == CorrelationEngine.MAX_EVENTS_PER_INCIDENT, "Detection list never exceeds evidence cap")
check(last["evidence_limit"] == CorrelationEngine.MAX_EVENTS_PER_INCIDENT, "Incident exposes evidence retention limit")
check(last["detections"][-1]["value"] == 80.0 + (submitted - 1) / 1000.0, "Newest forensic observation is retained")
check(last["detections"][0]["value"] > 80.0, "Oldest observations are compacted once cap is reached")
check(last["severity"] == "MEDIUM", "Repeated resource observations do not escalate severity by count alone")

stats = engine.get_stats()
check(stats["failed"] == 0, "Compaction path introduces no correlation failures")

print("RESULT: PASS")
