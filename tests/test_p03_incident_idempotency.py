from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.correlation.engine import CorrelationEngine


def detection(event_id: str, value: int = 1) -> dict:
    return {
        "event_type": "DETECTION",
        "event_id": event_id,
        "data": {
            "type": "P03_IDEMPOTENCY_TEST",
            "severity": "HIGH",
            "source": "p03-test",
            "value": value,
            "message": "synthetic",
        },
    }


class P03IncidentIdempotencyTests(unittest.TestCase):
    def test_same_source_event_has_stable_incident_identity_after_restart(self):
        first = CorrelationEngine().ingest(detection("evt-stable-1"), strict=True)
        restarted = CorrelationEngine().ingest(detection("evt-stable-1"), strict=True)

        self.assertIsInstance(first, dict)
        self.assertIsInstance(restarted, dict)
        self.assertEqual(first["incident_id"], restarted["incident_id"])
        self.assertEqual(first["idempotency_key"], restarted["idempotency_key"])
        self.assertEqual(first["source_event_id"], "evt-stable-1")
        self.assertEqual(restarted["source_event_id"], "evt-stable-1")

    def test_distinct_source_events_have_distinct_create_identities(self):
        first = CorrelationEngine().ingest(detection("evt-a"), strict=True)
        second = CorrelationEngine().ingest(detection("evt-b"), strict=True)

        self.assertNotEqual(first["incident_id"], second["incident_id"])
        self.assertNotEqual(first["idempotency_key"], second["idempotency_key"])

    def test_legacy_direct_engine_call_remains_supported(self):
        event = detection("legacy")
        event.pop("event_id")
        incident = CorrelationEngine().ingest(event, strict=True)
        self.assertIsInstance(incident, dict)
        self.assertIsNone(incident["source_event_id"])
        self.assertIsNone(incident["idempotency_key"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

