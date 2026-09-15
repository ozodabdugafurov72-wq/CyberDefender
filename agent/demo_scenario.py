from __future__ import annotations

import time
import uuid
from typing import Any


class CriticalThreatDemoScenario:
    """Safe P0.8 critical-threat / recovery visualization model.

    The scenario is synthetic telemetry only. It does not generate malware,
    invoke system commands, alter the host, or grant response authorization.
    """

    VERSION = "0.1"

    @classmethod
    def build(cls) -> dict[str, Any]:
        now = time.time()
        scenario_id = f"DEMO-{uuid.uuid4().hex[:12].upper()}"
        steps = [
            (0, "INITIAL_ACCESS_SIGNAL", "HIGH", "Untrusted document-like execution chain observed"),
            (2, "PROCESS_CHAIN_ANOMALY", "HIGH", "Unexpected child-process ancestry diverges from local baseline"),
            (5, "PRIVILEGE_BOUNDARY_SIGNAL", "CRITICAL", "Synthetic privilege-boundary anomaly correlated"),
            (8, "PERSISTENCE_SIGNAL", "HIGH", "Synthetic persistence-change telemetry correlated"),
            (11, "LATERAL_MOVEMENT_SIGNAL", "CRITICAL", "Synthetic peer-access behavior correlated"),
        ]
        timeline = [
            {
                "offset_seconds": offset,
                "timestamp": now + offset,
                "event_type": event_type,
                "severity": severity,
                "source": "P0.8-DemoScenario",
                "message": message,
                "synthetic": True,
            }
            for offset, event_type, severity, message in steps
        ]
        return {
            "scenario_id": scenario_id,
            "version": cls.VERSION,
            "name": "Critical Multi-Stage Threat Simulation",
            "threat_model": "ZERO_DAY_STYLE_BEHAVIOR_CHAIN",
            "synthetic": True,
            "authoritative": False,
            "real_world_effect": False,
            "generated_at": now,
            "timeline": timeline,
            "attack_graph": {
                "nodes": [item[1] for item in steps],
                "edges": [
                    [steps[index][1], steps[index + 1][1]]
                    for index in range(len(steps) - 1)
                ],
            },
            "risk": {
                "level": "CRITICAL",
                "score": 96,
                "reason": "Multiple independent synthetic behavior domains correlated",
            },
            "policy": {
                "outcome": "CONTAINMENT_RECOMMENDED",
                "recommendation": "SIMULATE_ISOLATE_AND_QUARANTINE",
                "authorization": "NOT_GRANTED",
                "authoritative": False,
            },
            "verification": {
                "outcome": "VERIFIED_DEMO_PROPOSAL",
                "verified": True,
                "authorization": "NOT_GRANTED",
            },
            "response_simulation": {
                "mode": "DRY_RUN_ONLY",
                "real_world_effect": False,
                "actions": [
                    {"action": "SUSPEND_SUSPECT_PROCESS", "status": "SIMULATED"},
                    {"action": "ISOLATE_ENDPOINT_NETWORK", "status": "SIMULATED"},
                    {"action": "QUARANTINE_SUSPECT_ARTIFACT", "status": "SIMULATED"},
                ],
            },
            "recovery_plan": {
                "status": "PLAN_READY",
                "real_world_effect": False,
                "phases": [
                    "VERIFY_CONTAINMENT",
                    "REMOVE_SYNTHETIC_PERSISTENCE",
                    "RESTORE_TRUSTED_CONFIGURATION",
                    "POST_ACTION_INTEGRITY_CHECK",
                    "CONTROLLED_RECONNECT",
                ],
            },
            "safety": {
                "malware_payload": False,
                "system_command_execution": False,
                "privileged_action": False,
                "authorization_granted": False,
            },
        }
