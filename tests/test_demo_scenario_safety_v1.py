from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.demo_scenario import CriticalThreatDemoScenario


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def main() -> None:
    scenario = CriticalThreatDemoScenario.build()
    check(scenario["synthetic"] is True, "Critical threat scenario is explicitly synthetic")
    check(scenario["authoritative"] is False, "Demo scenario is non-authoritative")
    check(scenario["real_world_effect"] is False, "Demo scenario has no real-world effect")
    check(scenario["risk"]["level"] == "CRITICAL" and scenario["risk"]["score"] >= 90, "Scenario demonstrates critical multi-stage risk")
    check(len(scenario["timeline"]) >= 5, "Scenario exposes a multi-stage evidence timeline")
    check(len(scenario["attack_graph"]["edges"]) == len(scenario["timeline"]) - 1, "Scenario graph preserves ordered attack-chain relationships")
    check(scenario["policy"]["authorization"] == "NOT_GRANTED", "Policy visualization never grants authorization")
    check(scenario["verification"]["authorization"] == "NOT_GRANTED", "Independent verification visualization never grants authorization")
    check(scenario["response_simulation"]["mode"] == "DRY_RUN_ONLY", "Response visualization is dry-run only")
    check(all(item["status"] == "SIMULATED" for item in scenario["response_simulation"]["actions"]), "Every proposed response action remains simulated")
    check(scenario["recovery_plan"]["status"] == "PLAN_READY", "Recovery visualization produces a plan")
    check(scenario["recovery_plan"]["real_world_effect"] is False, "Recovery visualization does not mutate the host")
    safety = scenario["safety"]
    check(safety["malware_payload"] is False, "Scenario contains no malware payload")
    check(safety["system_command_execution"] is False, "Scenario executes no system command")
    check(safety["privileged_action"] is False and safety["authorization_granted"] is False, "Scenario cannot cross the privileged safety boundary")
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
