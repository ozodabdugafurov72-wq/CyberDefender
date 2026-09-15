from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.config import load_config

safety = SafetyCore()
config = load_config()

runtime = CyberDefenderRuntime(
    safety,
    config,
)

health = runtime.health_snapshot()

print()
print("=== CYBERDEFENDER STARTUP HEALTH DIAGNOSTIC ===")

for name, value in health.items():
    print()
    print(f"[{name}]")
    print(value)

print()
print("=== CRITICAL COMPONENTS ===")

critical = (
    "key_manager",
    "runtime_pipeline",
    "admission_gateway",
    "spool",
    "pipeline",
)

for name in critical:
    value = health.get(name, {})
    print(
        f"{name}: "
        f"status={value.get('status', 'MISSING')}"
    )

print()
print("=== RESULT ===")

failed = []

for name in critical:
    value = health.get(name, {})
    status = value.get("status")

    if status != "HEALTHY":
        failed.append(
            (name, status)
        )

if failed:
    print("HEALTH_GATE_FAILURE=True")

    for name, status in failed:
        print(
            f"FAILED_COMPONENT={name} "
            f"STATUS={status}"
        )
else:
    print("HEALTH_GATE_FAILURE=False")
    print("ALL_CRITICAL_COMPONENTS_HEALTHY=True")
