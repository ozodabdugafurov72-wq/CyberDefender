from agent.main import (
    CyberDefenderRuntime,
    _load_runtime_config,
)
from agent.safety import SafetyCore


print("=== CYBERDEFENDER REAL KEY MANAGER TEST ===")

safety = SafetyCore()

config = _load_runtime_config(safety)

if config is None:
    raise SystemExit(
        "CONFIG LOAD FAILED"
    )

runtime = CyberDefenderRuntime(
    safety,
    config,
)

print()
print("=== KEY MANAGER HEALTH ===")

km = runtime.key_manager

print(km.health_check())

print()
print("=== KEY MANAGER STATE ===")

print("is_ready:")
print(km.is_ready())

print()
print("active_key_id:")
print(km.active_key_id())

print()
print("status:")
print(getattr(km, "_status", None))

print()
print("key_count:")
print(len(getattr(km, "_keys", {})))

print()
print("key_ids:")
print(list(getattr(km, "_keys", {}).keys()))

print()
print("=== ADMISSION GATEWAY ===")

gateway = runtime.admission_gateway

if gateway is None:
    print("gateway: NONE")
else:
    print(gateway.health_check())
