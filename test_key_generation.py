from agent.main import (
    CyberDefenderRuntime,
    _load_runtime_config,
)
from agent.safety import SafetyCore


print("=== KEY GENERATION + CRYPTO TEST ===")

safety = SafetyCore()

config = _load_runtime_config(safety)

if config is None:
    raise SystemExit("CONFIG LOAD FAILED")

runtime = CyberDefenderRuntime(
    safety,
    config,
)

km = runtime.key_manager

print()
print("BEFORE:")
print("status =", getattr(km, "_status", None))
print("ready =", km.is_ready())
print("active_key =", km.active_key_id())
print("key_count =", len(getattr(km, "_keys", {})))

print()
print("GENERATING KEY...")

key_id = km.generate_key()

print("generated_key_id =", key_id)

print()
print("AFTER:")

print("status =", getattr(km, "_status", None))
print("ready =", km.is_ready())
print("active_key =", km.active_key_id())
print("key_count =", len(getattr(km, "_keys", {})))

print()
print("HEALTH:")

print(km.health_check())

print()
print("=== SIGN / VERIFY TEST ===")

payload = b"CyberDefender-P11.20-TEST"

signature = km.sign(payload)

print("signature_created =", bool(signature))

if signature is None:
    raise SystemExit("SIGN FAILED")

verified = km.verify(
    payload,
    signature,
    key_id,
)

print("signature_verified =", verified)

print()
print("=== RESULT ===")

if (
    key_id
    and km.active_key_id() == key_id
    and signature
    and verified
):
    print("KEY CRYPTO TEST: PASS")
else:
    print("KEY CRYPTO TEST: FAIL")
