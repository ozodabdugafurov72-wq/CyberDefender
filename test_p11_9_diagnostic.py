from pathlib import Path
import shutil

from agent.event import SecurityEvent
from agent.crypto.key_manager import (
    KeyManager,
    generate_storage_key,
)
from agent.crypto.trust_decision_boundary import (
    TrustDecisionBoundary,
)


ROOT = Path(
    "state/test_p11_9_diagnostic"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

storage_key = generate_storage_key()

manager = KeyManager(
    ROOT / "keys",
    storage_key,
)

key_id = manager.generate_key()

boundary = TrustDecisionBoundary(
    manager
)

event = SecurityEvent(
    event_type="P11_9_DIAGNOSTIC",
    severity="HIGH",
    value=77,
    source="Diagnostic",
    message="P11.9 crypto diagnostic",
    confidence=0.99,
    host_id="host-p11-9",
    sensor_id="sensor-p11-9",
)

import json

payload = json.dumps(
    event.to_dict(),
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")

signature = manager.sign(
    payload
)

print("=== DIAGNOSTIC ===")
print("KEY_ID=", key_id)
print("ACTIVE_KEY=", manager.active_key_id())
print("READY=", manager.is_ready())
print("SIGNATURE_TYPE=", type(signature).__name__)
print("SIGNATURE_PRESENT=", bool(signature))
print("PAYLOAD_SIZE=", len(payload))

print()
print("=== DIRECT TRUST DECISION ===")

decision = boundary.verify(
    payload,
    signature,
    key_id,
)

print("ACCEPTED=", decision.accepted)
print("REASON=", decision.reason)
print("KEY_ID=", decision.key_id)

print()
print("=== HEALTH ===")

print(
    "MANAGER_HEALTH=",
    manager.health_check(),
)

print(
    "BOUNDARY_HEALTH=",
    boundary.health_check(),
)

print()
print("=== STATS ===")

print(
    "BOUNDARY_STATS=",
    boundary.get_stats(),
)
