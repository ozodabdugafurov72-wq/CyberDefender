from pathlib import Path
import shutil

from agent.crypto.key_manager import (
    KeyManager,
    generate_storage_key,
)

from agent.crypto.trust_decision_boundary import (
    TrustDecisionBoundary,
)


ROOT = Path(
    "state/test_p11_trust_boundary"
)


# ============================================================
# CLEAN TEST ENVIRONMENT
# ============================================================

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

storage_key = (
    generate_storage_key()
)


# ============================================================
# HELPER
# ============================================================

def print_decision(
    label,
    decision,
):
    print(
        label,
        "ACCEPTED=",
        decision.accepted,
    )

    print(
        label,
        "REASON=",
        decision.reason,
    )

    print(
        label,
        "KEY_ID=",
        decision.key_id,
    )


# ============================================================
# P11.7-01
# ACTIVE KEY + VALID SIGNATURE
# ============================================================

print(
    "=== P11.7-01 ACTIVE VALID ==="
)

manager = KeyManager(
    ROOT,
    storage_key,
)

key1 = manager.generate_key()

boundary = TrustDecisionBoundary(
    manager
)

payload = (
    b"CyberDefender trusted event"
)

mac1 = manager.sign(
    payload
)

decision = boundary.verify(
    payload,
    mac1,
    key1,
)

print(
    "KEY1_CREATED=",
    key1 is not None,
)

print(
    "MAC1_PRESENT=",
    bool(mac1),
)

print(
    "ACCEPTED=",
    decision.accepted,
)

print(
    "REASON=",
    decision.reason,
)

print(
    "KEY_ID_MATCH=",
    decision.key_id == key1,
)


# ============================================================
# P11.7-02
# ACTIVE KEY + TAMPERED PAYLOAD
# ============================================================

print()
print(
    "=== P11.7-02 TAMPERED PAYLOAD ==="
)

tampered_payload = (
    b"ATTACKER MODIFIED EVENT"
)

tampered = boundary.verify(
    tampered_payload,
    mac1,
    key1,
)

print(
    "ACCEPTED=",
    tampered.accepted,
)

print(
    "REASON=",
    tampered.reason,
)


# ============================================================
# P11.7-03
# KEY ROTATION
# ============================================================

print()
print(
    "=== P11.7-03 ROTATION ==="
)

key2 = manager.rotate()

print(
    "KEY2_CREATED=",
    key2 is not None,
)

print(
    "KEY1_METADATA=",
    manager.get_key_metadata(
        key1
    ),
)

print(
    "KEY2_METADATA=",
    manager.get_key_metadata(
        key2
    ),
)

print(
    "ACTIVE_KEY_ID=",
    manager.active_key_id(),
)


# ============================================================
# P11.7-04
# RETIRED KEY MUST BE REJECTED
# ============================================================

print()
print(
    "=== P11.7-04 RETIRED KEY ==="
)

retired = boundary.verify(
    payload,
    mac1,
    key1,
)

print(
    "ACCEPTED=",
    retired.accepted,
)

print(
    "REASON=",
    retired.reason,
)


# ============================================================
# P11.7-05
# NEW ACTIVE KEY + VALID SIGNATURE
# ============================================================

print()
print(
    "=== P11.7-05 NEW ACTIVE KEY ==="
)

payload2 = (
    b"New trusted event"
)

mac2 = manager.sign(
    payload2
)

active = boundary.verify(
    payload2,
    mac2,
    key2,
)

print(
    "MAC2_PRESENT=",
    bool(mac2),
)

print(
    "ACCEPTED=",
    active.accepted,
)

print(
    "REASON=",
    active.reason,
)

print(
    "KEY_ID_MATCH=",
    active.key_id == key2,
)


# ============================================================
# P11.7-06
# ACTIVE KEY + WRONG SIGNATURE
#
# IMPORTANT:
# This test MUST happen before key2 is revoked.
# ============================================================

print()
print(
    "=== P11.7-06 ACTIVE WRONG SIGNATURE ==="
)

wrong_signature = boundary.verify(
    payload2,
    "00" * 32,
    key2,
)

print(
    "ACCEPTED=",
    wrong_signature.accepted,
)

print(
    "REASON=",
    wrong_signature.reason,
)


# ============================================================
# P11.7-07
# UNKNOWN KEY
# ============================================================

print()
print(
    "=== P11.7-07 UNKNOWN KEY ==="
)

unknown = boundary.verify(
    payload2,
    mac2,
    "key-attacker-controlled",
)

print(
    "ACCEPTED=",
    unknown.accepted,
)

print(
    "REASON=",
    unknown.reason,
)


# ============================================================
# P11.7-08
# REVOKE ACTIVE KEY
# ============================================================

print()
print(
    "=== P11.7-08 REVOKE KEY ==="
)

revoke_result = manager.revoke(
    key2
)

print(
    "REVOKE_RESULT=",
    revoke_result,
)

print(
    "KEY2_METADATA_AFTER_REVOKE=",
    manager.get_key_metadata(
        key2
    ),
)

print(
    "ACTIVE_KEY_AFTER_REVOKE=",
    manager.active_key_id(),
)


# ============================================================
# P11.7-09
# REVOKED KEY MUST BE REJECTED
# ============================================================

print()
print(
    "=== P11.7-09 REVOKED KEY ==="
)

revoked = boundary.verify(
    payload2,
    mac2,
    key2,
)

print(
    "ACCEPTED=",
    revoked.accepted,
)

print(
    "REASON=",
    revoked.reason,
)


# ============================================================
# P11.7-10
# DEGRADED KEY MANAGER
# ============================================================

print()
print(
    "=== P11.7-10 DEGRADED MANAGER ==="
)

state_path = (
    ROOT
    / "key_state.json"
)

state_path.write_text(
    "{CORRUPTED}",
    encoding="utf-8",
)

degraded_manager = KeyManager(
    ROOT,
    storage_key,
)

degraded_boundary = (
    TrustDecisionBoundary(
        degraded_manager
    )
)

degraded = (
    degraded_boundary.verify(
        payload2,
        mac2,
        key2,
    )
)

print(
    "MANAGER_READY=",
    degraded_manager.is_ready(),
)

print(
    "ACCEPTED=",
    degraded.accepted,
)

print(
    "REASON=",
    degraded.reason,
)


# ============================================================
# P11.7-11
# HEALTH
# ============================================================

print()
print(
    "=== P11.7-11 HEALTH ==="
)

print(
    "BOUNDARY_HEALTH=",
    boundary.health_check(),
)

print(
    "BOUNDARY_STATS=",
    boundary.get_stats(),
)


# ============================================================
# P11.7-12
# FINAL
# ============================================================

print()
print(
    "=== P11.7-12 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
