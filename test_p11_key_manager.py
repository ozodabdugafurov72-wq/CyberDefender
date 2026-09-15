from pathlib import Path
import json
import shutil

from agent.crypto.key_manager import (
    KeyManager,
    generate_storage_key,
)


ROOT = Path(
    "state/test_p11_key_manager"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

storage_key = (
    generate_storage_key()
)


# ============================================================
# P11.5-01 INITIAL KEY
# ============================================================

print(
    "=== P11.5-01 INITIAL KEY ==="
)

manager1 = KeyManager(
    ROOT,
    storage_key,
)

key1 = manager1.generate_key()

print(
    "KEY1_CREATED=",
    key1 is not None,
)

print(
    "KEY1_ID=",
    key1,
)

print(
    "ACTIVE_KEY_ID=",
    manager1.active_key_id(),
)

print(
    "KEY1_METADATA=",
    manager1.get_key_metadata(
        key1
    ),
)

print(
    "HEALTH=",
    manager1.health_check(),
)


# ============================================================
# P11.5-02 SIGN / VERIFY
# ============================================================

print()
print(
    "=== P11.5-02 SIGN VERIFY ==="
)

payload = (
    b"CyberDefender P11.5 test payload"
)

mac1 = manager1.sign(
    payload
)

print(
    "MAC_PRESENT=",
    bool(mac1),
)

print(
    "VERIFY_VALID=",
    manager1.verify(
        payload,
        mac1,
        key1,
    ),
)

print(
    "VERIFY_TAMPER=",
    manager1.verify(
        b"TAMPERED",
        mac1,
        key1,
    ),
)


# ============================================================
# P11.5-03 RESTART
# ============================================================

print()
print(
    "=== P11.5-03 RESTART ==="
)

manager2 = KeyManager(
    ROOT,
    storage_key,
)

print(
    "RECOVERED_ACTIVE=",
    manager2.active_key_id()
    == key1,
)

print(
    "RECOVERED_METADATA=",
    manager2.get_key_metadata(
        key1
    ),
)

print(
    "RECOVERED_VERIFY=",
    manager2.verify(
        payload,
        mac1,
        key1,
    ),
)


# ============================================================
# P11.5-04 ROTATION
# ============================================================

print()
print(
    "=== P11.5-04 ROTATION ==="
)

key2 = manager2.rotate()

print(
    "KEY2_CREATED=",
    key2 is not None,
)

print(
    "KEY2_ID=",
    key2,
)

print(
    "ACTIVE_AFTER_ROTATION=",
    manager2.active_key_id(),
)

print(
    "KEY1_AFTER_ROTATION=",
    manager2.get_key_metadata(
        key1
    ),
)

print(
    "KEY2_AFTER_ROTATION=",
    manager2.get_key_metadata(
        key2
    ),
)


# ============================================================
# P11.5-05 OLD KEY REJECTION
# ============================================================

print()
print(
    "=== P11.5-05 OLD KEY REJECTION ==="
)

print(
    "OLD_KEY_VERIFY=",
    manager2.verify(
        payload,
        mac1,
        key1,
    ),
)

mac2 = manager2.sign(
    payload
)

print(
    "NEW_MAC_PRESENT=",
    bool(mac2),
)

print(
    "NEW_KEY_VERIFY=",
    manager2.verify(
        payload,
        mac2,
        key2,
    ),
)


# ============================================================
# P11.5-06 WRONG KEY ID
# ============================================================

print()
print(
    "=== P11.5-06 WRONG KEY ID ==="
)

print(
    "WRONG_KEY_VERIFY=",
    manager2.verify(
        payload,
        mac2,
        "key-does-not-exist",
    ),
)


# ============================================================
# P11.5-07 REVOCATION
# ============================================================

print()
print(
    "=== P11.5-07 REVOCATION ==="
)

revoke_result = manager2.revoke(
    key2
)

print(
    "REVOKE_RESULT=",
    revoke_result,
)

print(
    "REVOKED_METADATA=",
    manager2.get_key_metadata(
        key2
    ),
)

print(
    "ACTIVE_AFTER_REVOKE=",
    manager2.active_key_id(),
)

print(
    "REVOKED_KEY_VERIFY=",
    manager2.verify(
        payload,
        mac2,
        key2,
    ),
)

print(
    "SIGN_AFTER_REVOKE=",
    manager2.sign(
        payload
    ),
)


# ============================================================
# P11.5-08 DEGRADED STATE
# ============================================================

print()
print(
    "=== P11.5-08 STATE TAMPER ==="
)

state_path = (
    ROOT
    / "key_state.json"
)

data = json.loads(
    state_path.read_text(
        encoding="utf-8"
    )
)

data["active_key_id"] = (
    "attacker-key"
)

state_path.write_text(
    json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)

manager3 = KeyManager(
    ROOT,
    storage_key,
)

print(
    "TAMPER_READY=",
    manager3.is_ready(),
)

print(
    "TAMPER_HEALTH=",
    manager3.health_check(),
)

print(
    "TAMPER_SIGN=",
    manager3.sign(
        payload
    ),
)

print(
    "TAMPER_VERIFY=",
    manager3.verify(
        payload,
        mac2,
        key2,
    ),
)


# ============================================================
# P11.5-09 WRONG STORAGE KEY
# ============================================================

print()
print(
    "=== P11.5-09 WRONG STORAGE KEY ==="
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

manager4 = KeyManager(
    ROOT,
    storage_key,
)

fresh_key = manager4.generate_key()

fresh_mac = manager4.sign(
    payload
)

wrong_storage_key = (
    generate_storage_key()
)

manager5 = KeyManager(
    ROOT,
    wrong_storage_key,
)

print(
    "WRONG_STORAGE_READY=",
    manager5.is_ready(),
)

print(
    "WRONG_STORAGE_HEALTH=",
    manager5.health_check(),
)

print(
    "WRONG_STORAGE_SIGN=",
    manager5.sign(
        payload
    ),
)

print(
    "WRONG_STORAGE_VERIFY=",
    manager5.verify(
        payload,
        fresh_mac,
        fresh_key,
    ),
)


# ============================================================
# P11.5-10 FINAL STATS
# ============================================================

print()
print(
    "=== P11.5-10 FINAL STATS ==="
)

print(
    manager2.get_stats()
)

print(
    "TEST_COMPLETE=True"
)
