from pathlib import Path
import json
import shutil

from agent.crypto.key_manager import (
    KeyManager,
    generate_storage_key,
)

from agent.crypto.key_rotation_recovery import (
    KeyRotationRecovery,
)


ROOT = Path(
    "state/test_p11_key_rotation_recovery"
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

storage_key = (
    generate_storage_key()
)


# ============================================================
# P11.6-01 NORMAL INITIAL STATE
# ============================================================

print(
    "=== P11.6-01 NORMAL INITIAL STATE ==="
)

manager = KeyManager(
    ROOT,
    storage_key,
)

key1 = manager.generate_key()

checker = KeyRotationRecovery(
    ROOT,
    storage_key,
)

print(
    "KEY_CREATED=",
    key1 is not None,
)

print(
    "VALID=",
    checker.recover_and_validate(),
)

print(
    "HEALTH=",
    checker.health_check(),
)


# ============================================================
# P11.6-02 NORMAL ROTATION
# ============================================================

print()
print(
    "=== P11.6-02 NORMAL ROTATION ==="
)

key2 = manager.rotate()

checker2 = KeyRotationRecovery(
    ROOT,
    storage_key,
)

print(
    "ROTATION_CREATED=",
    key2 is not None,
)

print(
    "KEY1_STATUS=",
    manager.get_key_metadata(
        key1
    ),
)

print(
    "KEY2_STATUS=",
    manager.get_key_metadata(
        key2
    ),
)

print(
    "VALID_AFTER_ROTATION=",
    checker2.recover_and_validate(),
)


# ============================================================
# P11.6-03 RESTART AFTER ROTATION
# ============================================================

print()
print(
    "=== P11.6-03 RESTART AFTER ROTATION ==="
)

manager_restart = KeyManager(
    ROOT,
    storage_key,
)

checker_restart = (
    KeyRotationRecovery(
        ROOT,
        storage_key,
    )
)

print(
    "ACTIVE_RECOVERED=",
    manager_restart.active_key_id()
    == key2,
)

print(
    "VALID_AFTER_RESTART=",
    checker_restart.recover_and_validate(),
)


# ============================================================
# P11.6-04 TWO ACTIVE KEYS
# ============================================================

print()
print(
    "=== P11.6-04 TWO ACTIVE KEYS ==="
)

state_path = (
    ROOT
    / "key_state.json"
)

mac_path = (
    ROOT
    / "key_state.mac"
)

data = json.loads(
    state_path.read_text(
        encoding="utf-8"
    )
)

data["keys"][
    key1
]["status"] = "ACTIVE"

data["active_key_id"] = key2

raw = (
    json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("utf-8")

state_path.write_bytes(
    raw
)

import hashlib
import hmac

mac = hmac.new(
    storage_key,
    raw,
    hashlib.sha256,
).hexdigest()

mac_path.write_text(
    mac + "\n",
    encoding="ascii",
)

checker_two_active = (
    KeyRotationRecovery(
        ROOT,
        storage_key,
    )
)

print(
    "TWO_ACTIVE_VALID=",
    checker_two_active.recover_and_validate(),
)

print(
    "TWO_ACTIVE_HEALTH=",
    checker_two_active.health_check(),
)


# ============================================================
# P11.6-05 ACTIVE POINTER MISMATCH
# ============================================================

print()
print(
    "=== P11.6-05 ACTIVE POINTER MISMATCH ==="
)

# Restore a structurally invalid but authenticated state:
# one ACTIVE key exists, but active_key_id points elsewhere.

data = json.loads(
    state_path.read_text(
        encoding="utf-8"
    )
)

data["keys"][
    key1
]["status"] = "RETIRED"

data["keys"][
    key2
]["status"] = "ACTIVE"

data["active_key_id"] = (
    "non-existent-key"
)

raw = (
    json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("utf-8")

state_path.write_bytes(
    raw
)

mac = hmac.new(
    storage_key,
    raw,
    hashlib.sha256,
).hexdigest()

mac_path.write_text(
    mac + "\n",
    encoding="ascii",
)

checker_pointer = (
    KeyRotationRecovery(
        ROOT,
        storage_key,
    )
)

print(
    "POINTER_VALID=",
    checker_pointer.recover_and_validate(),
)

print(
    "POINTER_HEALTH=",
    checker_pointer.health_check(),
)


# ============================================================
# P11.6-06 MISSING MAC
# ============================================================

print()
print(
    "=== P11.6-06 MISSING MAC ==="
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

manager_clean = KeyManager(
    ROOT,
    storage_key,
)

manager_clean.generate_key()

mac_path = (
    ROOT
    / "key_state.mac"
)

mac_path.unlink()

checker_missing_mac = (
    KeyRotationRecovery(
        ROOT,
        storage_key,
    )
)

print(
    "MISSING_MAC_VALID=",
    checker_missing_mac.recover_and_validate(),
)

print(
    "MISSING_MAC_HEALTH=",
    checker_missing_mac.health_check(),
)


# ============================================================
# P11.6-07 CORRUPTED STATE
# ============================================================

print()
print(
    "=== P11.6-07 CORRUPTED STATE ==="
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

manager_corrupt = KeyManager(
    ROOT,
    storage_key,
)

manager_corrupt.generate_key()

state_path = (
    ROOT
    / "key_state.json"
)

state_path.write_text(
    "{CORRUPTED STATE",
    encoding="utf-8",
)

checker_corrupt = (
    KeyRotationRecovery(
        ROOT,
        storage_key,
    )
)

print(
    "CORRUPTED_VALID=",
    checker_corrupt.recover_and_validate(),
)

print(
    "CORRUPTED_HEALTH=",
    checker_corrupt.health_check(),
)


# ============================================================
# P11.6-08 WRONG STORAGE KEY
# ============================================================

print()
print(
    "=== P11.6-08 WRONG STORAGE KEY ==="
)

shutil.rmtree(
    ROOT,
    ignore_errors=True,
)

manager_wrong = KeyManager(
    ROOT,
    storage_key,
)

manager_wrong.generate_key()

wrong_key = (
    generate_storage_key()
)

checker_wrong = (
    KeyRotationRecovery(
        ROOT,
        wrong_key,
    )
)

print(
    "WRONG_KEY_VALID=",
    checker_wrong.recover_and_validate(),
)

print(
    "WRONG_KEY_HEALTH=",
    checker_wrong.health_check(),
)


# ============================================================
# P11.6-09 FINAL
# ============================================================

print()
print(
    "=== P11.6-09 FINAL ==="
)

print(
    "TEST_COMPLETE=True"
)
