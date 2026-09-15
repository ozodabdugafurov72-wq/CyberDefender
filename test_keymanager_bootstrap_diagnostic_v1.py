from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path.cwd()
STATE_ROOT = PROJECT_ROOT / "state"
KEY_ROOT = STATE_ROOT / "keys"
STATE_PATH = KEY_ROOT / "key_state.json"
MAC_PATH = KEY_ROOT / "key_state.mac"
ENV_NAME = "CYBERDEFENDER_STORAGE_KEY_B64"


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise SystemExit(2)


def main() -> int:
    print("CYBERDEFENDER — KEYMANAGER BOOTSTRAP ROOT-CAUSE DIAGNOSTIC v1")
    print()

    sys.path.insert(0, str(PROJECT_ROOT))
    from agent.crypto.key_manager import KeyManager

    print("01. PATH / FILE STATE")
    print(f"[INFO] Project root: {PROJECT_ROOT}")
    print(f"[INFO] Key directory: {KEY_ROOT}")
    print(f"[INFO] key_state.json exists: {STATE_PATH.exists()}")
    print(f"[INFO] key_state.mac exists: {MAC_PATH.exists()}")

    if STATE_PATH.exists():
        print(f"[INFO] key_state.json size: {STATE_PATH.stat().st_size} bytes")
    if MAC_PATH.exists():
        print(f"[INFO] key_state.mac size: {MAC_PATH.stat().st_size} bytes")

    print()
    print("02. STORAGE KEY ENVIRONMENT CONTRACT")
    encoded = os.getenv(ENV_NAME)
    if not encoded:
        fail(f"{ENV_NAME} is missing. Main should fail earlier with the storage-key bootstrap error.")

    try:
        storage_key = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        fail(f"{ENV_NAME} is not valid Base64: {type(exc).__name__}")

    print(f"[PASS] {ENV_NAME} present; decoded length={len(storage_key)} bytes (secret value not printed)")
    if len(storage_key) < 32:
        fail(f"Decoded storage key is too short: {len(storage_key)} bytes; minimum is 32 bytes.")
    print("[PASS] Storage key length contract satisfied")

    print()
    print("03. KEYMANAGER LOAD RESULT")
    km = KeyManager(KEY_ROOT, storage_key)
    stats = km.get_stats()
    print(json.dumps(stats, indent=2, ensure_ascii=False))

    if not km.is_ready():
        print("[FAIL] KeyManager is DEGRADED")
    else:
        print("[PASS] KeyManager is READY")

    print()
    print("04. PERSISTED INTEGRITY CHECK (READ-ONLY)")
    if not STATE_PATH.exists() and not MAC_PATH.exists():
        print("[INFO] No key state exists. This is a fresh KeyManager state with no active key.")
        return 3
    if STATE_PATH.exists() != MAC_PATH.exists():
        print("[FAIL] key_state.json and key_state.mac are not both present.")
        return 4

    raw = STATE_PATH.read_bytes()
    stored_mac = MAC_PATH.read_text(encoding="ascii").strip()
    expected_mac = hmac.new(storage_key, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        print("[FAIL] key_state MAC mismatch: supplied storage key does not authenticate the persisted key state.")
        print("[ROOT CAUSE CANDIDATE] Storage-key mismatch / changed secret / stale state directory.")
        return 5
    print("[PASS] key_state MAC matches current storage key")

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        print(f"[FAIL] key_state.json is not valid JSON: {type(exc).__name__}")
        return 6

    if not isinstance(data, dict):
        print("[FAIL] key_state.json root is not an object")
        return 7

    active = data.get("active_key_id")
    keys = data.get("keys")
    version = data.get("state_version")
    print(f"[INFO] state_version={version}")
    print(f"[INFO] key_count={len(keys) if isinstance(keys, dict) else 'invalid'}")
    print(f"[INFO] active_key_id_present={active is not None}")

    if version != KeyManager.STATE_VERSION:
        print("[FAIL] Unsupported key-state version")
        return 8
    if not isinstance(keys, dict):
        print("[FAIL] Persisted keys field is invalid")
        return 9
    if active is None:
        print("[FAIL] Persisted state has no active key")
        print("[ROOT CAUSE CANDIDATE] KeyManager can be READY with zero active key; runtime bootstrap currently accepts readiness but later admission cannot sign events.")
        return 10
    metadata = keys.get(active)
    if not isinstance(metadata, dict) or metadata.get("status") != KeyManager.ACTIVE:
        print("[FAIL] active_key_id does not point to an ACTIVE key")
        return 11

    print("[PASS] Persisted key state has a valid active key")
    print()
    print("RESULT: PASS — storage key authenticates persisted KeyManager state and an ACTIVE key is present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
