from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path.cwd().resolve()
STATE_ROOT = PROJECT_ROOT / "state"
KEY_ROOT = STATE_ROOT / "keys"
ENV_NAME = "CYBERDEFENDER_STORAGE_KEY_B64"


def fail(message: str) -> None:
    print(f"[FAIL] {message}")
    raise SystemExit(2)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def active_agent_processes() -> list[str]:
    try:
        import psutil
    except Exception as exc:
        fail(f"psutil is required for the process-safety gate: {type(exc).__name__}")

    matches: list[str] = []
    current_pid = os.getpid()

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if proc.info["pid"] == current_pid:
                continue
            cmdline = proc.info.get("cmdline") or []
            command = " ".join(str(part) for part in cmdline)
            normalized = [str(part).strip() for part in cmdline]
            is_module_launch = any(
                part == "agent.main" for part in normalized
            ) and any(
                part == "-m" for part in normalized
            )
            if is_module_launch:
                matches.append(
                    f"PID={proc.info['pid']} NAME={proc.info.get('name')} CMD={command}"
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return matches


def load_storage_key() -> bytes:
    encoded = os.getenv(ENV_NAME)
    if not encoded:
        fail(f"{ENV_NAME} is missing.")
    try:
        key = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        fail(f"{ENV_NAME} is invalid Base64: {type(exc).__name__}")
    if len(key) < 32:
        fail(f"Storage key is too short: {len(key)} bytes; minimum is 32 bytes.")
    return key


def verify_persisted_state(storage_key: bytes) -> dict:
    state_path = KEY_ROOT / "key_state.json"
    mac_path = KEY_ROOT / "key_state.mac"

    if state_path.exists() != mac_path.exists():
        fail("key_state.json and key_state.mac are not in a consistent presence state.")

    if not state_path.exists():
        return {"exists": False, "status": "FRESH_EMPTY_STATE"}

    raw = state_path.read_bytes()
    stored_mac = mac_path.read_text(encoding="ascii").strip()
    expected_mac = __import__("hmac").new(storage_key, raw, hashlib.sha256).hexdigest()

    authenticated = __import__("hmac").compare_digest(stored_mac, expected_mac)
    if authenticated:
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            fail(f"Authenticated key_state.json is invalid JSON: {type(exc).__name__}")
        if not isinstance(data, dict):
            fail("Authenticated key_state.json root is not an object.")
        return {
            "exists": True,
            "status": "AUTHENTICATED",
            "state_sha256": sha256_file(state_path),
            "mac_sha256": sha256_file(mac_path),
            "state_version": data.get("state_version"),
            "active_key_id": data.get("active_key_id"),
            "key_count": len(data.get("keys", {})) if isinstance(data.get("keys"), dict) else None,
        }

    return {
        "exists": True,
        "status": "MAC_MISMATCH",
        "state_sha256": sha256_file(state_path),
        "mac_sha256": sha256_file(mac_path),
    }


def backup_and_quarantine() -> Path:
    KEY_ROOT.mkdir(parents=True, exist_ok=True)
    state_path = KEY_ROOT / "key_state.json"
    mac_path = KEY_ROOT / "key_state.mac"

    existing = [p for p in (state_path, mac_path) if p.exists()]
    if not existing:
        return KEY_ROOT / f"recovery_{utc_stamp()}"

    backup_root = KEY_ROOT / f"recovery_{utc_stamp()}"
    backup_root.mkdir(parents=False, exist_ok=False)

    manifest: dict[str, object] = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "reason": "controlled KeyManager re-enrollment after storage-key MAC mismatch",
        "source_directory": str(KEY_ROOT),
        "files": [],
    }

    file_entries: list[dict[str, object]] = []
    for source in existing:
        destination = backup_root / source.name
        shutil.copy2(source, destination)
        file_entries.append(
            {
                "name": source.name,
                "size": source.stat().st_size,
                "sha256": sha256_file(destination),
            }
        )
    manifest["files"] = file_entries

    manifest_path = backup_root / "MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Verify backup before changing the live path.
    for entry in file_entries:
        copied = backup_root / str(entry["name"])
        if copied.stat().st_size != int(entry["size"]):
            fail(f"Backup size verification failed for {copied.name}.")
        if sha256_file(copied) != entry["sha256"]:
            fail(f"Backup SHA-256 verification failed for {copied.name}.")

    # Quarantine originals only after backup verification succeeds.
    for source in existing:
        target = backup_root / f"quarantined_{source.name}"
        os.replace(source, target)

    # Verify live path is now clean.
    if state_path.exists() or mac_path.exists():
        fail("Live key state was not fully quarantined.")

    return backup_root


def main() -> int:
    print("CYBERDEFENDER — KEYMANAGER CONTROLLED RE-ENROLLMENT v1")
    print()
    print("01. PROCESS SAFETY GATE")
    matches = active_agent_processes()
    if matches:
        print("[FAIL] Running agent.main process detected. Runtime must be stopped first.")
        for item in matches:
            print(f"        {item}")
        return 3
    print("[PASS] No concurrent agent.main process detected")

    print()
    print("02. STORAGE KEY CONTRACT")
    storage_key = load_storage_key()
    print(f"[PASS] {ENV_NAME} present; decoded length={len(storage_key)} bytes")

    print()
    print("03. CURRENT KEY STATE")
    before = verify_persisted_state(storage_key)
    print(json.dumps(before, indent=2, ensure_ascii=False))
    if before["status"] == "AUTHENTICATED":
        fail("Current storage key already authenticates the persisted state. Re-enrollment is unnecessary.")

    print()
    print("04. BACKUP + QUARANTINE")
    backup_root = backup_and_quarantine()
    print(f"[PASS] Original key state preserved in: {backup_root}")

    print()
    print("05. FRESH KEYMANAGER INITIALIZATION")
    sys.path.insert(0, str(PROJECT_ROOT))
    from agent.crypto.key_manager import KeyManager

    manager = KeyManager(KEY_ROOT, storage_key)
    if not getattr(manager, "is_unprovisioned", lambda: False)():
        fail("Fresh KeyManager is not UNPROVISIONED after controlled quarantine.")
    if manager.active_key_id() is not None:
        fail("Fresh KeyManager unexpectedly has an active key before generation.")

    key_id = manager.generate_key()
    if not key_id:
        fail("KeyManager.generate_key() failed.")
    if not manager.is_ready():
        fail("KeyManager did not become READY after key generation.")
    print(f"[PASS] New ACTIVE key generated: {key_id}")

    print()
    print("06. PERSISTENCE + RELOAD VERIFICATION")
    manager2 = KeyManager(KEY_ROOT, storage_key)
    if not manager2.is_ready():
        fail("Reloaded KeyManager is not READY.")
    if manager2.active_key_id() != key_id:
        fail("Reloaded active key ID does not match the newly generated key.")

    health = manager2.health_check()
    if health.get("status") != "HEALTHY":
        fail(f"Reloaded KeyManager health is not HEALTHY: {health}")
    if health.get("active_key") is not True:
        fail(f"Reloaded KeyManager does not report an active key: {health}")

    metadata = manager2.get_key_metadata(key_id)
    if not metadata or metadata.get("status") != KeyManager.ACTIVE:
        fail(f"New key metadata is not ACTIVE: {metadata}")

    payload = b"CyberDefender KeyManager controlled re-enrollment verification"
    mac = manager2.sign(payload)
    if not mac:
        fail("KeyManager.sign() returned no MAC.")
    if not manager2.verify(payload, mac, key_id):
        fail("Fresh sign/verify verification failed.")
    if manager2.verify(b"TAMPERED", mac, key_id):
        fail("Tampered payload was incorrectly accepted.")

    print("[PASS] Reloaded KeyManager is HEALTHY")
    print("[PASS] Active key persisted across reload")
    print("[PASS] Sign/verify integrity check")
    print("[PASS] Tampered payload rejected")

    print()
    print("07. FINAL STATE")
    final_state = verify_persisted_state(storage_key)
    print(json.dumps(final_state, indent=2, ensure_ascii=False))
    if final_state["status"] != "AUTHENTICATED":
        fail("Final persisted key state is not authenticated by the current storage key.")
    if final_state.get("active_key_id") != key_id:
        fail("Final persisted active key does not match the generated key.")

    print()
    print("RESULT: PASS — KeyManager re-enrollment completed safely.")
    print(f"Backup preserved at: {backup_root}")
    print("Next: run the existing bootstrap diagnostic, then start the runtime.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
