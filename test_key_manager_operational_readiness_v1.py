from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path

from agent.config import load_config
from agent.crypto.key_manager import KeyManager, generate_storage_key
from agent.main import CyberDefenderRuntime, RuntimeBootstrapError
from agent.safety import SafetyCore


RESULTS: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    RESULTS.append((label, condition))
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)


def main() -> int:
    print("CYBERDEFENDER — KEYMANAGER OPERATIONAL READINESS v1")
    print("=" * 76)

    with tempfile.TemporaryDirectory(prefix="cyberdefender_keyreadiness_") as temp_dir:
        root = Path(temp_dir)
        key_root = root / "keys"
        storage_key = generate_storage_key()

        fresh = KeyManager(key_root, storage_key)
        check("Fresh state is not operationally READY", fresh.is_ready() is False)
        check("Fresh state is explicitly UNPROVISIONED", fresh.is_unprovisioned() is True)
        check("Fresh health is UNPROVISIONED", fresh.health_check()["status"] == "UNPROVISIONED")
        check("Fresh state has no active key", fresh.active_key_id() is None)
        check("Fresh state cannot sign", fresh.sign(b"fresh") is None)

        first_key = fresh.generate_key()
        check("Initial provisioning creates a key", isinstance(first_key, str) and bool(first_key))
        check("Provisioned state becomes READY", fresh.is_ready() is True)
        check("Provisioned state leaves UNPROVISIONED", fresh.is_unprovisioned() is False)
        check("Provisioned health becomes HEALTHY", fresh.health_check()["status"] == "HEALTHY")

        reloaded = KeyManager(key_root, storage_key)
        check("Reloaded state remains READY", reloaded.is_ready() is True)
        check("Reloaded active key is preserved", reloaded.active_key_id() == first_key)

        payload = b"CyberDefender operational readiness"
        mac = reloaded.sign(payload)
        check("READY KeyManager signs", isinstance(mac, str) and bool(mac))
        check("READY KeyManager verifies", reloaded.verify(payload, mac or "", first_key or "") is True)

        check("Active key revocation succeeds", reloaded.revoke(first_key or "") is True)
        check("Revoked active key removes READY", reloaded.is_ready() is False)
        check("Revoked active key becomes UNPROVISIONED", reloaded.is_unprovisioned() is True)
        check("UNPROVISIONED state cannot sign", reloaded.sign(payload) is None)

        replacement_key = reloaded.generate_key()
        check("Controlled reprovisioning creates replacement key", bool(replacement_key))
        check("Replacement key restores READY", reloaded.is_ready() is True)

        # Tamper with authenticated state without updating MAC.
        state_path = key_root / "key_state.json"
        data = json.loads(state_path.read_text(encoding="utf-8"))
        data["active_key_id"] = "attacker-key"
        state_path.write_text(
            json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        tampered = KeyManager(key_root, storage_key)
        check("Tampered state is DEGRADED", tampered.is_degraded() is True)
        check("Tampered state is not UNPROVISIONED", tampered.is_unprovisioned() is False)
        check("Tampered state cannot provision a key", tampered.generate_key() is None)
        check("Tampered health is DEGRADED", tampered.health_check()["status"] == "DEGRADED")

    # Authenticated-but-incoherent state must also fail closed.  This tests
    # semantic integrity beyond the outer state MAC.
    with tempfile.TemporaryDirectory(prefix="cyberdefender_keysemantic_") as temp_dir:
        key_root = Path(temp_dir) / "keys"
        storage_key = generate_storage_key()
        manager = KeyManager(key_root, storage_key)
        key_id = manager.generate_key()
        check("Semantic test key provisioned", bool(key_id))

        state_path = key_root / "key_state.json"
        mac_path = key_root / "key_state.mac"
        data = json.loads(state_path.read_text(encoding="utf-8"))
        data["active_key_id"] = None
        raw = (
            json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        state_path.write_bytes(raw)
        mac_path.write_text(
            hmac.new(storage_key, raw, hashlib.sha256).hexdigest() + "\n",
            encoding="ascii",
        )

        incoherent = KeyManager(key_root, storage_key)
        check("Authenticated orphan ACTIVE key is DEGRADED", incoherent.is_degraded() is True)
        check("Authenticated semantic corruption cannot sign", incoherent.sign(b"x") is None)

    # Main bootstrap contract: a truly fresh installation may perform one
    # controlled initial key bootstrap because the operator has already
    # supplied the storage key.  Previously provisioned state with no ACTIVE
    # key (for example after revocation) must remain fail-closed.
    with tempfile.TemporaryDirectory(prefix="cyberdefender_main_keyreadiness_") as state_dir:
        storage_key = generate_storage_key()
        old_state_dir = os.environ.get("CYBERDEFENDER_STATE_DIR")
        old_storage_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
        try:
            os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
            os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(storage_key).decode("ascii")

            config = load_config()
            runtime = CyberDefenderRuntime(SafetyCore(), config)
            check("Fresh main bootstrap creates ACTIVE key", runtime.key_manager is not None and runtime.key_manager.is_ready())
            check("Fresh main KeyManager health is HEALTHY", runtime.key_manager.health_check()["status"] == "HEALTHY")

            active = runtime.key_manager.active_key_id()
            check("Fresh main bootstrap persisted an active key", isinstance(active, str) and bool(active))
            check("Revoking runtime active key succeeds", runtime.key_manager.revoke(active or "") is True)
            check("Revoked runtime key state is UNPROVISIONED", runtime.key_manager.is_unprovisioned() is True)
            runtime.close()

            try:
                CyberDefenderRuntime(SafetyCore(), config)
            except RuntimeBootstrapError as exc:
                check("Main fails closed after persisted active-key revocation", "ACTIVE key" in str(exc))
            else:
                raise AssertionError("Main silently re-keyed a revoked KeyManager state")
        finally:
            if old_state_dir is None:
                os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
            else:
                os.environ["CYBERDEFENDER_STATE_DIR"] = old_state_dir
            if old_storage_key is None:
                os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
            else:
                os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_storage_key

    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
