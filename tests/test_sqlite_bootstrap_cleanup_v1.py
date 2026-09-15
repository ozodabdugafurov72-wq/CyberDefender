from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

from agent.config import load_config
from agent.data.sqlite_repository import SQLiteDataRepository
from agent.main import CyberDefenderRuntime, RuntimeBootstrapError
from agent.safety import SafetyCore


def main() -> int:
    failures = 0

    def check(ok: bool, label: str) -> None:
        nonlocal failures
        print(("PASS" if ok else "FAIL") + " | " + label)
        failures += 0 if ok else 1

    with tempfile.TemporaryDirectory(prefix="cd_sqlite_bootstrap_cleanup_") as td:
        root = Path(td)
        old_state = os.environ.get("CYBERDEFENDER_STATE_DIR")
        old_key = os.environ.get("CYBERDEFENDER_STORAGE_KEY_B64")
        storage_key = os.urandom(32)
        os.environ["CYBERDEFENDER_STATE_DIR"] = str(root)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(storage_key).decode("ascii")

        try:
            runtime = CyberDefenderRuntime(SafetyCore(), load_config())
            active = runtime.key_manager.active_key_id() if runtime.key_manager else None
            check(bool(active), "Fresh runtime has ACTIVE signing key")
            if runtime.key_manager and active:
                check(runtime.key_manager.revoke(active) is True, "ACTIVE signing key can be revoked for fail-closed probe")
            runtime.close()

            closed_paths: list[Path] = []
            original_close = SQLiteDataRepository.close

            def tracked_close(self: SQLiteDataRepository) -> None:
                closed_paths.append(self.db_path)
                original_close(self)

            SQLiteDataRepository.close = tracked_close
            try:
                try:
                    CyberDefenderRuntime(SafetyCore(), load_config())
                except RuntimeBootstrapError:
                    failed_closed = True
                else:
                    failed_closed = False
            finally:
                SQLiteDataRepository.close = original_close

            check(failed_closed, "Persisted revoked-key bootstrap remains fail-closed")
            expected_db = (root / "data" / "cyberdefender.db").resolve()
            check(expected_db in closed_paths, "Failed bootstrap deterministically closes SQLite handle")

            # A new direct repository handle must open/close cleanly after the
            # failed runtime bootstrap.  On Windows this also exercises the
            # same database path that would otherwise remain locked.
            probe = SQLiteDataRepository(expected_db)
            probe.close()
            check(True, "SQLite database can be reopened after failed bootstrap cleanup")
        finally:
            if old_state is None:
                os.environ.pop("CYBERDEFENDER_STATE_DIR", None)
            else:
                os.environ["CYBERDEFENDER_STATE_DIR"] = old_state
            if old_key is None:
                os.environ.pop("CYBERDEFENDER_STORAGE_KEY_B64", None)
            else:
                os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = old_key

    print(f"RESULT: {'PASS' if failures == 0 else 'FAIL'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
