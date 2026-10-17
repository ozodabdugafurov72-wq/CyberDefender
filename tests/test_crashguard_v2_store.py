from __future__ import annotations

import copy
import errno
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from agent.crashguard_v2 import diagnostics
from agent.crashguard_v2.failure_codes import (
    DIAGNOSTIC_FAILURE_CODES,
    FAILURE_CODES,
    GUARD_FAILURE_CODES,
    INSTALLER_FAILURE_CODES,
    STORE_FAILURE_CODES,
)
from agent.crashguard_v2.store import (
    MAX_RECORD_BYTES,
    StoreV2,
    StoreV2Error,
    _atomic_write,
    _strict_json,
    fresh_record,
    read_status_snapshot,
)
from agent.crashguard_v2 import store as store_module


ALLOW = lambda _path: None
KEY = b"K" * 32


class CrashGuardV2StoreTests(unittest.TestCase):
    def roots(self, root: Path) -> tuple[Path, Path]:
        state = root / "state"
        anchor = root / "anchor-outside-state"
        state.mkdir()
        anchor.mkdir()
        return state, anchor

    def record(self) -> dict:
        return fresh_record("CyberDefenderAgent", boot_id="boot-a", monotonic_ns=100, wall_time_ns=1_000_000_000_000)

    def test_valid_dual_slot_commit_and_lock_free_authenticated_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-store-valid-") as raw:
            state, anchor = self.roots(Path(raw))
            with StoreV2(state, anchor, "CyberDefenderAgent", KEY, path_validator=ALLOW) as store:
                current = store.provision(self.record())
                current["generation"] = 1
                current["lifecycle"] = "READY"
                current["monotonic_ns"] = 200
                current["wall_time_ns"] = 2_000_000_000_000
                committed = store.write(current)
                status = read_status_snapshot(store.status_path, KEY)
                self.assertEqual(committed["revision"], status["revision"])
                self.assertEqual("READY", status["lifecycle"])
                self.assertNotIn("boot_id", status)
                self.assertNotIn("consumed_nonces", status)
                self.assertTrue(store.slot_paths[0].exists() and store.slot_paths[1].exists())
                with self.assertRaisesRegex(StoreV2Error, "LOCKED_BY_OWNER"):
                    StoreV2(state, anchor, "CyberDefenderAgent", KEY, path_validator=ALLOW)

    def test_tamper_wrong_key_and_older_slot_rollback_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-store-tamper-") as raw:
            state, anchor = self.roots(Path(raw))
            with StoreV2(state, anchor, "CyberDefenderAgent", KEY, path_validator=ALLOW) as store:
                current = store.provision(self.record())
                current["monotonic_ns"] = 200
                current["wall_time_ns"] = 2_000_000_000_000
                store.write(current)
                with self.assertRaisesRegex(StoreV2Error, "CRASH_STORE_AUTH_FAILED"):
                    read_status_snapshot(store.status_path, b"W" * 32)
                latest = store.slot_paths[1]
                original = latest.read_bytes()
                latest.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                with self.assertRaisesRegex(StoreV2Error, "CRASH_STORE_AUTH_FAILED|SCHEMA_INVALID"):
                    store.load()
                latest.write_bytes(store.slot_paths[0].read_bytes())
                with self.assertRaisesRegex(StoreV2Error, "ROLLBACK_SUSPECTED"):
                    store.load()

    def test_torn_anchor_disk_full_schema_oversize_and_clock_rollback_reject(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-store-failures-") as raw:
            state, anchor = self.roots(Path(raw))
            with StoreV2(state, anchor, "CyberDefenderAgent", KEY, path_validator=ALLOW) as store:
                current = store.provision(self.record())
                before = store.anchor_path.read_bytes()
                candidate = copy.deepcopy(current)
                candidate["failure_history"] = [{"generation": 0, "code": "UNKNOWN"}]
                with self.assertRaisesRegex(StoreV2Error, "SCHEMA_INVALID"):
                    store.write(candidate)
                candidate = copy.deepcopy(current)
                candidate["generation"] = -1
                with self.assertRaisesRegex(StoreV2Error, "SCHEMA_INVALID"):
                    store.write(candidate)
                candidate = copy.deepcopy(current)
                candidate["consumed_nonces"] = ["x" * MAX_RECORD_BYTES]
                with self.assertRaisesRegex(StoreV2Error, "SCHEMA_INVALID|CRASH_STORE_OVERSIZE"):
                    store.write(candidate)
                with self.assertRaisesRegex(StoreV2Error, "CRASH_STORE_OVERSIZE"):
                    _strict_json(b"x" * (MAX_RECORD_BYTES + 1), MAX_RECORD_BYTES)
                candidate = copy.deepcopy(current)
                candidate["monotonic_ns"] = 99
                with self.assertRaisesRegex(StoreV2Error, "ROLLBACK_SUSPECTED"):
                    store.write(candidate)
                candidate = copy.deepcopy(current)
                candidate["wall_time_ns"] = 0
                with self.assertRaisesRegex(StoreV2Error, "ROLLBACK_SUSPECTED"):
                    store.write(candidate)
                with mock.patch.object(store_module, "_move_replace", side_effect=OSError(errno.ENOSPC, "disk full")):
                    candidate = copy.deepcopy(current)
                    candidate["monotonic_ns"] = 200
                    candidate["wall_time_ns"] = 2_000_000_000_000
                    with self.assertRaisesRegex(StoreV2Error, "CRASH_STORE_DISK_FULL"):
                        store.write(candidate)
                self.assertEqual(before, store.anchor_path.read_bytes())
                store.anchor_path.write_bytes(b'{"payload":')
                with self.assertRaisesRegex(StoreV2Error, "SCHEMA_INVALID"):
                    store.load()

    def test_bounded_sharing_retry_and_acl_failure_are_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-store-retry-") as raw:
            root = Path(raw)
            target = root / "record"
            real_move = store_module._move_replace
            attempts = 0

            def sharing_twice(source, destination):
                nonlocal attempts
                attempts += 1
                if attempts < 3:
                    raise PermissionError("simulated sharing violation")
                return real_move(source, destination)

            with mock.patch.object(store_module, "_move_replace", side_effect=sharing_twice):
                _atomic_write(target, b"bounded", maximum=32)
            self.assertEqual(3, attempts)
            self.assertEqual(b"bounded", target.read_bytes())
            state, anchor = self.roots(root)
            with self.assertRaisesRegex(StoreV2Error, "ACL_REJECTED"):
                StoreV2(
                    state,
                    anchor,
                    "CyberDefenderAgent",
                    KEY,
                    path_validator=lambda _path: (_ for _ in ()).throw(StoreV2Error("ACL_REJECTED")),
                )

    def test_reparse_and_anchor_inside_state_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-store-path-") as raw:
            root = Path(raw)
            state, anchor = self.roots(root)
            with self.assertRaisesRegex(StoreV2Error, "SCHEMA_INVALID"):
                StoreV2(state, state / "anchor", "CyberDefenderAgent", KEY, path_validator=ALLOW)
            target = root / "target"
            target.mkdir()
            link = root / "link"
            try:
                os.symlink(target, link, target_is_directory=True)
            except OSError:
                created = subprocess.run(
                    ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if created.returncode != 0:
                    self.fail("real reparse fixture unavailable")
            try:
                with self.assertRaisesRegex(StoreV2Error, "REPARSE_REJECTED"):
                    StoreV2(link, anchor, "CyberDefenderAgent", KEY, path_validator=ALLOW)
            finally:
                link.rmdir()

    def test_failure_code_subsets_and_diagnostic_survive_store_rejection(self) -> None:
        for subset in (STORE_FAILURE_CODES, GUARD_FAILURE_CODES, DIAGNOSTIC_FAILURE_CODES, INSTALLER_FAILURE_CODES):
            self.assertLessEqual(subset, FAILURE_CODES)
        with tempfile.TemporaryDirectory(prefix="cg2-diagnostic-") as raw:
            output = Path(raw) / "diagnostic.json"
            diagnostics.write_diagnostic(
                output,
                code="CRASH_STORE_AUTH_FAILED",
                stage="STORE_COMMIT",
                exception_class="StoreV2Error",
            )
            payload = json.loads(output.read_text(encoding="ascii"))
            self.assertEqual("CRASH_STORE_AUTH_FAILED", payload["code"])
            self.assertLessEqual(output.stat().st_size, diagnostics.MAX_DIAGNOSTIC_BYTES)
            self.assertNotIn("args", payload)
            self.assertNotIn("message", payload)


if __name__ == "__main__":
    unittest.main()

