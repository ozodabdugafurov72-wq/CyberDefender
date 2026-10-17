from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from agent.event import SecurityEvent
from agent.storage.durable_spool import DurableEventSpool, DurableSpoolPolicy
from scripts.agent_release import offline_spool_recovery as recovery


def file_hashes(root: Path) -> dict[str, str]:
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in recovery.FILES
    }


def make_limit_plus_one(root: Path) -> tuple[Path, str]:
    spool = root / "spool-copy"
    store = DurableEventSpool(spool)
    for index in range(28):
        assert store.append(
            SecurityEvent(
                event_type="RECOVERY_FIXTURE",
                severity="HIGH",
                value=index,
                source="test",
                message="offline recovery fixture",
            )
        )
    pending = {record["event_id"] for record in store.pending_records()}
    ordered = [f"ack-{index:05d}" for index in range(DurableSpoolPolicy().max_terminal_records + 1)]
    (spool / "acked_state.json").write_text(
        json.dumps({"schema_version": "1", "status": "ACKED", "acked_ids": sorted(ordered)}),
        encoding="utf-8",
    )
    (spool / "acked.jsonl").write_text(
        "".join(json.dumps({"event_id": event_id}) + "\n" for event_id in ordered),
        encoding="utf-8",
    )
    (spool / "quarantined.jsonl").touch(exist_ok=True)
    return spool, recovery.pending_digest(pending)


class OfflineSpoolRecoveryTests(unittest.TestCase):
    def test_copy_recovery_is_ordered_idempotent_and_preserves_pending(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-offline-recovery-") as raw:
            root = Path(raw)
            spool, digest = make_limit_plus_one(root)
            quiescent = mock.Mock()
            result = recovery.recover(spool, root / "backup", digest, quiescent)

            self.assertEqual("OFFLINE_SPOOL_RECOVERY_PASS", result["status"])
            self.assertEqual(16385, result["ack_before"])
            self.assertEqual(16384, result["ack_after"])
            self.assertEqual(1, result["evicted_journal_position"])
            self.assertEqual(28, result["pending_count"])
            self.assertEqual(digest, result["pending_digest16"])
            self.assertTrue(result["idempotent_second_run"])
            self.assertEqual(4, quiescent.call_count)

    def test_execution_mode_rejects_environment_spoof_and_running_agent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-offline-mode-") as raw:
            root = Path(raw)
            live = root / "program-data" / "CyberDefender" / "state" / "spool"
            copy = root / "copy"
            live.mkdir(parents=True)
            copy.mkdir()
            with mock.patch.object(recovery, "known_program_data", return_value=root / "program-data"):
                with self.assertRaisesRegex(recovery.RecoveryError, "COPY_MODE_LIVE_PATH_REJECTED"):
                    recovery.validate_mode("copy", live)
                with mock.patch.object(recovery, "require_agent_stopped", side_effect=recovery.RecoveryError("AGENT_NOT_QUIESCENT")):
                    with self.assertRaisesRegex(recovery.RecoveryError, "AGENT_NOT_QUIESCENT"):
                        recovery.validate_mode("live", live)
                resolved, check = recovery.validate_mode("copy", copy)
                self.assertEqual(copy.resolve(), resolved)
                self.assertIsNone(check)

        fake_service = mock.Mock()
        with mock.patch.object(recovery.os, "name", "nt"), mock.patch.dict(
            "sys.modules", {"psutil": types.SimpleNamespace(win_service_get=lambda _name: fake_service)}
        ):
            fake_service.as_dict.return_value = {"status": "running", "pid": 41}
            with self.assertRaisesRegex(recovery.RecoveryError, "AGENT_NOT_QUIESCENT"):
                recovery.require_agent_stopped()
            fake_service.as_dict.return_value = {"status": "stopped", "pid": 0}
            recovery.require_agent_stopped()

    def test_failed_postcheck_restores_every_source_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-offline-rollback-") as raw:
            root = Path(raw)
            spool, digest = make_limit_plus_one(root)
            before = file_hashes(spool)
            real_store = recovery.DurableEventSpool

            class FailedHealthStore:
                def __init__(self, path: Path):
                    self.inner = real_store(path)
                    self._acked = self.inner._acked

                def health_check(self):
                    return {"status": "DEGRADED", "terminal_state_safe": False}

                def pending_records(self):
                    return self.inner.pending_records()

            with mock.patch.object(recovery, "DurableEventSpool", FailedHealthStore):
                with self.assertRaisesRegex(recovery.RecoveryError, "RECOVERY_POSTCHECK_FAILED"):
                    recovery.recover(spool, root / "backup", digest)

            self.assertEqual(before, file_hashes(spool))

    def test_corrupt_backup_is_rejected_before_any_source_replace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-offline-corrupt-backup-") as raw:
            root = Path(raw)
            spool, _ = make_limit_plus_one(root)
            backup = root / "backup"
            expected = recovery.copy_backup(spool, backup)
            (backup / "acked_state.json").write_bytes(b"corrupt")
            before = file_hashes(spool)

            with mock.patch("os.replace") as replace:
                self.assertFalse(recovery.restore(spool, backup, expected))

            replace.assert_not_called()
            self.assertEqual(before, file_hashes(spool))

    def test_mid_replace_failure_completes_bounded_second_restore(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-offline-partial-restore-") as raw:
            root = Path(raw)
            spool, _ = make_limit_plus_one(root)
            backup = root / "backup"
            expected = recovery.copy_backup(spool, backup)
            (spool / "pending.jsonl").write_bytes(b"mutated")
            real_replace = recovery.os.replace
            calls = 0

            def interrupted_once(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise PermissionError("simulated transient replace interruption")
                return real_replace(source, target)

            with mock.patch.object(recovery.os, "replace", side_effect=interrupted_once):
                self.assertTrue(recovery.restore(spool, backup, expected))

            self.assertGreater(calls, len(recovery.FILES))
            self.assertEqual(expected, file_hashes(spool))


if __name__ == "__main__":
    unittest.main()
