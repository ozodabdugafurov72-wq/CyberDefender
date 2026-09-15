import copy
import errno
import concurrent.futures
import threading
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from agent.service_crash_store import FileCrashStore, CrashStoreError, provision, no_reparse, MAX_BYTES
from agent.service_crash_guard import CrashGuard

SERVICE="CyberDefenderAgent"


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        provision(self.root,path_validator=no_reparse)
    def store(self,service=SERVICE):
        s=FileCrashStore(self.root,service,path_validator=no_reparse); self.addCleanup(s.close); return s

    def test_missing_corrupt_truncated_oversized_tampered(self):
        s=self.store(); path=self.root/(SERVICE+".0.json"); original=path.read_bytes()
        for data in (b"", b"{", b"x"*(MAX_BYTES+1), original.replace(b"READY",b"PROBE")):
            path.write_bytes(data)
            with self.assertRaises(CrashStoreError): s.load()
        path.unlink()
        with self.assertRaises(CrashStoreError): s.load()
        path.write_bytes(original)

    def test_slot_replay_and_wrong_service_rejected(self):
        s=self.store(); first=(self.root/(SERVICE+".0.json")).read_bytes()
        s.write(s.load()); s.write(s.load())
        (self.root/(SERVICE+".0.json")).write_bytes(first)
        with self.assertRaises(CrashStoreError): s.load()
        (self.root/(SERVICE+".0.json")).write_bytes((self.root/"CyberDefenderOwnerUI.0.json").read_bytes())
        with self.assertRaises(CrashStoreError): s.load()

    def test_exclusive_lock_and_separate_services(self):
        self.store()
        with self.assertRaises(CrashStoreError): self.store()
        self.assertEqual(self.store("CyberDefenderOwnerUI").load()["service"],"CyberDefenderOwnerUI")
        with self.assertRaises(CrashStoreError): self.store("../bad")

    def test_write_failure_keeps_last_committed_state(self):
        s=self.store(); r=s.load()
        for error in (PermissionError(), OSError(errno.ENOSPC,"synthetic")):
            with patch("agent.service_crash_store.atomic_write",side_effect=error):
                with self.assertRaises(OSError): s.write(r)
            self.assertEqual(s.load(),r)

    def test_interrupted_anchor_commit_keeps_old_transaction(self):
        import agent.service_crash_store as module
        s=self.store(); before=s.load(); real=module.atomic_write
        def fail_anchor(path,data):
            if path.suffix == ".anchor": raise OSError("synthetic interrupted commit")
            real(path,data)
        with patch.object(module,"atomic_write",side_effect=fail_anchor):
            with self.assertRaises(OSError): s.write(before)
        self.assertEqual(s.load(),before)
        self.assertEqual(s.write(before)["revision"],1)

    def test_no_auto_reprovision_after_deletion(self):
        (self.root/"guard.key").unlink()
        with self.assertRaises(CrashStoreError): provision(self.root,path_validator=no_reparse)

    def test_acl_denial_is_not_empty_state(self):
        def denied(_): raise PermissionError()
        with self.assertRaises(CrashStoreError): FileCrashStore(self.root,SERVICE,path_validator=denied)

    def test_durable_boot_transition_and_stop_abuse(self):
        s=self.store(); g=CrashGuard(s,boot="a"); self.assertTrue(g.admit()); s.close()
        s=self.store(); g=CrashGuard(s,boot="b")
        self.assertEqual(g.record["cumulative_failures"],1)
        self.assertEqual(g.record["generation"],1)
        g.stop(); s.close(); s=self.store()
        self.assertEqual(s.load()["attempts_since_stable"],1)

    def test_same_object_concurrent_writers_reject_stale_revision(self):
        s=self.store(); record=s.load()
        def write(_):
            try: s.write(record); return True
            except CrashStoreError: return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(write,range(8)))
        self.assertEqual(sum(results),1); self.assertEqual(s.load()["revision"],1)

    def test_marker_deletion_rejected(self):
        (self.root/"provisioned").unlink()
        with self.assertRaises(CrashStoreError): self.store()

    def test_reparse_attribute_rejected(self):
        from types import SimpleNamespace
        with patch.object(Path,"lstat",return_value=SimpleNamespace(st_mode=0,st_file_attributes=0x400)):
            with self.assertRaises(CrashStoreError): no_reparse(self.root)

    def test_actual_unprotected_test_directory_is_rejected(self):
        from agent.service_crash_store import protected_path
        with self.assertRaises(CrashStoreError): protected_path(self.root)

    def test_repair_grants_one_probe_without_erasing_interrupted_attempt(self):
        s=self.store(); g=CrashGuard(s,boot="a"); g.admit()
        r=s.authorize_probe()
        self.assertEqual(r["cumulative_failures"],1)
        self.assertEqual(r["generation"],1)
        self.assertEqual(r["repair_count"],1)
        self.assertEqual(r["attempts_since_stable"],1)
        self.assertEqual(r["state"],"LATCHED")

    def test_closed_store_cannot_write_without_ownership(self):
        s=self.store(); r=s.load(); s.close()
        with self.assertRaises(CrashStoreError): s.write(r)

    def test_resource_size_remains_bounded_under_repeated_failures(self):
        import time
        s=self.store(); g=CrashGuard(s,boot="a"); start=time.perf_counter()
        for _ in range(100): g.failed()
        sizes=[p.stat().st_size for p in self.root.iterdir() if p.is_file()]
        self.assertLessEqual(max(sizes),MAX_BYTES)
        self.assertEqual(len(g.record["recent_failures"]),32)
        print(f"RESOURCE_STORE files={len(sizes)} bytes={sum(sizes)} failure_commits=100 seconds={time.perf_counter()-start:.3f}")

    def test_committed_debit_is_readback_verified(self):
        import agent.service_crash_store as module
        s=self.store(); r=s.load(); real=module.atomic_write
        def corrupt_after_write(path,data):
            real(path,data)
            if path.suffix == ".anchor": path.write_bytes(b"corrupt")
        with patch.object(module,"atomic_write",side_effect=corrupt_after_write):
            with self.assertRaises(CrashStoreError): s.write(r)

    def test_close_waits_for_inflight_write(self):
        import agent.service_crash_store as module
        s=self.store(); r=s.load(); entered=threading.Event(); release=threading.Event(); closed=threading.Event()
        real=module.atomic_write; errors=[]
        def paused(path,data):
            entered.set(); release.wait(3); real(path,data)
        def write():
            try: s.write(r)
            except Exception as exc: errors.append(type(exc).__name__)
        def close(): s.close(); closed.set()
        with patch.object(module,"atomic_write",side_effect=paused):
            writer=threading.Thread(target=write); writer.start()
            self.assertTrue(entered.wait(2)); closer=threading.Thread(target=close); closer.start()
            try:
                self.assertFalse(closed.wait(.05))
                with self.assertRaises(CrashStoreError): self.store()
            finally:
                release.set(); writer.join(timeout=3); closer.join(timeout=3)
        self.assertTrue(closed.is_set()); self.assertEqual(errors,[])


if __name__ == "__main__": unittest.main()
