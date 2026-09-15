import copy
import unittest
from agent.service_crash_guard import CrashGuard, CrashPolicy, fresh_record


class MemoryStore:
    def __init__(self): self.record=fresh_record("CyberDefenderAgent")
    def load(self): return copy.deepcopy(self.record)
    def write(self, record):
        record["revision"] += 1; self.record=copy.deepcopy(record); return record


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.store=MemoryStore(); self.tick=0
        self.policy=CrashPolicy(attempts=2, stable_seconds=10, stable_checks=3, cooldown_seconds=5, probes=1)
    def guard(self, boot="boot-a"):
        return CrashGuard(self.store,boot=boot,policy=self.policy,clock=lambda:self.tick)

    def test_replacements_debit_and_latch(self):
        g=self.guard(); self.assertTrue(g.admit())
        g=self.guard(); self.assertFalse(g.admit()); self.tick+=5
        self.assertTrue(g.admit()); g=self.guard("boot-b")
        self.assertEqual(g.record["cumulative_failures"],2)
        self.assertFalse(g.admit()); self.tick+=5
        self.assertTrue(g.admit()); self.assertEqual(g.record["state"],"PROBE")
        g.failed(); self.tick+=100
        self.assertFalse(g.admit()); self.assertEqual(g.record["generation"],3)

    def test_stable_recovery_preserves_evidence(self):
        g=self.guard(); g.admit(); g.failed(); self.tick=5; g.admit()
        g.progress(healthy=True); self.tick=10; g.progress(healthy=True)
        self.assertNotEqual(g.record["state"],"RUNNING")
        self.tick=15; g.progress(healthy=True)
        self.assertEqual(g.record["state"],"RUNNING")
        self.assertEqual(g.record["cumulative_failures"],1)
        self.assertEqual(g.record["attempts_since_stable"],0)

    def test_stop_start_not_reset_and_no_parallel_admission(self):
        g=self.guard(); self.assertTrue(g.admit()); self.assertFalse(g.admit()); g.stop()
        g=self.guard(); self.tick=5; self.assertTrue(g.admit()); g.stop()
        g=self.guard(); self.assertFalse(g.admit())
        self.assertEqual(g.record["attempts_since_stable"],2)

    def test_store_failure_never_allows_factory(self):
        g=self.guard()
        self.store.write=lambda _: (_ for _ in ()).throw(OSError())
        with self.assertRaises(RuntimeError): g.admit()
        self.assertFalse(g.admit()); self.assertEqual(g.snapshot()["state"],"UNAVAILABLE")

    def test_unhealthy_and_monotonic_rollback_earn_no_stability(self):
        g=self.guard(); g.admit(); g.progress(healthy=True)
        self.tick=10; g.progress(healthy=False)
        self.tick=1; g.progress(healthy=True)
        self.assertNotEqual(g.record["state"],"RUNNING")

    def test_bounded_history(self):
        g=self.guard()
        for _ in range(100): g.failed()
        self.assertEqual(len(g.record["recent_failures"]),32)
        self.assertEqual(g.record["cumulative_failures"],100)

    def test_optional_sensors_recover_after_validated_clean_restart(self):
        g=self.guard(); self.assertTrue(g.allow_optional); g.admit(); g.failed()
        self.assertFalse(g.allow_optional)
        self.tick=5; g.admit(); g.progress(healthy=True)
        self.tick=10; g.progress(healthy=True)
        self.tick=15; g.progress(healthy=True); g.stop()
        g=self.guard(); self.assertTrue(g.allow_optional)
        self.assertEqual(g.record["cumulative_failures"],1)


if __name__ == "__main__": unittest.main()
