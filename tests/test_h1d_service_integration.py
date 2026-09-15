import threading
import unittest
from unittest.mock import Mock, patch
from agent.service_lifecycle import run_guarded_service, boot_identity
from agent.service_crash_guard import CrashGuard, CrashPolicy, fresh_record
from agent.service_runner import ServiceRunner


class Store:
    def __init__(self): self.r=fresh_record("CyberDefenderAgent")
    def load(self): return self.r.copy()
    def write(self,r): r["revision"]+=1; self.r=r.copy(); return r
    def close(self): pass


class IntegrationTests(unittest.TestCase):
    def test_store_missing_never_initializes_application(self):
        stop=threading.Event(); attempted=Mock(); states=[]
        def observe(_,state): states.append(state); stop.set()
        def missing(): raise OSError()
        run_guarded_service("CyberDefenderAgent",stop,attempted,store_factory=missing,observer=observe)
        attempted.assert_not_called(); self.assertEqual(states,["UNAVAILABLE"])

    def test_attempt_persisted_before_factory_and_stop_clean(self):
        stop=threading.Event(); store=Store()
        def run(guard):
            self.assertTrue(store.r["active_attempt"])
            self.assertEqual(store.r["generation"],1)
            stop.set()
        run_guarded_service("CyberDefenderAgent",stop,run,store_factory=lambda:store,boot_factory=lambda:"a",observer=lambda *_:None)
        self.assertTrue(store.r["clean_stop"])

    def test_early_stop_skips_runtime(self):
        stop=threading.Event(); stop.set(); factory=Mock()
        runner=ServiceRunner(factory,stop_event=stop); runner.run()
        factory.assert_not_called(); self.assertTrue(runner.cleanup_verified)

    def test_cleanup_failure_retains_runtime(self):
        rt=Mock(); rt.close.side_effect=OSError()
        runner=ServiceRunner(lambda:rt); runner.run(max_cycles=1)
        self.assertFalse(runner.cleanup_verified); self.assertIs(runner.runtime,rt)

    def test_boot_guid_stable_in_same_boot(self):
        self.assertEqual(boot_identity(),boot_identity())
        self.assertEqual(len(boot_identity()),32)
        self.assertNotEqual(boot_identity(),"0"*32)

    def test_optional_telemetry_constructor_failure_preserves_core(self):
        import agent.windows_service as host
        service=object.__new__(host.CyberDefenderWindowsService)
        service._runner=None; service._stop_event=threading.Event()
        runtime=Mock()
        runtime.run_cycle.side_effect=lambda:service._stop_event.set()
        runtime.health_snapshot.return_value={"runtime":{"status":"HEALTHY"}}
        runtime.child_cleanup_verified=True
        guard=Mock(allow_optional=True)
        paths={"fleet_token":Mock(),"endpoint_id":Mock()}
        with patch.object(host,"configure_machine_environment",return_value=paths),patch("agent.main.build_managed_runtime",return_value=runtime),patch("agent.fleet.client.FleetTelemetryClient",side_effect=OSError("synthetic secret")),patch("agent.service_diagnostics.write_service_log"),patch.object(host.servicemanager,"LogInfoMsg"):
            service._run_attempt(guard)
        self.assertEqual(runtime.run_cycle.call_count,1)
        self.assertTrue(service._runner.cleanup_verified)


if __name__ == "__main__": unittest.main()
