from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

SERVICE_NAME = "CyberDefenderAgent"
DISPLAY_NAME = "CyberDefender Endpoint Protection"
DESCRIPTION = "CyberDefender security-first endpoint runtime service"
PYWIN32_AVAILABLE = False

if os.name == "nt":
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
        PYWIN32_AVAILABLE = True
    except ImportError:
        PYWIN32_AVAILABLE = False


def _machine_paths() -> dict[str, Path]:
    program_data = Path(os.environ.get("PROGRAMDATA", r"C:\\ProgramData")) / "CyberDefender"
    return {
        "base": program_data,
        "state": program_data / "state",
        "secrets": program_data / "secrets",
        "key": program_data / "secrets" / "storage_key.b64",
        "fleet_token": program_data / "secrets" / "fleet_token.txt",
        "endpoint_id": program_data / "identity" / "endpoint_id.txt",
        "distribution_db": program_data / "control-plane" / "distribution.db",
    }


def configure_machine_environment() -> dict[str, Path]:
    paths = _machine_paths()
    app_root = Path(__file__).resolve().parent.parent
    os.environ["CYBERDEFENDER_ROOT"] = str(app_root)
    os.environ["CYBERDEFENDER_STATE_DIR"] = str(paths["state"])
    os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = paths["key"].read_text(encoding="ascii").strip()
    os.environ["CYBERDEFENDER_ENDPOINT_ID"] = paths["endpoint_id"].read_text(encoding="ascii").strip()
    os.environ["CYBERDEFENDER_DISTRIBUTION_DB"] = str(paths["distribution_db"])
    os.environ["CYBERDEFENDER_FLEET_TOKEN_FILE"] = str(paths["fleet_token"])
    return paths


if PYWIN32_AVAILABLE:
    class CyberDefenderWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._stop_handle = win32event.CreateEvent(None, 0, 0, None)
            self._runner = None
            self._stop_event = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()
            if self._runner is not None:
                self._runner.stop()
            win32event.SetEvent(self._stop_handle)

        def SvcDoRun(self):
            from agent.service_lifecycle import run_guarded_service
            run_guarded_service(SERVICE_NAME, self._stop_event, self._run_attempt)

        def _run_attempt(self, guard):
            from agent.service_diagnostics import write_service_log
            try:
                from agent.main import build_managed_runtime
                from agent.service_runner import ServiceRunner
                paths = configure_machine_environment()
                client = None
                base_url = os.environ.get("CYBERDEFENDER_DISTRIBUTION_URL", "http://127.0.0.1:8785")
                try:
                    from agent.fleet.client import FleetTelemetryClient
                    if paths["fleet_token"].is_file() and paths["endpoint_id"].is_file():
                        client = FleetTelemetryClient(base_url, paths["fleet_token"], paths["endpoint_id"])
                except Exception:
                    write_service_log(SERVICE_NAME,"TELEMETRY_UNAVAILABLE")
                factory = lambda: build_managed_runtime(allow_optional_sensors=guard.allow_optional)
                self._runner = ServiceRunner(factory, interval_seconds=5.0, telemetry_client=client,
                                             lifecycle=guard, stop_event=self._stop_event)
                write_service_log(SERVICE_NAME, "RUNNING")
                servicemanager.LogInfoMsg("CyberDefender service starting")
                self._runner.run()
                if not self._runner.cleanup_verified:
                    guard.failed("CLEANUP_UNVERIFIED")
                    return False
                write_service_log(SERVICE_NAME, "STOPPED")
                servicemanager.LogInfoMsg("CyberDefender service stopped")
            except BaseException as exc:
                write_service_log(SERVICE_NAME, "FATAL", exc=exc)
                try: servicemanager.LogErrorMsg("CyberDefenderAgent: ATTEMPT_FAILED; see protected lifecycle evidence")
                except Exception: pass
                if self._runner is not None and not self._runner.cleanup_verified:
                    guard.failed("CLEANUP_UNVERIFIED")
                    return False
                raise
else:
    class CyberDefenderWindowsService:
        pass


def run_scm_dispatcher() -> int:
    if os.name != "nt" or not PYWIN32_AVAILABLE:
        return 3
    # Direct venv-python hosting avoids pythonservice.exe/PythonClass registry ambiguity.
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(CyberDefenderWindowsService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def preflight() -> int:
    if os.name != "nt" or not PYWIN32_AVAILABLE:
        return 3
    from agent.main import CyberDefenderRuntime, build_managed_runtime
    from agent.storage.durable_spool import DurableEventSpool
    from agent.quarantine.vault import SecureQuarantineVault
    configure_machine_environment()
    runtime = build_managed_runtime()
    try:
        print(
            "Agent service preflight OK",
            CyberDefenderRuntime.VERSION,
            DurableEventSpool.VERSION,
            SecureQuarantineVault.__name__,
            "| managed factory OK",
        )
    finally:
        runtime.close()
    return 0


def main() -> int:
    if os.name != "nt":
        print("CyberDefenderWindowsService is Windows-only")
        return 2
    if not PYWIN32_AVAILABLE:
        print("pywin32 is required: pip install pywin32")
        return 3
    if "--service-run" in sys.argv:
        return run_scm_dispatcher()
    if "--preflight" in sys.argv:
        return preflight()
    win32serviceutil.HandleCommandLine(CyberDefenderWindowsService)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
