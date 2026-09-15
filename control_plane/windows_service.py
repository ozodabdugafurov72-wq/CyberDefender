from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

SERVICE_NAME = "CyberDefenderControlPlane"
DISPLAY_NAME = "CyberDefender Distribution Telemetry"
DESCRIPTION = "CyberDefender local distribution and fleet telemetry control plane"
PYWIN32_AVAILABLE = False

if os.name == "nt":
    try:
        import servicemanager
        import win32service
        import win32serviceutil
        PYWIN32_AVAILABLE = True
    except ImportError:
        PYWIN32_AVAILABLE = False


def configure_machine_environment() -> Path:
    app_root = Path(__file__).resolve().parent.parent
    base = Path(os.environ.get("PROGRAMDATA", r"C:\\ProgramData")) / "CyberDefender"
    os.environ["CYBERDEFENDER_ROOT"] = str(app_root)
    os.environ["CYBERDEFENDER_DISTRIBUTION_DB"] = str(base / "control-plane" / "distribution.db")
    os.environ["CYBERDEFENDER_FLEET_TOKEN_FILE"] = str(base / "secrets" / "fleet_token.txt")
    os.environ.setdefault("CYBERDEFENDER_INSTALLER_PATH", str(base / "distribution" / "CyberDefenderPackage.zip"))
    return base

if PYWIN32_AVAILABLE:
    class CyberDefenderControlPlaneService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._server = None
            self._stop_event = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()
            if self._server is not None:
                threading.Thread(target=self._server.shutdown, daemon=True).start()

        def SvcDoRun(self):
            from agent.service_lifecycle import run_guarded_service
            run_guarded_service(SERVICE_NAME, self._stop_event, self._run_attempt)

        def _run_attempt(self, guard):
            from agent.service_diagnostics import write_service_log
            try:
                configure_machine_environment()
                from control_plane.distribution_server import HOST, PORT, Handler, DB
                from http.server import ThreadingHTTPServer
                DB.parent.mkdir(parents=True, exist_ok=True)
                self._server = ThreadingHTTPServer((HOST, PORT), Handler)
                write_service_log(SERVICE_NAME, "RUNNING")
                servicemanager.LogInfoMsg("CyberDefender control plane starting")
                try:
                    from agent.service_lifecycle import serve_http
                    return serve_http(self._server, guard, self._stop_event, "/health")
                finally:
                    self._server.server_close()
                    write_service_log(SERVICE_NAME, "STOPPED")
                    servicemanager.LogInfoMsg("CyberDefender control plane stopped")
            except BaseException as exc:
                write_service_log(SERVICE_NAME, "FATAL", exc=exc)
                try: servicemanager.LogErrorMsg("CyberDefenderControlPlane: ATTEMPT_FAILED; see protected lifecycle evidence")
                except Exception: pass
                raise
else:
    class CyberDefenderControlPlaneService: pass


def run_scm_dispatcher() -> int:
    if os.name != "nt" or not PYWIN32_AVAILABLE: return 3
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(CyberDefenderControlPlaneService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def preflight() -> int:
    if os.name != "nt" or not PYWIN32_AVAILABLE: return 3
    base = configure_machine_environment()
    from control_plane.distribution_server import HOST, PORT, DB, ARTIFACT, TOKEN_FILE
    if not TOKEN_FILE.is_file(): raise RuntimeError("fleet token missing")
    if not ARTIFACT.is_file(): raise RuntimeError("distribution artifact missing")
    DB.parent.mkdir(parents=True, exist_ok=True)
    print(f"Control plane preflight OK {HOST}:{PORT} | {DB}")
    return 0


def main() -> int:
    if os.name != "nt": print("CyberDefenderControlPlaneService is Windows-only"); return 2
    if not PYWIN32_AVAILABLE: print("pywin32 is required"); return 3
    if "--service-run" in sys.argv: return run_scm_dispatcher()
    if "--preflight" in sys.argv: return preflight()
    win32serviceutil.HandleCommandLine(CyberDefenderControlPlaneService); return 0

if __name__ == "__main__": raise SystemExit(main())
