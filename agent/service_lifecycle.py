"""Small SCM-facing host; no application imports before durable admission."""
from __future__ import annotations

import ctypes
from pathlib import Path
import threading
import time

from agent.service_crash_guard import CrashGuard, CrashPolicy
from agent.service_crash_store import FileCrashStore, default_root
from agent.service_watchdog import ProgressWatchdog, active_time


def boot_identity():
    """Windows boot GUID, independent of wall-clock estimates."""
    import uuid
    buffer=(ctypes.c_ubyte * 32)()
    query=ctypes.WinDLL("ntdll").NtQuerySystemInformation
    query.argtypes=[ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_void_p]
    query.restype=ctypes.c_long
    # SystemBootEnvironmentInformation (90), first member GUID BootIdentifier.
    if query(90,buffer,ctypes.sizeof(buffer),None) < 0:
        raise RuntimeError("BOOT_ID_UNAVAILABLE")
    return uuid.UUID(bytes_le=bytes(buffer[:16])).hex


def notify(service, state):
    from agent.service_diagnostics import write_service_log
    write_service_log(service,state)
    # The protected store may itself be unavailable. Keep a fixed-message
    # independent signal; never include exceptions or untrusted parameters.
    from agent.service_crash_guard import SERVICES
    if service in SERVICES and state in {"UNAVAILABLE", "STALLED", "LATCHED"}:
        try:
            import servicemanager
            servicemanager.LogErrorMsg(service + ": " + state)
        except Exception: pass


def run_guarded_service(service, stop_event, run_attempt, *, policy=CrashPolicy(),
                        store_factory=None, boot_factory=boot_identity, observer=notify,
                        clock=active_time):
    store=None; guard=None; last_state=None
    monitor_stop=threading.Event(); monitor=None
    try:
        try:
            store=(store_factory or (lambda: FileCrashStore(default_root(),service)))()
            guard=CrashGuard(store,boot=boot_factory(),policy=policy,clock=clock)
            guard.watchdog=ProgressWatchdog(clock=clock)
            monitor=threading.Thread(target=guard.watchdog.monitor,args=(monitor_stop,lambda state:observer(service,state)),
                                     name="CyberDefenderProgressWatchdog",daemon=True)
            monitor.start()
        except Exception:
            observer(service,"UNAVAILABLE")
            # No untrusted-state reprovision or risky application bootstrap.
            stop_event.wait()
            return
        while not stop_event.is_set():
            try:
                if guard.admit():
                    observer(service,"STARTING")
                    result=run_attempt(guard)
                    if not stop_event.is_set():
                        guard.failed("CLEANUP_UNVERIFIED" if result is False else "ATTEMPT_FAILED")
                state=guard.snapshot()["state"]
            except Exception:
                try: guard.failed()
                except Exception: pass
                state=guard.snapshot()["state"]
            if state != last_state:
                observer(service,state); last_state=state
            stop_event.wait(1.0)
        if guard is not None:
            try: guard.stop()
            except Exception: observer(service,"UNAVAILABLE")
    finally:
        monitor_stop.set()
        if monitor is not None: monitor.join(timeout=2)
        if store is not None: store.close()


def serve_http(server, guard, stop_event, path, *, probe_interval=5.0, probe_timeout=2.0):
    """Verify actual HTTP work on the local server; never count idle ticks."""
    import http.client
    import secrets
    completed=threading.Event()
    probe_finished=threading.Event()
    probe_nonce=secrets.token_hex(16)
    original_handler=server.RequestHandlerClass
    class ObservedHandler(original_handler):
        def handle(self):
            try: return super().handle()
            finally:
                headers=getattr(self,"headers",None)
                if headers is not None and headers.get("X-CyberDefender-Probe") == probe_nonce:
                    probe_finished.set()
    server.RequestHandlerClass=ObservedHandler
    def verify():
        while not completed.wait(probe_interval) and not stop_event.is_set():
            connection=None
            probe_finished.clear()
            try:
                # Bind to the actual local server port; no configurable remote URL.
                connection=http.client.HTTPConnection("127.0.0.1",server.server_address[1],timeout=probe_timeout)
                connection.request("GET",path,headers={"X-CyberDefender-Probe":probe_nonce})
                response=connection.getresponse()
                body=response.read(65537)
                healthy=response.status == 200 and len(body) <= 65536
                guard.progress(healthy=healthy)
            except Exception:
                try: guard.progress(healthy=False)
                except Exception: pass
            finally:
                if connection is not None: connection.close()
            # A timeout is not permission to accumulate additional request
            # threads. Wait for this handler to finish before another probe.
            while not completed.is_set() and not stop_event.is_set():
                if probe_finished.wait(1.0): break
    verifier=threading.Thread(target=verify,name="CyberDefenderHTTPProgress",daemon=True)
    verifier.start()
    try:
        if not stop_event.is_set(): server.serve_forever(poll_interval=.5)
    finally:
        completed.set(); verifier.join(timeout=3)
        server.server_close()
    return not verifier.is_alive()
