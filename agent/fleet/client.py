from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class FleetTelemetryClient:
    """Best-effort non-authoritative fleet telemetry client.

    Failure to report fleet telemetry MUST NOT disable local protection or grant
    any authorization. Device certificates/attestation replace the bootstrap
    bearer token in a later enterprise milestone.
    """

    VERSION = "0.1"

    def __init__(self, base_url: str, token_file: str | Path, endpoint_id_file: str | Path, timeout: float = 2.0):
        self.base_url = str(base_url).rstrip("/")
        self.token_file = Path(token_file)
        self.endpoint_id_file = Path(endpoint_id_file)
        self.timeout = max(0.2, float(timeout))
        self.sent = 0
        self.failed = 0
        self.last_error: str | None = None

    def _token(self) -> str:
        return self.token_file.read_text(encoding="ascii").strip()

    def endpoint_id(self) -> str:
        return self.endpoint_id_file.read_text(encoding="ascii").strip()[:128]

    def _post(self, path: str, payload: dict[str, Any]) -> bool:
        try:
            raw = json.dumps(payload, separators=(",",":"), default=str).encode("utf-8")
            request = urllib.request.Request(
                self.base_url + path,
                data=raw,
                method="POST",
                headers={"Content-Type":"application/json","Authorization":"Bearer " + self._token()},
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                ok = 200 <= int(response.status) < 300
            if ok:
                self.sent += 1; self.last_error = None; return True
            self.failed += 1; self.last_error = f"HTTP_{response.status}"; return False
        except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            self.failed += 1; self.last_error = type(exc).__name__; return False

    def register(self, *, runtime_version: str, health_state: str = "UNKNOWN", service_state: str = "REGISTERED") -> bool:
        return self._post("/api/v1/enrollment/register", {
            "endpoint_id": self.endpoint_id(), "hostname": socket.gethostname(),
            "runtime_version": runtime_version, "install_state": "INSTALLED",
            "health_state": health_state, "service_state": service_state,
        })

    def heartbeat(self, *, runtime_version: str, health_state: str, service_state: str,
                  resource_state: str = "", last_error: str | None = None) -> bool:
        return self._post("/api/v1/endpoints/heartbeat", {
            "endpoint_id": self.endpoint_id(), "hostname": socket.gethostname(),
            "runtime_version": runtime_version, "health_state": health_state,
            "service_state": service_state, "resource_state": resource_state,
            "last_error": last_error,
        })

    def health_check(self) -> dict[str, Any]:
        return {"component":"FleetTelemetryClient","version":self.VERSION,
                "status":"HEALTHY" if self.failed == 0 else "DEGRADED",
                "authoritative":False,"sent":self.sent,"failed":self.failed,"last_error":self.last_error}
