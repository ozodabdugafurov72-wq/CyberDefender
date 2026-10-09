from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from control_plane.fleet_protocol import PROTOCOL_VERSION, signature_headers, validate_token
from control_plane.xdr_compat import (
    CAPABILITY_DEVICE_INVENTORY,
    CAPABILITY_ENDPOINT_HEALTH,
    OCSF_DEVICE_INVENTORY_CLASS_UID,
    OCSF_SCHEMA_NAME,
    OCSF_SCHEMA_VERSION,
    validate_endpoint_id,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FleetTelemetryClient:
    """Best-effort non-authoritative fleet telemetry client.

    Failure to report fleet telemetry MUST NOT disable local protection or grant
    any authorization. Device certificates/attestation replace the bootstrap
    bearer token in a later enterprise milestone.
    """

    VERSION = "0.2"

    def __init__(self, base_url: str, token_file: str | Path, endpoint_id_file: str | Path, timeout: float = 2.0):
        self.base_url = self._validate_base_url(base_url)
        self.token_file = Path(token_file)
        self.endpoint_id_file = Path(endpoint_id_file)
        self.timeout = max(0.2, float(timeout))
        self.sent = 0
        self.failed = 0
        self.consecutive_failures = 0
        self.last_error: str | None = None
        self._opener = urllib.request.build_opener(_NoRedirect)

    @staticmethod
    def _validate_base_url(value: str) -> str:
        base_url = str(value or "").strip().rstrip("/")
        parsed = urlparse(base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("fleet URL must not contain credentials, query, or fragment")
        hostname = (parsed.hostname or "").lower()
        loopback = hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme not in ({"http", "https"} if loopback else {"https"}):
            raise ValueError("remote fleet URL must use HTTPS")
        if not hostname or parsed.path not in {"", "/"}:
            raise ValueError("fleet URL must be an origin without a path")
        return base_url

    def _token(self) -> str:
        return validate_token(self.token_file.read_text(encoding="ascii").strip())

    def endpoint_id(self) -> str:
        return validate_endpoint_id(self.endpoint_id_file.read_text(encoding="ascii").strip())

    def _contract(self, *, runtime_version: str) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "observed_at": int(time.time() * 1000),
            "telemetry_schema": OCSF_SCHEMA_NAME,
            "telemetry_schema_version": OCSF_SCHEMA_VERSION,
            "xdr_event_class_uids": [OCSF_DEVICE_INVENTORY_CLASS_UID],
            "capabilities": [CAPABILITY_ENDPOINT_HEALTH, CAPABILITY_DEVICE_INVENTORY],
            "endpoint_id": self.endpoint_id(),
            "hostname": socket.gethostname(),
            "runtime_version": str(runtime_version),
        }

    def _post(self, path: str, payload: dict[str, Any]) -> bool:
        try:
            raw = json.dumps(payload, separators=(",",":"), sort_keys=True, default=str).encode("utf-8")
            token = self._token()
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
                "User-Agent": "CyberDefenderFleet/0.2",
            }
            headers.update(signature_headers(token, method="POST", path=path, body=raw))
            request = urllib.request.Request(
                self.base_url + path,
                data=raw,
                method="POST",
                headers=headers,
            )
            with self._opener.open(request, timeout=self.timeout) as response:
                ok = 200 <= int(response.status) < 300
            if ok:
                self.sent += 1
                self.consecutive_failures = 0
                self.last_error = None
                return True
            self.failed += 1
            self.consecutive_failures += 1
            self.last_error = f"HTTP_{response.status}"
            return False
        except urllib.error.HTTPError as exc:
            exc.close()
            self.failed += 1
            self.consecutive_failures += 1
            self.last_error = f"HTTP_{exc.code}"
            return False
        except (OSError, ValueError, urllib.error.URLError) as exc:
            self.failed += 1
            self.consecutive_failures += 1
            self.last_error = type(exc).__name__
            return False

    def register(self, *, runtime_version: str, health_state: str = "UNKNOWN", service_state: str = "REGISTERED") -> bool:
        payload = self._contract(runtime_version=runtime_version)
        payload.update({
            "install_state": "INSTALLED",
            "health_state": health_state,
            "service_state": service_state,
        })
        return self._post("/api/v1/enrollment/register", payload)

    def heartbeat(self, *, runtime_version: str, health_state: str, service_state: str,
                  resource_state: str = "", last_error: str | None = None) -> bool:
        payload = self._contract(runtime_version=runtime_version)
        payload.update({
            "health_state": health_state,
            "service_state": service_state,
            "resource_state": resource_state or "UNKNOWN",
            "last_error": last_error,
        })
        return self._post("/api/v1/endpoints/heartbeat", payload)

    def health_check(self) -> dict[str, Any]:
        return {"component":"FleetTelemetryClient","version":self.VERSION,
                "status":"HEALTHY" if self.last_error is None else "DEGRADED",
                "authoritative":False,"sent":self.sent,"failed":self.failed,
                "failures_total":self.failed,"consecutive_failures":self.consecutive_failures,
                "last_error":self.last_error,"protocol":PROTOCOL_VERSION,
                "telemetry_schema":"OCSF","telemetry_schema_version":OCSF_SCHEMA_VERSION,
                "signed_ingest":True,"replay_protection":True}
