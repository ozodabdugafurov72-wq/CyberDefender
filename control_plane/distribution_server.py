from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from control_plane.distribution_repository import DistributionRepository
from control_plane.cloud_soc_v2 import CloudSocError, CloudSocRepository, CloudSocService
from control_plane.fleet_protocol import FleetProtocolError, SlidingWindowLimiter, validate_token, verify_request
from control_plane.xdr_compat import (
    CAPABILITY_RESPONSE_EVIDENCE,
    compatibility_status,
    device_inventory_events,
    validate_ingest_contract,
    validate_response_evidence,
)


HOST = os.getenv("CYBERDEFENDER_DISTRIBUTION_HOST", "127.0.0.1")
PORT = int(os.getenv("PORT") or os.getenv("CYBERDEFENDER_DISTRIBUTION_PORT", "8785"))
DB = Path(
    os.getenv(
        "CYBERDEFENDER_DISTRIBUTION_DB",
        Path(os.getenv("LOCALAPPDATA", ".")) / "CyberDefender" / "state" / "control_plane" / "distribution.db",
    )
).expanduser().resolve()
_default_base = Path(os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA") or ".") / "CyberDefender"
_default_artifact = _default_base / "distribution" / "CyberDefenderPackage.zip"
ARTIFACT = Path(os.getenv("CYBERDEFENDER_INSTALLER_PATH", str(_default_artifact))).expanduser().resolve()
TOKEN_FILE = Path(
    os.getenv(
        "CYBERDEFENDER_FLEET_TOKEN_FILE",
        Path(os.getenv("LOCALAPPDATA", ".")) / "CyberDefender" / "secrets" / "fleet_token.txt",
    )
).expanduser().resolve()
MAX_BODY = 64 * 1024
_MANIFEST_LOCK = threading.RLock()
_MANIFEST_CACHE: tuple[tuple[str, int, int], dict] | None = None
_AUTH_LIMITER = SlidingWindowLimiter(
    limit=int(os.getenv("CYBERDEFENDER_FLEET_AUTH_RATE_LIMIT", "120")),
    window_seconds=60,
)
_WRITE_LIMITER = SlidingWindowLimiter(
    limit=int(os.getenv("CYBERDEFENDER_FLEET_ENDPOINT_RATE_LIMIT", "60")),
    window_seconds=60,
)
_DOWNLOAD_LIMITER = SlidingWindowLimiter(
    limit=int(os.getenv("CYBERDEFENDER_DOWNLOAD_RATE_LIMIT", "60")),
    window_seconds=60,
)
_TENANT_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")


def _token() -> str:
    if os.getenv("CYBERDEFENDER_FLEET_TOKEN"):
        return os.environ["CYBERDEFENDER_FLEET_TOKEN"].strip()
    try:
        return TOKEN_FILE.read_text(encoding="ascii").strip()
    except OSError:
        return ""


def _read_token() -> str:
    return os.getenv("CYBERDEFENDER_DISTRIBUTION_READ_TOKEN", "").strip()


def _v2_read_token(tenant_id: str) -> str:
    raw = os.getenv("CYBERDEFENDER_CLOUD_SOC_READ_TOKENS_JSON", "").strip()
    if not raw or len(raw) > 32 * 1024:
        return ""
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return ""
    if not isinstance(value, dict) or not value or len(value) > 1_000:
        return ""
    normalized = {}
    seen_tokens = set()
    for tenant, token in value.items():
        if (not isinstance(tenant, str) or not _TENANT_ID_RE.fullmatch(tenant) or
                not isinstance(token, str) or not 32 <= len(token.strip()) <= 512 or
                token.strip() in seen_tokens):
            return ""
        normalized[tenant] = token.strip()
        seen_tokens.add(token.strip())
    return normalized.get(str(tenant_id).strip().lower(), "")


def _cloud_v2_enabled() -> bool:
    return os.getenv("CYBERDEFENDER_CLOUD_SOC_V2", "").strip().lower() in {"1", "true", "yes", "on"}


def _v2_endpoint_path(path: str) -> tuple[str, str] | None:
    parts = path.strip("/").split("/")
    if len(parts) == 5 and parts[:3] == ["api", "v2", "endpoints"]:
        if parts[4] in {"heartbeat", "event-batches"}:
            return parts[3], parts[4]
    return None


def _v2_owner_tenant(path: str) -> str | None:
    parts = path.strip("/").split("/")
    if len(parts) == 6 and parts[:4] == ["api", "v2", "owner", "tenants"] and parts[5] == "fleet":
        return parts[4]
    return None


def _authorized(value: str | None, expected: str | None = None) -> bool:
    expected = _token() if expected is None else str(expected).strip()
    if not expected or not value or not value.startswith("Bearer "):
        return False
    return hmac.compare_digest(expected, value[7:].strip())


def _private_network_host(value: str | None) -> bool:
    host = str(value or "").strip().lower()
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    else:
        host = host.split(":", 1)[0]
    expected = os.getenv("RAILWAY_PRIVATE_DOMAIN", "").strip().lower()
    return bool(host and ((expected and host == expected) or host.endswith(".railway.internal")))


def _artifact_manifest() -> dict:
    global _MANIFEST_CACHE
    if not ARTIFACT.is_file():
        raise FileNotFoundError(str(ARTIFACT))
    stat = ARTIFACT.stat()
    key = (str(ARTIFACT), int(stat.st_size), int(stat.st_mtime_ns))
    with _MANIFEST_LOCK:
        if _MANIFEST_CACHE is not None and _MANIFEST_CACHE[0] == key:
            return dict(_MANIFEST_CACHE[1])
        digest = hashlib.sha256()
        with ARTIFACT.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        raw_digest = digest.digest()
        manifest = {
            "artifact": ARTIFACT.name,
            "version": os.getenv("CYBERDEFENDER_PACKAGE_VERSION", "unversioned")[:64],
            "channel": os.getenv("CYBERDEFENDER_PACKAGE_CHANNEL", "stable")[:32],
            "size": int(stat.st_size),
            "sha256": digest.hexdigest(),
            "digest": "sha-256=:" + base64.b64encode(raw_digest).decode("ascii") + ":",
        }
        _MANIFEST_CACHE = (key, manifest)
        return dict(manifest)


def _read_only_connection(db_path: Path) -> sqlite3.Connection:
    if not db_path.is_file():
        raise FileNotFoundError(str(db_path))
    uri = "file:" + quote(db_path.as_posix(), safe="/:") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute("PRAGMA busy_timeout=1000")
    return conn


def _owner_snapshot(db_path: Path, *, online_after_seconds: float = 90.0) -> dict:
    conn = _read_only_connection(db_path)
    try:
        cutoff = time.time() - max(1.0, float(online_after_seconds))
        downloads = conn.execute(
            """
            SELECT COUNT(*) downloads_total,
              SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) downloads_completed,
              SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) downloads_failed
            FROM downloads
            """
        ).fetchone()
        fleet = conn.execute(
            """
            SELECT COUNT(*) endpoints_total,
              SUM(CASE WHEN install_state='INSTALLED' THEN 1 ELSE 0 END) installed,
              SUM(CASE WHEN install_state='PENDING' THEN 1 ELSE 0 END) pending,
              SUM(CASE WHEN install_state='FAILED' THEN 1 ELSE 0 END) install_failed,
              SUM(CASE WHEN install_state='REVOKED' THEN 1 ELSE 0 END) revoked,
              SUM(CASE WHEN install_state='INSTALLED' AND last_seen>=? THEN 1 ELSE 0 END) online,
              SUM(CASE WHEN install_state='INSTALLED' AND last_seen<? THEN 1 ELSE 0 END) offline,
              SUM(CASE WHEN health_state='DEGRADED' THEN 1 ELSE 0 END) degraded,
              SUM(CASE WHEN health_state='CRITICAL' THEN 1 ELSE 0 END) critical
            FROM fleet_endpoints
            """,
            (cutoff, cutoff),
        ).fetchone()
        rows = conn.execute(
            """
            SELECT endpoint_id, hostname, install_state, health_state,
                   service_state, runtime_version, resource_state,
                   first_seen, last_seen, telemetry_schema,
                   telemetry_schema_version, capabilities_json, last_observed_at
            FROM fleet_endpoints ORDER BY last_seen DESC LIMIT 100
            """
        ).fetchall()
        response_summary = conn.execute(
            """
            SELECT COUNT(*) responses_total,
              SUM(CASE WHEN action_state='QUARANTINED' THEN 1 ELSE 0 END) responses_quarantined,
              SUM(CASE WHEN action_state='RESTORED' THEN 1 ELSE 0 END) responses_restored,
              MAX(response_latency_ms) response_latency_ms_max
            FROM fleet_response_evidence
            """
        ).fetchone()
        response_rows = conn.execute(
            """
            SELECT evidence_id, endpoint_id, incident_id, event_id, observed_at, received_at,
                   target_name, target_sha256, detection_types_json, risk_score, risk_level,
                   policy_outcome, policy_reason, verifier_outcome, action_state,
                   verification_outcome, response_latency_ms, execution_latency_ms,
                   detection_to_response_ms, restore_latency_ms, evidence_ref,
                   production_authorization, lab_authorization, authorization_policy_id, receipt_integrity,
                   post_action_verification
            FROM fleet_response_evidence ORDER BY received_at DESC LIMIT 100
            """
        ).fetchall()
    finally:
        conn.close()
    summary = {
        key: int((downloads[key] if downloads else 0) or 0)
        for key in ("downloads_total", "downloads_completed", "downloads_failed")
    }
    summary.update(
        {
            key: int((fleet[key] if fleet else 0) or 0)
            for key in (
                "endpoints_total",
                "installed",
                "pending",
                "install_failed",
                "revoked",
                "online",
                "offline",
                "degraded",
                "critical",
            )
        }
    )
    summary.update(
        {
            key: int((response_summary[key] if response_summary else 0) or 0)
            for key in ("responses_total", "responses_quarantined", "responses_restored")
        }
    )
    summary["response_latency_ms_max"] = (
        float(response_summary["response_latency_ms_max"])
        if response_summary and response_summary["response_latency_ms_max"] is not None
        else None
    )
    endpoints = []
    for row in rows:
        item = dict(row)
        try:
            capabilities = json.loads(item.pop("capabilities_json", "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            capabilities = []
        item["capabilities"] = capabilities if isinstance(capabilities, list) else []
        endpoints.append(item)
    responses = []
    for row in response_rows:
        item = dict(row)
        try:
            detections = json.loads(item.pop("detection_types_json", "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            detections = []
        item["schema"] = "cyberdefender.response-evidence.v1"
        item["detection_types"] = detections if isinstance(detections, list) else []
        item["receipt_integrity"] = item.get("receipt_integrity") == 1
        item["post_action_verification"] = item.get("post_action_verification") == 1
        responses.append(item)
    return {
        "status": "HEALTHY",
        "summary": summary,
        "endpoints": endpoints,
        "responses": responses,
        "read_only": True,
        "xdr": compatibility_status(),
    }


def _owner_xdr_snapshot(db_path: Path, *, limit: int = 100) -> dict:
    conn = _read_only_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT endpoint_id, hostname, install_state, health_state,
                   service_state, runtime_version, resource_state,
                   first_seen, last_seen
            FROM fleet_endpoints
            WHERE telemetry_schema='ocsf' AND telemetry_schema_version='1.9.0'
            ORDER BY last_seen DESC LIMIT ?
            """,
            (max(1, min(int(limit), 500)),),
        ).fetchall()
    finally:
        conn.close()
    return {
        "schema": "OCSF",
        "schema_version": "1.9.0",
        "class_uid": 5001,
        "read_only": True,
        "events": device_inventory_events(dict(row) for row in rows),
    }


def _initialize_database(db_path: Path) -> None:
    """Create/migrate the distribution schema before read-only consumers query it."""
    repository = DistributionRepository(db_path)
    repository.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberDefender"
    sys_version = ""

    def log_message(self, format, *args):
        return

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def _json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> tuple[bytes, dict]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0:
            raise ValueError("request body required")
        if length > MAX_BODY:
            raise OverflowError("request body too large")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("incomplete request body")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return raw, value

    def _client_key(self) -> str:
        candidate = str(self.headers.get("X-Real-IP") or "").strip()
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            normalized = str(self.client_address[0] if self.client_address else "unknown")
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._json(
                200,
                {
                    "name": "CyberDefender",
                    "health": "/health",
                    "download": "/download/cyberdefender",
                    "manifest": "/download/cyberdefender/manifest",
                },
            )
            return
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return
        v2_tenant = _v2_owner_tenant(parsed.path)
        if v2_tenant is not None:
            if not _cloud_v2_enabled():
                self._json(404, {"error": "NOT_FOUND"})
                return
            if not _private_network_host(self.headers.get("Host")):
                self._json(404, {"error": "NOT_FOUND"})
                return
            if not _authorized(self.headers.get("Authorization"), _v2_read_token(v2_tenant)):
                self._json(403, {"error": "TENANT_ACCESS_DENIED"})
                return
            repository = CloudSocRepository(DB)
            try:
                self._json(200, repository.tenant_snapshot(v2_tenant, now=time.time()))
            except CloudSocError as exc:
                self._json(exc.status, {"error": exc.code})
            except sqlite3.Error:
                self._json(503, {"error": "STORAGE_UNAVAILABLE"})
            finally:
                repository.close()
            return
        if parsed.path in {
            "/api/v1/owner/summary",
            "/api/v1/owner/xdr/ocsf/device-inventory",
        }:
            if not _private_network_host(self.headers.get("Host")):
                self._json(404, {"error": "NOT_FOUND"})
                return
            if not _authorized(self.headers.get("Authorization"), _read_token()):
                self._json(401, {"error": "UNAUTHORIZED"})
                return
            try:
                payload = _owner_snapshot(DB) if parsed.path == "/api/v1/owner/summary" else _owner_xdr_snapshot(DB)
                self._json(200, payload)
            except (OSError, sqlite3.Error, ValueError):
                self._json(503, {"status": "UNAVAILABLE"})
            return
        if parsed.path == "/download/cyberdefender/manifest":
            try:
                self._json(200, _artifact_manifest())
            except OSError:
                self._json(503, {"error": "INSTALLER_NOT_CONFIGURED"})
            return
        if parsed.path == "/download/cyberdefender":
            if not _DOWNLOAD_LIMITER.allow("download:" + self._client_key()):
                self._json(429, {"error": "RATE_LIMITED"})
                return
            if not ARTIFACT.is_file():
                self._json(503, {"error": "INSTALLER_NOT_CONFIGURED"})
                return
            query = parse_qs(parsed.query)
            version = str((query.get("version") or [""])[0])[:64]
            channel = str((query.get("channel") or ["stable"])[0])[:32]
            repository = DistributionRepository(DB)
            download_id = repository.begin_download(artifact_name=ARTIFACT.name, version=version, channel=channel)
            sent = 0
            try:
                manifest = _artifact_manifest()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{ARTIFACT.name}"')
                self.send_header("Content-Length", str(manifest["size"]))
                self.send_header("X-CyberDefender-Download-ID", download_id)
                self.send_header("X-CyberDefender-SHA256", manifest["sha256"])
                self.send_header("Digest", manifest["digest"])
                self._security_headers()
                self.end_headers()
                with ARTIFACT.open("rb") as source:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        sent += len(chunk)
                repository.complete_download(download_id, bytes_sent=sent)
            except (BrokenPipeError, ConnectionResetError, OSError):
                repository.fail_download(download_id)
            finally:
                repository.close()
            return
        self._json(404, {"error": "NOT_FOUND"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        v2_endpoint = _v2_endpoint_path(parsed.path)
        if parsed.path == "/api/v2/enrollment" or v2_endpoint is not None:
            if not _cloud_v2_enabled():
                self._json(404, {"error": "NOT_FOUND"})
                return
            if self.headers.get_content_type().lower() != "application/json":
                self._json(415, {"error": "CONTENT_TYPE_REQUIRED"})
                return
            if not _AUTH_LIMITER.allow("cloud-v2:" + self._client_key()):
                self._json(429, {"error": "RATE_LIMITED"})
                return
            try:
                raw, body = self._body()
            except OverflowError:
                self.close_connection = True
                self._json(413, {"error": "REQUEST_TOO_LARGE"})
                return
            except ValueError:
                self._json(400, {"error": "INVALID_REQUEST"})
                return
            repository = CloudSocRepository(DB)
            try:
                if parsed.path == "/api/v2/enrollment":
                    self._json(201, repository.enroll(body, now=time.time()))
                    return
                service = CloudSocService(repository)
                endpoint_id, operation = v2_endpoint
                if operation == "heartbeat":
                    result = service.ingest_heartbeat(endpoint_id, raw, self.headers)
                else:
                    result = service.ingest_events(endpoint_id, raw, self.headers)
                self._json(200, result)
            except CloudSocError as exc:
                self._json(exc.status, {"error": exc.code})
            except sqlite3.Error:
                self._json(503, {"error": "STORAGE_UNAVAILABLE"})
            finally:
                repository.close()
            return
        if parsed.path not in {
            "/api/v1/enrollment/register",
            "/api/v1/endpoints/heartbeat",
            "/api/v1/endpoints/response-evidence",
        }:
            self._json(404, {"error": "NOT_FOUND"})
            return
        if self.headers.get_content_type().lower() != "application/json":
            self._json(415, {"error": "CONTENT_TYPE_REQUIRED"})
            return
        if not _AUTH_LIMITER.allow("fleet-auth:" + self._client_key()):
            self._json(429, {"error": "RATE_LIMITED"})
            return
        if not _authorized(self.headers.get("Authorization")):
            self._json(401, {"error": "UNAUTHORIZED"})
            return
        try:
            raw, body = self._body()
        except OverflowError:
            self.close_connection = True
            self._json(413, {"error": "REQUEST_TOO_LARGE"})
            return
        except ValueError:
            self._json(400, {"error": "INVALID_REQUEST"})
            return
        try:
            verified = verify_request(
                _token(), method="POST", path=parsed.path, body=raw, headers=self.headers, now=time.time()
            )
            contract = validate_ingest_contract(body, signed_timestamp=verified.timestamp)
            response_evidence = None
            if parsed.path == "/api/v1/endpoints/response-evidence":
                if CAPABILITY_RESPONSE_EVIDENCE not in contract["capabilities"]:
                    raise ValueError("response evidence capability required")
                response_evidence = validate_response_evidence(
                    body.get("response_evidence"), endpoint_id=contract["endpoint_id"]
                )
                response_evidence.pop("endpoint_id", None)
        except FleetProtocolError as exc:
            code = "STALE_REQUEST" if exc.code == "TIMESTAMP_OUT_OF_RANGE" else "UNAUTHORIZED"
            self._json(401, {"error": code})
            return
        except ValueError:
            self._json(400, {"error": "INVALID_TELEMETRY_CONTRACT"})
            return
        if not _WRITE_LIMITER.allow("fleet-write:" + contract["endpoint_id"]):
            self._json(429, {"error": "RATE_LIMITED"})
            return

        repository = DistributionRepository(DB)
        try:
            if not repository.accept_request_nonce(
                nonce=verified.nonce,
                endpoint_id=contract["endpoint_id"],
                observed_at=time.time(),
            ):
                self._json(409, {"error": "REPLAY_DETECTED"})
                return
            common = {
                "endpoint_id": contract["endpoint_id"],
                "hostname": contract["hostname"],
                "runtime_version": contract["runtime_version"],
                "telemetry_schema": contract["telemetry_schema"],
                "telemetry_schema_version": contract["telemetry_schema_version"],
                "capabilities": contract["capabilities"],
                "observed_at": contract["observed_at"],
            }
            if parsed.path == "/api/v1/enrollment/register":
                repository.register_endpoint(
                    **common,
                    download_id=body.get("download_id") or None,
                    install_state=body.get("install_state", "INSTALLED"),
                    health_state=body.get("health_state", "UNKNOWN"),
                    service_state=body.get("service_state", "REGISTERED"),
                )
                self._json(200, {"status": "REGISTERED"})
                return
            if parsed.path == "/api/v1/endpoints/response-evidence":
                repository.record_response_evidence(
                    response_evidence,
                    endpoint_id=contract["endpoint_id"],
                    observed_at=contract["observed_at"],
                )
                self._json(200, {"status": "EVIDENCE_ACCEPTED"})
                return
            repository.heartbeat(
                **common,
                health_state=body.get("health_state", "UNKNOWN"),
                service_state=body.get("service_state", "RUNNING"),
                resource_state=body.get("resource_state", "UNKNOWN"),
                last_error=body.get("last_error"),
            )
            self._json(200, {"status": "ACK"})
        except ValueError:
            self._json(400, {"error": "INVALID_REQUEST"})
        except sqlite3.IntegrityError:
            self._json(409, {"error": "STATE_CONFLICT"})
        except sqlite3.Error:
            self._json(503, {"error": "STORAGE_UNAVAILABLE"})
        finally:
            repository.close()


def serve() -> None:
    configured_token = _token()
    if configured_token:
        try:
            validate_token(configured_token)
        except FleetProtocolError as exc:
            raise RuntimeError("CYBERDEFENDER_FLEET_TOKEN must be a strong 32-512 byte ASCII secret") from exc
    DB.parent.mkdir(parents=True, exist_ok=True)
    _initialize_database(DB)
    print(f"CyberDefender Distribution telemetry: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    serve()
