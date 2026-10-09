from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from control_plane.distribution_repository import DistributionRepository

HOST = os.getenv("CYBERDEFENDER_DISTRIBUTION_HOST", "127.0.0.1")
PORT = int(os.getenv("PORT") or os.getenv("CYBERDEFENDER_DISTRIBUTION_PORT", "8785"))
DB = Path(os.getenv("CYBERDEFENDER_DISTRIBUTION_DB", Path(os.getenv("LOCALAPPDATA", ".")) / "CyberDefender" / "state" / "control_plane" / "distribution.db")).expanduser().resolve()
_default_base = Path(os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA") or ".") / "CyberDefender"
_default_artifact = _default_base / "distribution" / "CyberDefenderPackage.zip"
ARTIFACT = Path(os.getenv("CYBERDEFENDER_INSTALLER_PATH", str(_default_artifact))).expanduser().resolve()
TOKEN_FILE = Path(os.getenv("CYBERDEFENDER_FLEET_TOKEN_FILE", Path(os.getenv("LOCALAPPDATA", ".")) / "CyberDefender" / "secrets" / "fleet_token.txt")).expanduser().resolve()
MAX_BODY = 64 * 1024
_MANIFEST_LOCK = threading.RLock()
_MANIFEST_CACHE: tuple[tuple[str, int, int], dict] | None = None


def _token() -> str:
    if os.getenv("CYBERDEFENDER_FLEET_TOKEN"):
        return os.environ["CYBERDEFENDER_FLEET_TOKEN"].strip()
    try: return TOKEN_FILE.read_text(encoding="ascii").strip()
    except OSError: return ""


def _read_token() -> str:
    return os.getenv("CYBERDEFENDER_DISTRIBUTION_READ_TOKEN", "").strip()


def _authorized(value: str | None, expected: str | None = None) -> bool:
    expected = _token() if expected is None else str(expected).strip()
    if not expected or not value or not value.startswith("Bearer "): return False
    return hmac.compare_digest(expected, value[7:].strip())


def _private_network_host(value: str | None) -> bool:
    host = str(value or "").strip().lower()
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
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


def _owner_snapshot(db_path: Path, *, online_after_seconds: float = 90.0) -> dict:
    if not db_path.is_file():
        raise FileNotFoundError(str(db_path))
    uri = "file:" + quote(db_path.as_posix(), safe="/:") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA busy_timeout=1000")
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
                   first_seen, last_seen
            FROM fleet_endpoints ORDER BY last_seen DESC LIMIT 100
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
                "endpoints_total", "installed", "pending", "install_failed",
                "revoked", "online", "offline", "degraded", "critical",
            )
        }
    )
    return {"status": "HEALTHY", "summary": summary, "endpoints": [dict(row) for row in rows], "read_only": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberDefender"
    sys_version = ""
    def log_message(self, format, *args): return

    def _json(self, status: int, payload: dict):
        raw = json.dumps(payload, separators=(",",":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(raw)

    def _body(self) -> dict:
        try: length = int(self.headers.get("Content-Length", "0"))
        except ValueError: length = 0
        if length <= 0 or length > MAX_BODY: return {}
        try:
            obj = json.loads(self.rfile.read(length).decode("utf-8"))
            return obj if isinstance(obj, dict) else {}
        except Exception: return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._json(200, {"name": "CyberDefender", "health": "/health",
                             "download": "/download/cyberdefender",
                             "manifest": "/download/cyberdefender/manifest"}); return
        if parsed.path == "/health":
            self._json(200,{"status":"ok"}); return
        if parsed.path == "/api/v1/owner/summary":
            if not _private_network_host(self.headers.get("Host")):
                self._json(404,{"error":"NOT_FOUND"}); return
            if not _authorized(self.headers.get("Authorization"), _read_token()):
                self._json(401,{"error":"UNAUTHORIZED"}); return
            try:
                self._json(200,_owner_snapshot(DB))
            except (OSError, sqlite3.Error):
                self._json(503,{"status":"UNAVAILABLE"})
            return
        if parsed.path == "/download/cyberdefender/manifest":
            try:
                self._json(200,_artifact_manifest())
            except OSError:
                self._json(503,{"error":"INSTALLER_NOT_CONFIGURED"})
            return
        if parsed.path == "/download/cyberdefender":
            if ARTIFACT is None or not ARTIFACT.is_file():
                self._json(503,{"error":"INSTALLER_NOT_CONFIGURED"}); return
            q = parse_qs(parsed.query)
            version = str((q.get("version") or [""])[0])[:64]
            channel = str((q.get("channel") or ["stable"])[0])[:32]
            repo = DistributionRepository(DB)
            download_id = repo.begin_download(artifact_name=ARTIFACT.name, version=version, channel=channel)
            sent = 0
            try:
                manifest = _artifact_manifest()
                size = manifest["size"]
                self.send_response(200); self.send_header("Content-Type","application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{ARTIFACT.name}"')
                self.send_header("Content-Length", str(size)); self.send_header("X-CyberDefender-Download-ID", download_id)
                self.send_header("X-CyberDefender-SHA256", manifest["sha256"])
                self.send_header("Digest", manifest["digest"])
                self.send_header("Cache-Control","no-store"); self.end_headers()
                with ARTIFACT.open("rb") as f:
                    while True:
                        chunk = f.read(64*1024)
                        if not chunk: break
                        self.wfile.write(chunk); sent += len(chunk)
                repo.complete_download(download_id, bytes_sent=sent)
            except (BrokenPipeError, ConnectionResetError, OSError):
                repo.fail_download(download_id)
            finally:
                repo.close()
            return
        self._json(404,{"error":"NOT_FOUND"})

    def do_POST(self):
        if not _authorized(self.headers.get("Authorization")):
            self._json(401,{"error":"UNAUTHORIZED"}); return
        body = self._body(); repo = DistributionRepository(DB)
        try:
            if self.path == "/api/v1/enrollment/register":
                repo.register_endpoint(endpoint_id=body.get("endpoint_id",""), hostname=body.get("hostname","unknown"),
                    download_id=body.get("download_id") or None, runtime_version=body.get("runtime_version",""),
                    install_state=body.get("install_state","INSTALLED"), health_state=body.get("health_state","UNKNOWN"),
                    service_state=body.get("service_state","REGISTERED"))
                self._json(200,{"status":"REGISTERED"}); return
            if self.path == "/api/v1/endpoints/heartbeat":
                repo.heartbeat(endpoint_id=body.get("endpoint_id",""), hostname=body.get("hostname","unknown"),
                    runtime_version=body.get("runtime_version",""), health_state=body.get("health_state","UNKNOWN"),
                    service_state=body.get("service_state","RUNNING"), resource_state=body.get("resource_state",""),
                    last_error=body.get("last_error"))
                self._json(200,{"status":"ACK"}); return
            self._json(404,{"error":"NOT_FOUND"})
        except (ValueError, sqlite3.Error) as exc:
            self._json(400,{"error":type(exc).__name__})
        finally:
            repo.close()


def serve() -> None:
    DB.parent.mkdir(parents=True, exist_ok=True)
    print(f"CyberDefender Distribution telemetry: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST,PORT), Handler).serve_forever()

if __name__ == "__main__": serve()
