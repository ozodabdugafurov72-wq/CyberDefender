from __future__ import annotations

import hmac
import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from control_plane.distribution_repository import DistributionRepository

HOST = os.getenv("CYBERDEFENDER_DISTRIBUTION_HOST", "127.0.0.1")
PORT = int(os.getenv("CYBERDEFENDER_DISTRIBUTION_PORT", "8785"))
DB = Path(os.getenv("CYBERDEFENDER_DISTRIBUTION_DB", Path(os.getenv("LOCALAPPDATA", ".")) / "CyberDefender" / "state" / "control_plane" / "distribution.db")).expanduser().resolve()
_default_base = Path(os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA") or ".") / "CyberDefender"
_default_artifact = _default_base / "distribution" / "CyberDefenderPackage.zip"
ARTIFACT = Path(os.getenv("CYBERDEFENDER_INSTALLER_PATH", str(_default_artifact))).expanduser().resolve()
TOKEN_FILE = Path(os.getenv("CYBERDEFENDER_FLEET_TOKEN_FILE", Path(os.getenv("LOCALAPPDATA", ".")) / "CyberDefender" / "secrets" / "fleet_token.txt")).expanduser().resolve()
MAX_BODY = 64 * 1024


def _token() -> str:
    try: return TOKEN_FILE.read_text(encoding="ascii").strip()
    except OSError: return ""


def _authorized(value: str | None) -> bool:
    expected = _token()
    if not expected or not value or not value.startswith("Bearer "): return False
    return hmac.compare_digest(expected, value[7:].strip())


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberDefenderDistribution/0.1"
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
        if parsed.path == "/health":
            self._json(200,{"status":"HEALTHY","component":"DistributionServer","version":"0.1"}); return
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
                size = ARTIFACT.stat().st_size
                self.send_response(200); self.send_header("Content-Type","application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{ARTIFACT.name}"')
                self.send_header("Content-Length", str(size)); self.send_header("X-CyberDefender-Download-ID", download_id)
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
