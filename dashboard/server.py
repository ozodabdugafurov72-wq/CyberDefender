from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import mimetypes
import os
import secrets
import hashlib
import hmac
import time
import urllib.parse
import psutil

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "dashboard"
STATE_ROOT = Path(os.environ.get("CYBERDEFENDER_STATE_DIR", ROOT / "state")).expanduser().resolve()
if os.environ.get("CYBERDEFENDER_LOG_DIR"):
    LOG_ROOT = Path(os.environ["CYBERDEFENDER_LOG_DIR"]).expanduser().resolve()
elif os.environ.get("CYBERDEFENDER_STATE_DIR"):
    LOG_ROOT = STATE_ROOT / "logs"
else:
    LOG_ROOT = ROOT / "logs"
LOG_FILE = LOG_ROOT / "events.jsonl"
STATE_FILE = STATE_ROOT / "state.json"
RUNTIME_STATE_FILE = STATE_ROOT / "dashboard_runtime.json"
RUNTIME_STALE_AFTER = 15.0

HOST = "127.0.0.1"
PORT = int(os.environ.get("CYBERDEFENDER_DASHBOARD_PORT", "8765"))

# Local dashboard authentication. No credential is embedded in source.
# Set CYBERDEFENDER_DASHBOARD_PASSWORD before starting this legacy monitor.
ADMIN_PASSWORD = os.environ.get("CYBERDEFENDER_DASHBOARD_PASSWORD")

SESSION_TOKEN = secrets.token_urlsafe(32)
SESSION_CREATED = 0
SESSION_TTL = 3600


def make_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


ADMIN_PASSWORD_HASH = make_hash(ADMIN_PASSWORD) if ADMIN_PASSWORD else None


def authenticated(handler):
    cookie = handler.headers.get("Cookie", "")

    token = None

    for item in cookie.split(";"):
        item = item.strip()
        if item.startswith("cd_session="):
            token = item.split("=", 1)[1]

    if not token:
        return False

    if not hmac.compare_digest(token, SESSION_TOKEN):
        return False

    if SESSION_CREATED and time.time() - SESSION_CREATED > SESSION_TTL:
        return False

    return True


def _read_jsonl_tail(path: Path, requested: int, byte_budget: int):
    if requested <= 0 or byte_budget <= 0 or not path.is_file():
        return [], 0

    consumed = 0
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            position = f.tell()
            buffer = b""
            chunk_size = 64 * 1024

            while position > 0 and buffer.count(b"\n") <= requested and len(buffer) < byte_budget:
                read_size = min(chunk_size, position, byte_budget - len(buffer))
                if read_size <= 0:
                    break
                position -= read_size
                f.seek(position)
                chunk = f.read(read_size)
                consumed += len(chunk)
                buffer = chunk + buffer

        lines = buffer.splitlines()
        if position > 0 and lines:
            lines = lines[1:]
    except OSError:
        return [], consumed

    events = []
    for raw in reversed(lines[-requested:]):
        try:
            item = json.loads(raw.decode("utf-8"))
            if isinstance(item, dict):
                events.append(item)
        except (UnicodeDecodeError, ValueError, TypeError):
            continue
    return events, consumed


def read_events(limit=100):
    """Read a bounded live view across active and rotated evidence logs."""
    requested = max(1, min(int(limit), 500))
    max_tail_bytes = 2 * 1024 * 1024
    try:
        backup_count = int(os.environ.get("CYBERDEFENDER_EVENT_LOG_BACKUP_COUNT", "6"))
    except (TypeError, ValueError):
        backup_count = 6
    backup_count = max(0, min(backup_count, 64))

    paths = [LOG_FILE] + [
        LOG_FILE.with_name(f"{LOG_FILE.name}.{index}")
        for index in range(1, backup_count + 1)
    ]

    events = []
    remaining = requested
    budget = max_tail_bytes
    for path in paths:
        if remaining <= 0 or budget <= 0:
            break
        chunk, consumed = _read_jsonl_tail(path, remaining, budget)
        events.extend(chunk)
        remaining = requested - len(events)
        budget = max(0, budget - consumed)

    # Legacy monitor historically displayed oldest-to-newest within its
    # selected window, so preserve that presentation contract.
    return list(reversed(events[:requested]))

def read_state():
    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def read_runtime_state():
    """
    Read the agent-owned dashboard snapshot.

    Dashboard is read-only. It never controls the runtime.
    RuntimeStatePublisher atomically replaces this file.
    """
    if not RUNTIME_STATE_FILE.exists():
        return {}

    try:
        with RUNTIME_STATE_FILE.open(
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

        return data if isinstance(data, dict) else {}

    except Exception:
        return {}


def runtime_freshness(runtime_state):
    publisher = runtime_state.get(
        "publisher",
        {},
    )

    if not isinstance(publisher, dict):
        publisher = {}

    generated_at = publisher.get(
        "generated_at"
    )

    try:
        age = max(
            0.0,
            time.time()
            - float(generated_at),
        )
    except (TypeError, ValueError):
        return {
            "available": False,
            "stale": True,
            "age_seconds": None,
        }

    return {
        "available": True,
        "stale": (
            age > RUNTIME_STALE_AFTER
        ),
        "age_seconds": round(
            age,
            2,
        ),
    }


def runtime_system_data(
    runtime_state,
):
    observation = runtime_state.get(
        "observation",
        {},
    )

    if not isinstance(
        observation,
        dict,
    ):
        observation = {}

    return {
        "cpu": observation.get(
            "cpu_percent"
        ),
        "memory": observation.get(
            "memory_percent"
        ),
        "memory_available_mb":
            observation.get(
                "memory_available_mb"
            ),
        "disk": observation.get(
            "disk_percent"
        ),
        "processes": observation.get(
            "process_count"
        ),
        "network": {
            "sent_mb": observation.get(
                "network_sent_mb"
            ),
            "received_mb": observation.get(
                "network_recv_mb"
            ),
        },
    }


def dashboard_data():
    events = read_events()
    state = read_state()
    runtime_state = read_runtime_state()

    freshness = runtime_freshness(
        runtime_state
    )

    runtime = runtime_state.get(
        "runtime",
        {},
    )

    health = runtime_state.get(
        "health",
        {},
    )

    incidents = runtime_state.get(
        "incidents",
        [],
    )

    if not isinstance(runtime, dict):
        runtime = {}

    if not isinstance(health, dict):
        health = {}

    if not isinstance(incidents, list):
        incidents = []

    runtime_health = health.get(
        "runtime",
        {},
    )

    if not isinstance(
        runtime_health,
        dict,
    ):
        runtime_health = {}

    # Never claim PROTECTED when the
    # real agent has no fresh signal.
    if not freshness["available"]:
        status = "AGENT_OFFLINE"

    elif freshness["stale"]:
        status = "STALE"

    else:
        status = (
            runtime_health.get("status")
            or runtime.get("status")
            or "UNKNOWN"
        )

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for incident in incidents:
        if not isinstance(
            incident,
            dict,
        ):
            continue

        severity = str(
            incident.get(
                "severity",
                "INFO",
            )
        ).strip().upper()

        # Incident severity is authoritative.
        # Never infer severity from event names such as HIGH_MEMORY_USAGE.
        if severity == "CRITICAL":
            counts["critical"] += 1
        elif severity == "HIGH":
            counts["high"] += 1
        elif severity in ("MEDIUM", "WARNING"):
            counts["medium"] += 1
        elif severity in ("LOW", "INFO"):
            counts["low" if severity == "LOW" else "info"] += 1

    return {
        "status": status,
        "timestamp": time.time(),

        # Agent-owned runtime state.
        "runtime": runtime,
        "health": health,
        "observation":
            runtime_state.get(
                "observation",
                {},
            ),
        "incidents": incidents,
        "runtime_freshness":
            freshness,

        # Compatibility with the
        # existing dashboard layout.
        "system":
            runtime_system_data(
                runtime_state
            ),

        "alerts": {
            "total": len(incidents),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "info": counts["info"],
        },

        # Historical forensic stream.
        "events": events[:25],
        "state": state,
    }


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def send_bytes(self, data, content_type, status=200):
        try:
            self.send_response(status)
            self.send_header(
                "Content-Type",
                content_type,
            )
            self.send_header(
                "Content-Length",
                str(len(data)),
            )
            self.send_header(
                "Cache-Control",
                "no-store",
            )
            self.end_headers()
            self.wfile.write(data)
            return True

        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
        ):
            return False

        except OSError as exc:
            if getattr(
                exc,
                "winerror",
                None,
            ) in (
                10053,
                10054,
            ):
                return False

            raise

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):

        global SESSION_CREATED

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/":
            if authenticated(self):
                self.redirect("/dashboard")
            else:
                self.redirect("/login")
            return

        if path == "/login":
            data = (DASHBOARD / "templates" / "login.html").read_bytes()
            self.send_bytes(data, "text/html; charset=utf-8")
            return

        if path == "/dashboard":
            if not authenticated(self):
                self.redirect("/login")
                return

            data = (DASHBOARD / "static" / "dashboard.html").read_bytes()
            self.send_bytes(data, "text/html; charset=utf-8")
            return

        if path == "/api/status":
            if not authenticated(self):
                self.send_bytes(
                    b'{"error":"UNAUTHORIZED"}',
                    "application/json",
                    401
                )
                return

            payload = json.dumps(
                dashboard_data(),
                ensure_ascii=False
            ).encode("utf-8")

            self.send_bytes(
                payload,
                "application/json; charset=utf-8"
            )
            return

        if path == "/api/logout":
            SESSION_CREATED = 0

            self.send_response(302)
            self.send_header("Set-Cookie", "cd_session=; Max-Age=0; HttpOnly; SameSite=Strict")
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if path.startswith("/static/"):
            relative = path[len("/static/"):]

            target = (DASHBOARD / "static" / relative).resolve()

            static_root = (DASHBOARD / "static").resolve()

            if not str(target).startswith(str(static_root)):
                self.send_bytes(b"Forbidden", "text/plain", 403)
                return

            if not target.exists() or not target.is_file():
                self.send_bytes(b"Not Found", "text/plain", 404)
                return

            content_type = mimetypes.guess_type(str(target))[0]
            content_type = content_type or "application/octet-stream"

            self.send_bytes(
                target.read_bytes(),
                content_type
            )
            return

        self.send_bytes(b"Not Found", "text/plain", 404)

    def do_POST(self):

        global SESSION_TOKEN
        global SESSION_CREATED

        parsed = urllib.parse.urlparse(self.path)

        if parsed.path != "/login":
            self.send_bytes(b"Not Found", "text/plain", 404)
            return

        length = int(self.headers.get("Content-Length", "0"))

        raw = self.rfile.read(length)

        try:
            form = urllib.parse.parse_qs(
                raw.decode("utf-8")
            )
        except Exception:
            self.redirect("/login")
            return

        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        password_hash = make_hash(password)

        if (
            ADMIN_PASSWORD_HASH is not None
            and username == "admin"
            and hmac.compare_digest(
                password_hash,
                ADMIN_PASSWORD_HASH
            )
        ):
            SESSION_TOKEN = secrets.token_urlsafe(32)
            SESSION_CREATED = time.time()

            self.send_response(302)
            self.send_header(
                "Set-Cookie",
                f"cd_session={SESSION_TOKEN}; HttpOnly; SameSite=Strict; Path=/"
            )
            self.send_header("Location", "/dashboard")
            self.end_headers()
            return

        self.send_response(302)
        self.send_header("Location", "/login?error=1")
        self.end_headers()


def main():
    if ADMIN_PASSWORD_HASH is None:
        raise RuntimeError(
            "CYBERDEFENDER_DASHBOARD_PASSWORD is required; "
            "hardcoded/default dashboard passwords are forbidden."
        )

    print("========================================")
    print(" CyberDefender Admin Dashboard")
    print("========================================")
    print()
    print(f"Dashboard: http://{HOST}:{PORT}")
    print("Authentication: ENABLED")
    print("Mode: LOCAL ADMIN DEMO")
    print()
    print("Press CTRL+C to stop.")
    print()

    server = ThreadingHTTPServer(
        (HOST, PORT),
        Handler
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("Dashboard stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

# ============================================================

