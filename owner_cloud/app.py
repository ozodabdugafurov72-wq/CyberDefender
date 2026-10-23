from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import json
import time
import uuid
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlparse

from owner_cloud.config import Config
from owner_cloud.distribution_client import DistributionClient
from owner_cloud.security import (
    ROLE_ADMIN,
    ROLE_OWNER,
    SlidingWindowLimiter,
    new_token,
    token_hash,
    verify_password,
)
from owner_cloud.store import OwnerStore
from owner_cloud.totp import verify as verify_totp


STATIC_ROOT = Path(__file__).resolve().parent / "static"
MAX_FORM_BODY = 16 * 1024


@dataclass(frozen=True)
class Request:
    method: str
    target: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    peer_ip: str = ""

    @property
    def path(self) -> str:
        return urlparse(self.target).path

    def header(self, name: str) -> str:
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return str(value)
        return ""


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: list[tuple[str, str]] = field(default_factory=list)

    def add_header(self, name: str, value: str) -> "Response":
        self.headers.append((name, value))
        return self

    def values(self, name: str) -> list[str]:
        return [value for key, value in self.headers if key.lower() == name.lower()]


class Application:
    def __init__(
        self,
        config: Config,
        *,
        store: OwnerStore | None = None,
        distribution: DistributionClient | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config.validate()
        self.store = store or OwnerStore(config.db_path)
        self.distribution = distribution or DistributionClient(
            config.distribution_private_url,
            config.distribution_read_token,
            tenant_id=config.tenant_id,
        )
        self.clock = clock
        self.login_limiter = SlidingWindowLimiter(
            limit=config.login_rate_limit,
            window_seconds=60,
            clock=clock,
        )
        self.api_limiter = SlidingWindowLimiter(
            limit=config.api_rate_limit,
            window_seconds=60,
            clock=clock,
        )
        self._dummy_password_hash = next(iter(config.accounts.values())).password_hash

    def handle(self, request: Request) -> Response:
        request_id = uuid.uuid4().hex
        try:
            response = self._dispatch(request, request_id)
        except Exception:
            response = self._json(500, {"error": "INTERNAL_ERROR", "request_id": request_id})
        return self._finalize(response, request_id)

    def _dispatch(self, request: Request, request_id: str) -> Response:
        method = request.method.upper()
        path = request.path
        if path != "/health" and not self._valid_host(request.header("Host")):
            return self._json(400, {"error": "INVALID_HOST"})
        if self.config.production_like and path != "/health":
            if request.header("X-Forwarded-Proto").lower() != "https":
                return self._json(400, {"error": "HTTPS_REQUIRED"})

        if method == "GET" and path == "/health":
            try:
                healthy = self.store.health()
            except Exception:
                healthy = False
            return self._json(200 if healthy else 503, {"status": "ok" if healthy else "unavailable"})
        if method == "GET" and path in {"/static/app.css", "/static/response.css", "/static/app.js"}:
            return self._static(path)
        if method == "GET" and path == "/login":
            return self._login_page()
        if method == "POST" and path == "/login":
            return self._login(request, request_id)

        session = self._session(request)
        if session is None:
            if method == "GET" and path in {"/", "/owner", "/admin"}:
                return self._redirect("/login")
            self._audit(request_id, "anonymous", "", "authentication", "DENIED", request, path[:128])
            return self._json(401, {"error": "AUTHENTICATION_REQUIRED"})
        if not self.api_limiter.allow("session:" + session["token_hash"]):
            self._audit(request_id, session["username"], session["role"], "api.rate_limit", "DENIED", request, path[:128])
            return self._json(429, {"error": "RATE_LIMITED"}).add_header("Retry-After", "60")

        if method == "GET" and path == "/":
            return self._redirect("/owner" if session["role"] == ROLE_OWNER else "/admin")
        if method == "GET" and path == "/owner":
            if session["role"] != ROLE_OWNER:
                return self._forbidden(request_id, session, request, "owner.page.read")
            return self._dashboard_page(session, surface="owner")
        if method == "GET" and path == "/admin":
            if session["role"] != ROLE_ADMIN:
                return self._forbidden(request_id, session, request, "admin.page.read")
            return self._dashboard_page(session, surface="admin")
        if method == "GET" and path == "/api/v1/session":
            return self._json(
                200,
                {
                    "username": session["username"],
                    "role": session["role"],
                    "read_only": True,
                    "expires_at": session["expires_at"],
                },
            )
        if method == "GET" and path in {"/api/v1/state", "/api/v1/owner/state", "/api/v1/admin/state"}:
            expected_role = None
            if path == "/api/v1/owner/state":
                expected_role = ROLE_OWNER
            elif path == "/api/v1/admin/state":
                expected_role = ROLE_ADMIN
            if expected_role is not None and session["role"] != expected_role:
                return self._forbidden(request_id, session, request, f"{expected_role.lower()}.state.read")
            return self._json(200, self._state_payload(session))
        if method == "GET" and path == "/api/v1/audit":
            if session["role"] != ROLE_OWNER:
                return self._forbidden(request_id, session, request, "audit.read")
            return self._json(200, {"events": self.store.recent_audit(100), "read_only": True})
        if method == "POST" and path == "/logout":
            if not self._valid_session_csrf(request, session):
                return self._forbidden(request_id, session, request, "session.logout.csrf")
            self.store.revoke_session(session["token_hash"], now=float(self.clock()))
            self._audit(request_id, session["username"], session["role"], "session.logout", "SUCCESS", request)
            return self._redirect("/login").add_header(
                "Set-Cookie", self._delete_cookie(self.config.session_cookie_name)
            )
        if method == "POST" and path.startswith("/api/v1/actions/"):
            if not self._valid_session_csrf(request, session):
                return self._forbidden(request_id, session, request, "action.csrf")
            self._audit(
                request_id,
                session["username"],
                session["role"],
                "privileged_action",
                "DENIED_READ_ONLY",
                request,
                path[:128],
            )
            return self._json(403, {"error": "READ_ONLY_MODE"})
        return self._json(404, {"error": "NOT_FOUND"})

    def _valid_host(self, raw_host: str) -> bool:
        host = raw_host.strip().lower()
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        else:
            host = host.split(":", 1)[0]
        return bool(host and host in self.config.allowed_hosts)

    def _cookies(self, request: Request) -> dict[str, str]:
        raw = request.header("Cookie")
        if not raw:
            return {}
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            return {}
        return {name: morsel.value for name, morsel in cookie.items()}

    def _client_hash(self, request: Request) -> str:
        candidate = request.peer_ip.strip() or "unknown"
        real_ip = request.header("X-Real-IP").strip()
        if real_ip:
            try:
                candidate = ipaddress.ip_address(real_ip).compressed
            except ValueError:
                pass
        return hashlib.sha256(candidate.encode("utf-8", "replace")).hexdigest()

    def _session(self, request: Request) -> dict | None:
        raw_token = self._cookies(request).get(self.config.session_cookie_name, "")
        if len(raw_token) < 32:
            return None
        hashed = token_hash(raw_token)
        session = self.store.get_session(
            hashed,
            now=float(self.clock()),
            idle_seconds=self.config.session_idle_seconds,
        )
        if session is None:
            return None
        account = self.config.accounts.get(str(session["username"]))
        if account is None or not account.enabled or account.role != session["role"]:
            self.store.revoke_session(hashed, now=float(self.clock()))
            return None
        session["token_hash"] = hashed
        return session

    def _form(self, request: Request) -> dict[str, str]:
        if len(request.body) > MAX_FORM_BODY:
            return {}
        content_type = request.header("Content-Type").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            return {}
        try:
            values = parse_qs(
                request.body.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=12,
            )
        except (UnicodeDecodeError, ValueError):
            return {}
        return {key: str(items[0])[:4096] for key, items in values.items() if items}

    def _login_page(self, *, status: int = 200, error: str = "") -> Response:
        csrf_token = new_token()
        safe_error = html.escape(error)
        error_html = f'<p class="error" role="alert">{safe_error}</p>' if safe_error else ""
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TENQORVA Secure Login</title><link rel="stylesheet" href="/static/app.css"></head>
<body class="login-body"><main class="login-card"><div class="brand-mark">TQ</div>
<p class="eyebrow">TENQORVA · CYBERDEFENDER CONTROL PLANE</p><h1>Secure access</h1>
<p class="muted">Authorized Owner and Admin accounts only.</p>{error_html}
<form method="post" action="/login" autocomplete="on">
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
<label>Username<input name="username" maxlength="64" autocomplete="username" required></label>
<label>Password<input type="password" name="password" maxlength="256" autocomplete="current-password" required></label>
<label>Authenticator code<input name="otp" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" required></label>
<button type="submit">Sign in securely</button></form>
<p class="guard">Fail-closed · audited · read-only</p></main></body></html>"""
        return self._html(status, page).add_header(
            "Set-Cookie",
            self._cookie(self.config.preauth_cookie_name, csrf_token, max_age=600),
        )

    def _login(self, request: Request, request_id: str) -> Response:
        client_hash = self._client_hash(request)
        if not self.login_limiter.allow("login:" + client_hash):
            self._audit(request_id, "unknown", "", "session.login", "RATE_LIMITED", request)
            return self._json(429, {"error": "RATE_LIMITED"}).add_header("Retry-After", "60")
        form = self._form(request)
        username = form.get("username", "").strip().lower()[:64]
        password = form.get("password", "")
        otp = form.get("otp", "")
        csrf_token = form.get("csrf_token", "")
        preauth = self._cookies(request).get(self.config.preauth_cookie_name, "")
        if not csrf_token or not preauth or not hmac.compare_digest(token_hash(csrf_token), token_hash(preauth)):
            self._audit(request_id, username or "unknown", "", "session.login", "CSRF_DENIED", request)
            return self._login_page(status=403, error="The login form expired. Try again.")
        subject_hash = token_hash(username or "unknown")
        allowed, locked_until = self.store.login_allowed(subject_hash, client_hash, now=float(self.clock()))
        if not allowed:
            retry = max(1, int(locked_until - float(self.clock())))
            self._audit(request_id, username or "unknown", "", "session.login", "LOCKED", request)
            return self._json(429, {"error": "LOGIN_LOCKED"}).add_header("Retry-After", str(retry))
        account = self.config.accounts.get(username)
        password_hash = account.password_hash if account is not None else self._dummy_password_hash
        password_ok = verify_password(password, password_hash)
        mfa_secret = self.config.mfa_secrets.get(username, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
        mfa_counter = verify_totp(mfa_secret, otp, now=float(self.clock()))
        mfa_ok = account is not None and account.enabled and password_ok and mfa_counter is not None
        if mfa_ok:
            mfa_ok = self.store.consume_mfa_counter(account.username, mfa_counter, now=float(self.clock()))
        if account is None or not account.enabled or not password_ok or not mfa_ok:
            locked_until = self.store.record_login_failure(
                subject_hash,
                client_hash,
                now=float(self.clock()),
                window_seconds=self.config.login_failure_window_seconds,
                failure_limit=self.config.login_failure_limit,
                lock_seconds=self.config.login_lock_seconds,
            )
            self._audit(request_id, username or "unknown", "", "session.login", "DENIED", request)
            if locked_until > float(self.clock()):
                return self._json(429, {"error": "LOGIN_LOCKED"}).add_header(
                    "Retry-After", str(self.config.login_lock_seconds)
                )
            return self._login_page(status=401, error="Invalid credentials or authenticator code.")

        now = float(self.clock())
        self.store.clear_login_failures(subject_hash, client_hash)
        session_token, session_csrf = new_token(), new_token()
        self.store.create_session(
            token_hash=token_hash(session_token),
            csrf_hash=token_hash(session_csrf),
            username=account.username,
            role=account.role,
            now=now,
            expires_at=now + self.config.session_ttl_seconds,
            mfa_verified_at=now,
        )
        self._audit(request_id, account.username, account.role, "session.login", "SUCCESS", request)
        return (
            self._redirect("/owner" if account.role == ROLE_OWNER else "/admin")
            .add_header(
                "Set-Cookie",
                self._cookie(
                    self.config.session_cookie_name,
                    session_token,
                    max_age=self.config.session_ttl_seconds,
                ),
            )
            .add_header("Set-Cookie", self._delete_cookie(self.config.preauth_cookie_name))
        )

    def _valid_session_csrf(self, request: Request, session: dict) -> bool:
        provided = request.header("X-CSRF-Token")
        if not provided:
            provided = self._form(request).get("csrf_token", "")
        return bool(provided and hmac.compare_digest(token_hash(provided), str(session["csrf_hash"])))

    def _state_payload(self, session: dict) -> dict:
        upstream = self.distribution.state()
        capabilities = upstream.get("capabilities", {}) if isinstance(upstream, dict) else {}
        available = isinstance(upstream, dict) and upstream.get("status") == "HEALTHY"
        return {
            "status": "HEALTHY" if available else "UNAVAILABLE",
            "mode": "READ_ONLY",
            "environment": self.config.environment,
            "surface": session["role"].lower(),
            "actor": {"username": session["username"], "role": session["role"]},
            "distribution": upstream,
            "integrations": {
                "endpoint_diagnostics": {
                    "status": "AVAILABLE" if capabilities.get("endpoint_diagnostics") else "UNAVAILABLE",
                    "reason": "" if capabilities.get("endpoint_diagnostics") else "NOT_EXPOSED_BY_FLEET_API",
                },
                "event_investigation": {
                    "status": "AVAILABLE" if capabilities.get("event_investigation") else "UNAVAILABLE",
                    "reason": "" if capabilities.get("event_investigation") else "NOT_EXPOSED_BY_FLEET_API",
                },
                "quarantine_detail": {
                    "status": "EVENT_METADATA_ONLY" if capabilities.get("event_investigation") else "UNAVAILABLE",
                    "reason": "NO_AUTHENTICATED_QUARANTINE_DETAIL_API",
                },
                "sensor_plane": {"status": "UNAVAILABLE", "reason": "NO_AUTHENTICATED_SENSOR_API"},
                "process_graph": {"status": "UNAVAILABLE", "reason": "NO_AUTHENTICATED_PROCESSGRAPH_API"},
                "persistence_detail": {"status": "UNAVAILABLE", "reason": "NO_AUTHENTICATED_PERSISTENCE_API"},
            },
            "security": {
                "authentication": "ENFORCED",
                "mfa": "TOTP_ENFORCED",
                "server_side_rbac": "ENFORCED",
                "csrf": "ENFORCED",
                "privileged_actions": "DISABLED_READ_ONLY",
                "risk_is_authorization": False,
                "secure_session_cookie": self.config.secure_cookies,
            },
        }

    def _dashboard_page(self, session: dict, *, surface: str) -> Response:
        csrf_token = new_token()
        if not self.store.rotate_session_csrf(session["token_hash"], token_hash(csrf_token)):
            return self._json(401, {"error": "AUTHENTICATION_REQUIRED"})
        title = "Owner command view" if surface == "owner" else "Admin operations view"
        eyebrow = "OWNER SECURITY CONTROL" if surface == "owner" else "ADMIN OPERATIONS"
        state_url = f"/api/v1/{surface}/state"
        audit_panel = """
<section class="panel owner-only" id="auditPanel"><div class="panel-title"><div><p class="kicker">OWNER ONLY</p><h2>Security access audit</h2></div><span id="auditStatus" class="status loading">LOADING</span></div><div id="audit" class="table-shell"><p class="empty">Loading audited access events…</p></div></section>""" if surface == "owner" else ""
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TENQORVA · {html.escape(title)}</title><link rel="stylesheet" href="/static/app.css"></head>
<body><header class="topbar"><a class="brand" href="/{surface}" aria-label="TENQORVA {surface} dashboard"><span class="brand-mark small">TQ</span><span><b>TENQORVA</b><small>CyberDefender control plane</small></span></a>
<nav aria-label="Dashboard sections"><a href="#overview">Overview</a><a href="#fleet">Fleet</a><a href="#events">Events</a><a href="#diagnostics">Diagnostics</a></nav>
<div class="identity"><span>{html.escape(session["username"])}</span><strong>{html.escape(session["role"])}</strong><form method="post" action="/logout">
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
<button class="ghost" type="submit">Logout</button></form></div></header>
<main class="dashboard" data-role="{html.escape(session["role"], quote=True)}" data-surface="{surface}" data-state-url="{state_url}">
<section class="hero" id="overview"><div><p class="eyebrow">{eyebrow}</p><h1>{html.escape(title)}</h1><p>Authenticated, tenant-scoped visibility through the Railway private service boundary.</p></div><div class="read-only-seal"><span>CONTROL MODE</span><b>READ ONLY</b><small>No endpoint actions enabled</small></div></section>
<div id="globalState" class="notice loading" role="status">Loading authenticated fleet state…</div>
<section class="metric-grid" aria-label="Fleet metrics"><article><span>Registered</span><b id="endpoints">—</b><small>tenant endpoints</small></article><article class="good"><span>Online</span><b id="online">—</b><small>verified heartbeat</small></article><article><span>Offline</span><b id="offline">—</b><small>outside freshness window</small></article><article class="warn"><span>Degraded</span><b id="degraded">—</b><small>reported health</small></article><article class="danger"><span>Critical</span><b id="critical">—</b><small>reported health</small></article><article><span>Unknown</span><b id="unknown">—</b><small>incomplete state</small></article></section>
<section class="panel" id="fleet"><div class="panel-title"><div><p class="kicker">FLEET</p><h2>Endpoint health &amp; runtime</h2></div><span id="fleetEvidenceStatus" class="status loading">LOADING</span></div><div class="freshness"><span>Data generated <b id="generatedAt">—</b></span><span>Freshness window <b id="freshnessWindow">—</b></span><span>Transport <b id="transport">—</b></span></div><div id="fleetEvidence" class="table-shell"><p class="empty">Awaiting verified endpoint telemetry…</p></div></section>
<section class="split" id="events"><section class="panel"><div class="panel-title"><div><p class="kicker">DETECTION</p><h2>Security event summary</h2></div><span class="status neutral">AGGREGATED</span></div><div id="eventSummary" class="event-summary"><p class="empty">Awaiting signed event totals…</p></div></section><section class="panel"><div class="panel-title"><div><p class="kicker">CORRELATION</p><h2>Threat visibility</h2></div><span id="correlationStatus" class="status loading">LOADING</span></div><div class="mini-grid"><div><span>Detections</span><b id="detectionCount">—</b></div><div><span>Incidents</span><b id="incidentCount">—</b></div><div><span>Attack graph</span><b id="graphCount">—</b></div><div><span>Risk signals</span><b id="riskCount">—</b></div></div></section></section>
<section class="panel"><div class="panel-title"><div><p class="kicker">INVESTIGATION</p><h2>Recent event evidence</h2></div><span id="investigationStatus" class="status loading">LOADING</span></div><div id="recentEvents" class="table-shell"><p class="empty">Awaiting authenticated event metadata…</p></div></section>
<section class="panel"><div class="panel-title"><div><p class="kicker">CONTAINMENT</p><h2>Quarantine visibility</h2></div><span id="quarantineStatus" class="status loading">LOADING</span></div><p id="quarantineMessage" class="integration-copy">Checking authenticated quarantine contracts…</p></section>
<section class="panel" id="diagnostics"><div class="panel-title"><div><p class="kicker">OPERATIONS</p><h2>Spool, persistence &amp; ACK diagnostics</h2></div><span id="diagnosticsStatus" class="status loading">LOADING</span></div><div id="diagnosticsTable" class="table-shell"><p class="empty">Awaiting trusted endpoint diagnostics…</p></div></section>
<section class="split"><section class="panel"><div class="panel-title"><div><p class="kicker">OBSERVABILITY</p><h2>Sensor &amp; ProcessGraph</h2></div><span class="status neutral">CONTRACT STATUS</span></div><ul class="integration-list"><li><span>Sensor plane</span><b id="sensorPlane">CHECKING</b><small id="sensorReason"></small></li><li><span>ProcessGraph</span><b id="processGraph">CHECKING</b><small id="processReason"></small></li><li><span>Persistence detail</span><b id="persistenceDetail">CHECKING</b><small id="persistenceReason"></small></li></ul></section><section class="panel"><div class="panel-title"><div><p class="kicker">RELEASE</p><h2>Installed versions</h2></div><span class="status neutral">REPORTED</span></div><div id="versions" class="version-list"><p class="empty">Awaiting runtime versions…</p></div></section></section>
<section class="split"><section class="panel"><div class="panel-title"><div><p class="kicker">INTEROPERABILITY</p><h2>XDR contract</h2></div><span id="xdrStatus" class="status loading">CHECKING</span></div><ul class="integration-list"><li><span>Schema</span><b id="xdrSchema">—</b></li><li><span>Signed ingest</span><b id="xdrSigned">CHECKING</b></li><li><span>Replay protection</span><b id="xdrReplay">CHECKING</b></li><li><span>Runtime validation</span><b id="xdrValidation">CHECKING</b></li></ul></section><section class="panel"><div class="panel-title"><div><p class="kicker">SECURITY</p><h2>Control-plane gates</h2></div><span class="status good">ENFORCED</span></div><ul class="integration-list"><li><span>Authentication</span><b id="authGate">CHECKING</b></li><li><span>Server-side RBAC</span><b id="rbacGate">CHECKING</b></li><li><span>CSRF</span><b id="csrfGate">CHECKING</b></li><li><span>Risk ≠ authorization</span><b id="trustGate">CHECKING</b></li></ul></section></section>
<section class="panel"><div class="panel-title"><div><p class="kicker">RESPONSE EVIDENCE</p><h2>Verified containment records</h2></div><span id="responseStatus" class="status loading">CHECKING</span></div><div class="mini-grid response-metrics"><div><span>Total</span><b id="responseTotal">—</b></div><div><span>Quarantined</span><b id="responseQuarantined">—</b></div><div><span>Restored</span><b id="responseRestored">—</b></div><div><span>Max response</span><b id="responseLatency">—</b></div></div><div id="responseEvidence" class="table-shell"><p class="empty">Awaiting signed response evidence…</p></div></section>
<section class="panel"><div class="panel-title"><div><p class="kicker">SESSION</p><h2>Security &amp; session boundary</h2></div><span class="status good">READ ONLY</span></div><div class="session-grid"><div><span>User</span><b>{html.escape(session["username"])}</b></div><div><span>Role</span><b>{html.escape(session["role"])}</b></div><div><span>Expires</span><b id="sessionExpiry">—</b></div><div><span>Environment</span><b>{html.escape(self.config.environment.upper())}</b></div><div><span>MFA</span><b id="mfaGate">CHECKING</b></div><div><span>Privileged actions</span><b id="actionGate">CHECKING</b></div></div></section>
{audit_panel}</main><script src="/static/app.js" defer></script></body></html>"""
        return self._html(200, page)

    def _forbidden(self, request_id: str, session: dict, request: Request, action: str) -> Response:
        self._audit(
            request_id,
            session.get("username", "unknown"),
            session.get("role", ""),
            action,
            "DENIED",
            request,
        )
        return self._json(403, {"error": "FORBIDDEN"})

    def _audit(
        self,
        request_id: str,
        actor: str,
        role: str,
        action: str,
        outcome: str,
        request: Request,
        subject: str = "",
    ) -> None:
        self.store.audit(
            now=float(self.clock()),
            request_id=request_id,
            actor=actor,
            role=role,
            action=action,
            outcome=outcome,
            client_hash=self._client_hash(request),
            subject=subject,
        )

    def _static(self, path: str) -> Response:
        name = path.rsplit("/", 1)[-1]
        target = STATIC_ROOT / name
        try:
            body = target.read_bytes()
        except OSError:
            return self._json(404, {"error": "NOT_FOUND"})
        content_type = "text/css; charset=utf-8" if name.endswith(".css") else "application/javascript; charset=utf-8"
        return Response(200, body, [("Content-Type", content_type), ("Cache-Control", "public, max-age=3600")])

    def _cookie(self, name: str, value: str, *, max_age: int) -> str:
        parts = [f"{name}={value}", "Path=/", f"Max-Age={max(0, int(max_age))}", "HttpOnly", "SameSite=Strict"]
        if self.config.secure_cookies:
            parts.append("Secure")
        return "; ".join(parts)

    def _delete_cookie(self, name: str) -> str:
        return self._cookie(name, "", max_age=0)

    @staticmethod
    def _json(status: int, payload: dict) -> Response:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return Response(status, body, [("Content-Type", "application/json; charset=utf-8")])

    @staticmethod
    def _html(status: int, page: str) -> Response:
        return Response(status, page.encode("utf-8"), [("Content-Type", "text/html; charset=utf-8")])

    @staticmethod
    def _redirect(location: str) -> Response:
        return Response(303, b"", [("Location", location)])

    def _finalize(self, response: Response, request_id: str) -> Response:
        response.headers.extend(
            [
                ("Content-Length", str(len(response.body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
                (
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
                ),
                ("Cross-Origin-Resource-Policy", "same-origin"),
                ("X-Request-ID", request_id),
            ]
        )
        if self.config.production_like:
            response.headers.append(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        return response
