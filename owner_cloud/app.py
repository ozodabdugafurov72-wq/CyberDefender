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
        if method == "GET" and path in {"/static/app.css", "/static/app.js"}:
            return self._static(path)
        if method == "GET" and path == "/login":
            return self._login_page()
        if method == "POST" and path == "/login":
            return self._login(request, request_id)

        session = self._session(request)
        if session is None:
            if method == "GET" and path in {"/", "/owner"}:
                return self._redirect("/login")
            return self._json(401, {"error": "AUTHENTICATION_REQUIRED"})
        if not self.api_limiter.allow("session:" + session["token_hash"]):
            return self._json(429, {"error": "RATE_LIMITED"}).add_header("Retry-After", "60")

        if method == "GET" and path == "/":
            return self._redirect("/owner")
        if method == "GET" and path == "/owner":
            return self._dashboard_page(session)
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
        if method == "GET" and path == "/api/v1/state":
            if session["role"] not in {ROLE_OWNER, ROLE_ADMIN}:
                return self._forbidden(request_id, session, request, "state.read")
            upstream = self.distribution.state()
            return self._json(
                200,
                {
                    "status": "HEALTHY",
                    "mode": "READ_ONLY",
                    "environment": self.config.environment,
                    "actor": {"username": session["username"], "role": session["role"]},
                    "distribution": upstream,
                },
            )
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
<title>CyberDefender Owner Login</title><link rel="stylesheet" href="/static/app.css"></head>
<body class="login-body"><main class="login-card"><div class="brand-mark">CD</div>
<p class="eyebrow">CYBERDEFENDER CONTROL PLANE</p><h1>Owner access</h1>
<p class="muted">Authorized Owner and Admin accounts only.</p>{error_html}
<form method="post" action="/login" autocomplete="on">
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
<label>Username<input name="username" maxlength="64" autocomplete="username" required></label>
<label>Password<input type="password" name="password" maxlength="256" autocomplete="current-password" required></label>
<button type="submit">Sign in securely</button></form>
<p class="guard">Fail-closed · audited · read-only</p></main></body></html>"""
        return self._html(status, page).add_header(
            "Set-Cookie",
            self._cookie(self.config.preauth_cookie_name, csrf_token, max_age=600),
        )

    def _login(self, request: Request, request_id: str) -> Response:
        client_hash = self._client_hash(request)
        if not self.login_limiter.allow("login:" + client_hash):
            return self._json(429, {"error": "RATE_LIMITED"}).add_header("Retry-After", "60")
        form = self._form(request)
        username = form.get("username", "").strip().lower()[:64]
        password = form.get("password", "")
        csrf_token = form.get("csrf_token", "")
        preauth = self._cookies(request).get(self.config.preauth_cookie_name, "")
        if not csrf_token or not preauth or not hmac.compare_digest(token_hash(csrf_token), token_hash(preauth)):
            self._audit(request_id, username or "unknown", "", "session.login", "CSRF_DENIED", request)
            return self._login_page(status=403, error="The login form expired. Try again.")
        subject_hash = token_hash(username or "unknown")
        allowed, locked_until = self.store.login_allowed(subject_hash, client_hash, now=float(self.clock()))
        if not allowed:
            retry = max(1, int(locked_until - float(self.clock())))
            return self._json(429, {"error": "LOGIN_LOCKED"}).add_header("Retry-After", str(retry))
        account = self.config.accounts.get(username)
        password_hash = account.password_hash if account is not None else self._dummy_password_hash
        password_ok = verify_password(password, password_hash)
        if account is None or not account.enabled or not password_ok:
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
            return self._login_page(status=401, error="Invalid username or password.")

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
        )
        self._audit(request_id, account.username, account.role, "session.login", "SUCCESS", request)
        return (
            self._redirect("/owner")
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

    def _dashboard_page(self, session: dict) -> Response:
        csrf_token = new_token()
        if not self.store.rotate_session_csrf(session["token_hash"], token_hash(csrf_token)):
            return self._json(401, {"error": "AUTHENTICATION_REQUIRED"})
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberDefender Owner Control</title><link rel="stylesheet" href="/static/app.css"></head>
<body><header class="topbar"><div><span class="brand-mark small">CD</span><b>CyberDefender</b>
<span class="badge">READ ONLY</span></div><div class="identity"><span>{html.escape(session["username"])}</span>
<strong>{html.escape(session["role"])}</strong><form method="post" action="/logout">
<input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
<button class="ghost" type="submit">Logout</button></form></div></header>
<main class="dashboard" data-role="{html.escape(session["role"], quote=True)}">
<section class="hero"><p class="eyebrow">SECURE OWNER DASHBOARD</p><h1>Fleet control overview</h1>
<p>Authenticated monitoring through the Railway private service boundary.</p></section>
<section class="grid" id="metrics"><article><span>Environment</span><b>{html.escape(self.config.environment.upper())}</b></article>
<article><span>Mode</span><b>READ ONLY</b></article><article><span>Distribution</span><b id="distributionStatus">LOADING</b></article>
<article><span>Transport</span><b id="transport">PRIVATE</b></article></section>
<section class="panel"><div class="panel-title"><h2>Fleet summary</h2><span id="updated">Awaiting private API</span></div>
<div class="grid compact"><article><span>Endpoints</span><b id="endpoints">—</b></article>
<article><span>Online</span><b id="online">—</b></article><article><span>Critical</span><b id="critical">—</b></article>
<article><span>Downloads</span><b id="downloads">—</b></article></div></section>
<section class="panel"><h2>Security gates</h2><ul class="gates">
<li><b>Authentication</b><span class="pass">PASS</span></li><li><b>Server-side RBAC</b><span class="pass">PASS</span></li>
<li><b>Privileged actions</b><span>DISABLED</span></li><li><b>Risk ≠ Authorization</b><span>ENFORCED</span></li></ul></section>
<section class="panel owner-only" id="auditPanel" hidden><h2>Recent access audit</h2><div id="audit">Loading…</div></section>
</main><script src="/static/app.js" defer></script></body></html>"""
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
        name = "app.css" if path.endswith(".css") else "app.js"
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
