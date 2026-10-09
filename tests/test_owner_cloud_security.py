from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from owner_cloud.app import Application, Request
from owner_cloud.config import Config
from owner_cloud.security import Account, hash_password
from owner_cloud.store import OwnerStore


class FakeDistribution:
    def state(self):
        return {
            "status": "HEALTHY",
            "summary": {
                "endpoints_total": 3,
                "online": 2,
                "critical": 0,
                "downloads_completed": 4,
            },
            "xdr": {
                "status": "READY",
                "schema": "OCSF",
                "schema_version": "1.9.0",
                "runtime_contract_validation": True,
                "signed_ingest": True,
                "replay_protection": True,
            },
            "transport": "RAILWAY_PRIVATE_AUTHENTICATED",
        }


class OwnerCloudSecurityTests(unittest.TestCase):
    def setUp(self):
        test_root = Path(".test-tmp").resolve()
        test_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="cd-owner-cloud-", dir=test_root)
        self.now = [1_800_000_000.0]
        accounts = {
            "owner": Account("owner", "OWNER", hash_password("Owner-Test-Password-42!", n=1024)),
            "admin": Account("admin", "ADMIN", hash_password("Admin-Test-Password-42!", n=1024)),
        }
        self.config = Config(
            environment="test",
            db_path=Path(self.temp.name) / "owner.db",
            accounts=accounts,
            distribution_private_url="http://127.0.0.1:1",
            distribution_read_token="x" * 48,
            allowed_hosts=("owner.test",),
            secure_cookies=True,
            session_ttl_seconds=3600,
            session_idle_seconds=900,
            login_failure_limit=3,
            login_failure_window_seconds=600,
            login_lock_seconds=600,
            login_rate_limit=100,
            api_rate_limit=1000,
        )
        self.app = Application(
            self.config,
            distribution=FakeDistribution(),
            clock=lambda: self.now[0],
        )

    def tearDown(self):
        self.temp.cleanup()

    def request(self, method, path, *, cookie="", body="", headers=None):
        values = {
            "Host": "owner.test",
            "X-Forwarded-Proto": "https",
            "X-Real-IP": "203.0.113.10",
        }
        if cookie:
            values["Cookie"] = cookie
        if body:
            values["Content-Type"] = "application/x-www-form-urlencoded"
        values.update(headers or {})
        return self.app.handle(
            Request(method, path, values, body.encode("utf-8"), "10.0.0.2")
        )

    @staticmethod
    def cookie(response, name):
        for value in response.values("Set-Cookie"):
            if value.startswith(name + "="):
                return value.split(";", 1)[0]
        raise AssertionError(f"cookie {name} not found")

    @staticmethod
    def csrf(response):
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.body.decode("utf-8"))
        if not match:
            raise AssertionError("CSRF token not found")
        return match.group(1)

    def login(self, username="owner", password="Owner-Test-Password-42!"):
        page = self.request("GET", "/login")
        csrf = self.csrf(page)
        preauth = self.cookie(page, self.config.preauth_cookie_name)
        body = urlencode({"username": username, "password": password, "csrf_token": csrf})
        response = self.request("POST", "/login", cookie=preauth, body=body)
        self.assertEqual(response.status, 303)
        return self.cookie(response, self.config.session_cookie_name), response

    def test_health_is_minimal_and_public(self):
        response = self.app.handle(Request("GET", "/health"))
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body), {"status": "ok"})
        self.assertNotIn(b"version", response.body)

    def test_unauthenticated_owner_redirects_and_api_denies(self):
        self.assertEqual(self.request("GET", "/owner").status, 303)
        self.assertEqual(self.request("GET", "/api/v1/state").status, 401)

    def test_owner_login_secure_cookie_and_logout_invalidation(self):
        session_cookie, login_response = self.login()
        set_cookie = " ".join(login_response.values("Set-Cookie"))
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(attribute, set_cookie)
        page = self.request("GET", "/owner", cookie=session_cookie)
        self.assertEqual(page.status, 200)
        csrf = self.csrf(page)
        state = self.request("GET", "/api/v1/state", cookie=session_cookie)
        self.assertEqual(state.status, 200)
        state_payload = json.loads(state.body)
        self.assertTrue(state_payload["mode"] == "READ_ONLY")
        self.assertEqual(state_payload["security"]["authentication"], "ENFORCED")
        self.assertEqual(state_payload["security"]["server_side_rbac"], "ENFORCED")
        self.assertEqual(state_payload["security"]["csrf"], "ENFORCED")
        self.assertFalse(state_payload["security"]["risk_is_authorization"])
        self.assertTrue(state_payload["distribution"]["xdr"]["signed_ingest"])
        logout = self.request(
            "POST",
            "/logout",
            cookie=session_cookie,
            body=urlencode({"csrf_token": csrf}),
        )
        self.assertEqual(logout.status, 303)
        self.assertEqual(self.request("GET", "/api/v1/state", cookie=session_cookie).status, 401)

    def test_dashboard_waits_for_runtime_security_and_xdr_evidence(self):
        session_cookie, _ = self.login()
        page = self.request("GET", "/owner", cookie=session_cookie)
        self.assertEqual(page.status, 200)
        html = page.body.decode("utf-8")
        for element_id in (
            "xdrStatus", "xdrSchema", "xdrSigned", "xdrReplay", "xdrValidation",
            "authGate", "rbacGate", "csrfGate", "actionGate", "trustGate",
        ):
            self.assertIn(f'id="{element_id}"', html)
        self.assertNotIn('<span class="pass">PASS</span>', html)

    def test_admin_rbac_and_privileged_action_are_server_side_denied(self):
        session_cookie, _ = self.login("admin", "Admin-Test-Password-42!")
        self.assertEqual(self.request("GET", "/api/v1/audit", cookie=session_cookie).status, 403)
        page = self.request("GET", "/owner", cookie=session_cookie)
        csrf = self.csrf(page)
        denied = self.request(
            "POST",
            "/api/v1/actions/quarantine",
            cookie=session_cookie,
            body=urlencode({"csrf_token": csrf}),
        )
        self.assertEqual(denied.status, 403)
        self.assertEqual(json.loads(denied.body)["error"], "READ_ONLY_MODE")

    def test_csrf_is_required_for_login_logout_and_denied_action(self):
        body = urlencode({"username": "owner", "password": "Owner-Test-Password-42!"})
        self.assertEqual(self.request("POST", "/login", body=body).status, 403)
        session_cookie, _ = self.login()
        self.assertEqual(self.request("POST", "/logout", cookie=session_cookie, body="x=1").status, 403)
        self.assertEqual(
            self.request("POST", "/api/v1/actions/quarantine", cookie=session_cookie, body="x=1").status,
            403,
        )

    def test_expired_and_invalid_sessions_fail_closed(self):
        session_cookie, _ = self.login()
        invalid = self.config.session_cookie_name + "=not-a-valid-session-token"
        self.assertEqual(self.request("GET", "/api/v1/state", cookie=invalid).status, 401)
        self.now[0] += 3601
        self.assertEqual(self.request("GET", "/api/v1/state", cookie=session_cookie).status, 401)

    def test_login_brute_force_lock(self):
        statuses = []
        for _ in range(3):
            page = self.request("GET", "/login")
            body = urlencode(
                {
                    "username": "owner",
                    "password": "wrong-password-value",
                    "csrf_token": self.csrf(page),
                }
            )
            statuses.append(
                self.request(
                    "POST",
                    "/login",
                    cookie=self.cookie(page, self.config.preauth_cookie_name),
                    body=body,
                ).status
            )
        self.assertEqual(statuses, [401, 401, 429])

    def test_client_hash_uses_stable_railway_real_ip(self):
        first = Request(
            "GET",
            "/health",
            {"X-Real-IP": "203.0.113.10", "X-Forwarded-For": "198.51.100.1"},
            b"",
            "10.0.0.2",
        )
        second = Request(
            "GET",
            "/health",
            {"X-Real-IP": "203.0.113.10", "X-Forwarded-For": "198.51.100.99"},
            b"",
            "10.0.0.3",
        )
        self.assertEqual(self.app._client_hash(first), self.app._client_hash(second))

        invalid = Request("GET", "/health", {"X-Real-IP": "not-an-ip"}, b"", "10.0.0.4")
        fallback = Request("GET", "/health", {}, b"", "10.0.0.4")
        self.assertEqual(self.app._client_hash(invalid), self.app._client_hash(fallback))

    def test_host_and_https_are_enforced_in_production_mode(self):
        production = Config(
            **{
                **self.config.__dict__,
                "environment": "production",
                "distribution_private_url": "http://cyberdefender.railway.internal:8080",
                "allowed_hosts": ("app.cyberdefender-sec.uz",),
            }
        )
        app = Application(production, distribution=FakeDistribution(), clock=lambda: self.now[0])
        bad_host = app.handle(
            Request("GET", "/login", {"Host": "evil.example", "X-Forwarded-Proto": "https"})
        )
        cleartext = app.handle(
            Request("GET", "/login", {"Host": "app.cyberdefender-sec.uz", "X-Forwarded-Proto": "http"})
        )
        self.assertEqual(bad_host.status, 400)
        self.assertEqual(cleartext.status, 400)

    def test_production_rejects_public_distribution_url(self):
        with self.assertRaises(ValueError):
            Config(
                **{
                    **self.config.__dict__,
                    "environment": "production",
                    "distribution_private_url": "https://cyberdefender-production.up.railway.app",
                    "allowed_hosts": ("app.cyberdefender-sec.uz",),
                }
            ).validate()

    def test_session_and_audit_survive_store_reopen_without_credentials(self):
        session_cookie, _ = self.login()
        second_store = OwnerStore(self.config.db_path)
        rows = second_store.recent_audit()
        self.assertTrue(any(row["action"] == "session.login" for row in rows))
        self.assertNotIn("Owner-Test-Password", json.dumps(rows))
        token = session_cookie.split("=", 1)[1]
        self.assertIsNotNone(
            second_store.get_session(
                __import__("owner_cloud.security", fromlist=["token_hash"]).token_hash(token),
                now=self.now[0],
                idle_seconds=900,
            )
        )


if __name__ == "__main__":
    unittest.main()
