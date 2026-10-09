from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from owner_cloud.security import Account, load_accounts


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    environment: str
    db_path: Path
    accounts: dict[str, Account]
    distribution_private_url: str
    distribution_read_token: str
    allowed_hosts: tuple[str, ...]
    secure_cookies: bool = True
    session_ttl_seconds: int = 8 * 60 * 60
    session_idle_seconds: int = 30 * 60
    login_failure_limit: int = 5
    login_failure_window_seconds: int = 15 * 60
    login_lock_seconds: int = 15 * 60
    login_rate_limit: int = 20
    api_rate_limit: int = 240

    @property
    def production_like(self) -> bool:
        return self.environment in {"staging", "production"}

    @property
    def session_cookie_name(self) -> str:
        return "__Host-cd_session" if self.secure_cookies else "cd_session"

    @property
    def preauth_cookie_name(self) -> str:
        return "__Host-cd_preauth" if self.secure_cookies else "cd_preauth"

    def validate(self) -> "Config":
        if not self.accounts:
            raise ValueError("accounts are required")
        if self.production_like and not self.secure_cookies:
            raise ValueError("secure cookies are mandatory outside development")
        if self.production_like:
            parsed = urlparse(self.distribution_private_url)
            if parsed.scheme not in {"http", "https"} or not (parsed.hostname or "").endswith(".railway.internal"):
                raise ValueError("distribution URL must use Railway private networking")
            if len(self.distribution_read_token) < 32:
                raise ValueError("distribution read token must contain at least 32 characters")
            if not self.allowed_hosts:
                raise ValueError("at least one allowed host is required")
        if not 300 <= self.session_idle_seconds <= self.session_ttl_seconds:
            raise ValueError("invalid session lifetime")
        if not 900 <= self.session_ttl_seconds <= 24 * 60 * 60:
            raise ValueError("session lifetime must be between 15 minutes and 24 hours")
        return self

    @classmethod
    def from_environment(cls) -> "Config":
        environment = os.getenv("CYBERDEFENDER_ENVIRONMENT", "development").strip().lower()
        if environment not in {"development", "test", "staging", "production"}:
            raise ValueError("invalid environment")
        if _truthy(os.getenv("DEBUG")) or _truthy(os.getenv("CYBERDEFENDER_DEBUG")):
            raise ValueError("debug mode is forbidden")
        accounts = load_accounts(os.getenv("CYBERDEFENDER_OWNER_ACCOUNTS_JSON", ""))
        host_values = {
            value.strip().lower().split(":", 1)[0]
            for value in os.getenv("CYBERDEFENDER_OWNER_ALLOWED_HOSTS", "").split(",")
            if value.strip()
        }
        for name in ("RAILWAY_PUBLIC_DOMAIN", "CYBERDEFENDER_OWNER_CUSTOM_DOMAIN"):
            value = os.getenv(name, "").strip().lower()
            if value:
                host_values.add(value.split(":", 1)[0])
        if environment in {"development", "test"}:
            host_values.update({"localhost", "127.0.0.1", "owner.test"})
        config = cls(
            environment=environment,
            db_path=Path(os.getenv("CYBERDEFENDER_OWNER_DB", "/data/owner.db")).expanduser().resolve(),
            accounts=accounts,
            distribution_private_url=os.getenv("CYBERDEFENDER_DISTRIBUTION_PRIVATE_URL", "").rstrip("/"),
            distribution_read_token=os.getenv("CYBERDEFENDER_DISTRIBUTION_READ_TOKEN", ""),
            allowed_hosts=tuple(sorted(host_values)),
            secure_cookies=not _truthy(os.getenv("CYBERDEFENDER_ALLOW_INSECURE_COOKIES")),
            session_ttl_seconds=int(os.getenv("CYBERDEFENDER_SESSION_TTL_SECONDS", str(8 * 60 * 60))),
            session_idle_seconds=int(os.getenv("CYBERDEFENDER_SESSION_IDLE_SECONDS", str(30 * 60))),
        )
        return config.validate()
