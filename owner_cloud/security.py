from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable


ROLE_OWNER = "OWNER"
ROLE_ADMIN = "ADMIN"
ALLOWED_ROLES = frozenset({ROLE_OWNER, ROLE_ADMIN})


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, *, n: int = 16384, r: int = 8, p: int = 1) -> str:
    if not isinstance(password, str) or len(password) < 14:
        raise ValueError("password must contain at least 14 characters")
    if n < 1024 or n & (n - 1) or r < 1 or p < 1:
        raise ValueError("invalid scrypt parameters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, raw_n, raw_r, raw_p, raw_salt, raw_digest = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        n, r, p = int(raw_n), int(raw_r), int(raw_p)
        if n < 1024 or n > 262144 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
            return False
        salt, expected = _b64decode(raw_salt), _b64decode(raw_digest)
        if not 8 <= len(salt) <= 64 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
        return hmac.compare_digest(expected, actual)
    except (TypeError, ValueError):
        return False


@dataclass(frozen=True)
class Account:
    username: str
    role: str
    password_hash: str
    enabled: bool = True


def load_accounts(raw: str) -> dict[str, Account]:
    try:
        values = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("accounts JSON is invalid") from exc
    if not isinstance(values, list) or not values:
        raise ValueError("at least one account is required")
    accounts: dict[str, Account] = {}
    for item in values:
        if not isinstance(item, dict):
            raise ValueError("account entry must be an object")
        username = str(item.get("username", "")).strip().lower()
        role = str(item.get("role", "")).strip().upper()
        password_hash = str(item.get("password_hash", "")).strip()
        enabled = item.get("enabled", True) is True
        if not username or len(username) > 64 or not username.replace(".", "").replace("_", "").replace("-", "").isalnum():
            raise ValueError("invalid account username")
        if role not in ALLOWED_ROLES:
            raise ValueError("invalid account role")
        if username in accounts:
            raise ValueError("duplicate account username")
        if not password_hash.startswith("scrypt$"):
            raise ValueError("invalid password hash format")
        # Parse and bound the encoded parameters without requiring the real password.
        parts = password_hash.split("$")
        if len(parts) != 6:
            raise ValueError("invalid password hash format")
        try:
            n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            salt, digest = _b64decode(parts[4]), _b64decode(parts[5])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid password hash format") from exc
        if n < 1024 or n > 262144 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
            raise ValueError("unsafe password hash parameters")
        if not 8 <= len(salt) <= 64 or len(digest) != 32:
            raise ValueError("invalid password hash material")
        accounts[username] = Account(username, role, password_hash, enabled)
    if not any(account.role == ROLE_OWNER and account.enabled for account in accounts.values()):
        raise ValueError("an enabled OWNER account is required")
    return accounts


def new_token(bytes_count: int = 32) -> str:
    return secrets.token_urlsafe(bytes_count)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SlidingWindowLimiter:
    def __init__(self, *, limit: int, window_seconds: float, clock: Callable[[], float] = time.time):
        self.limit = max(1, int(limit))
        self.window_seconds = max(1.0, float(window_seconds))
        self.clock = clock
        self._lock = threading.RLock()
        self._events: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = float(self.clock())
        cutoff = now - self.window_seconds
        with self._lock:
            events = [stamp for stamp in self._events.get(key, ()) if stamp > cutoff]
            if len(events) >= self.limit:
                self._events[key] = events
                return False
            events.append(now)
            self._events[key] = events
            if len(self._events) > 4096:
                self._events = {
                    current_key: stamps
                    for current_key, stamps in self._events.items()
                    if any(stamp > cutoff for stamp in stamps)
                }
            return True
