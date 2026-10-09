from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping


PROTOCOL_VERSION = "cyberdefender.fleet.v1"
MAX_CLOCK_SKEW_SECONDS = 300
MIN_TOKEN_BYTES = 32
MAX_TOKEN_BYTES = 512

HEADER_PROTOCOL = "X-CyberDefender-Protocol"
HEADER_TIMESTAMP = "X-CyberDefender-Timestamp"
HEADER_NONCE = "X-CyberDefender-Nonce"
HEADER_CONTENT_SHA256 = "X-CyberDefender-Content-SHA256"
HEADER_SIGNATURE = "X-CyberDefender-Signature"

_NONCE_RE = re.compile(r"^[0-9a-f]{32,64}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class FleetProtocolError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerifiedRequest:
    timestamp: int
    nonce: str
    content_sha256: str


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
            events = [stamp for stamp in self._events.get(str(key), ()) if stamp > cutoff]
            if len(events) >= self.limit:
                self._events[str(key)] = events
                return False
            events.append(now)
            self._events[str(key)] = events
            if len(self._events) > 4096:
                self._events = {
                    current_key: stamps
                    for current_key, stamps in self._events.items()
                    if any(stamp > cutoff for stamp in stamps)
                }
            return True


def validate_token(token: str) -> str:
    value = str(token or "").strip()
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise FleetProtocolError("TOKEN_INVALID") from exc
    if not MIN_TOKEN_BYTES <= len(encoded) <= MAX_TOKEN_BYTES:
        raise FleetProtocolError("TOKEN_INVALID")
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise FleetProtocolError("TOKEN_INVALID")
    return value


def _header(headers: Mapping[str, str], name: str) -> str:
    direct = headers.get(name)
    if direct is not None:
        return str(direct).strip()
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value).strip()
    return ""


def content_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_request(
    *,
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    digest: str,
) -> bytes:
    normalized_method = str(method).upper()
    normalized_path = str(path)
    if not normalized_path.startswith("/") or "\n" in normalized_path or "\r" in normalized_path:
        raise FleetProtocolError("PATH_INVALID")
    if not _NONCE_RE.fullmatch(nonce):
        raise FleetProtocolError("NONCE_INVALID")
    if not _DIGEST_RE.fullmatch(digest):
        raise FleetProtocolError("DIGEST_INVALID")
    return "\n".join(
        (PROTOCOL_VERSION, normalized_method, normalized_path, str(int(timestamp)), nonce, digest)
    ).encode("ascii")


def signature_headers(
    token: str,
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    secret = validate_token(token)
    observed = int(time.time() if timestamp is None else timestamp)
    request_nonce = secrets.token_hex(16) if nonce is None else str(nonce).lower()
    digest = content_sha256(body)
    canonical = canonical_request(
        method=method,
        path=path,
        timestamp=observed,
        nonce=request_nonce,
        digest=digest,
    )
    signature = hmac.new(secret.encode("ascii"), canonical, hashlib.sha256).hexdigest()
    return {
        HEADER_PROTOCOL: PROTOCOL_VERSION,
        HEADER_TIMESTAMP: str(observed),
        HEADER_NONCE: request_nonce,
        HEADER_CONTENT_SHA256: digest,
        HEADER_SIGNATURE: "sha256=" + signature,
    }


def verify_request(
    token: str,
    *,
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    now: float | None = None,
    max_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
) -> VerifiedRequest:
    secret = validate_token(token)
    if _header(headers, HEADER_PROTOCOL) != PROTOCOL_VERSION:
        raise FleetProtocolError("PROTOCOL_REQUIRED")
    raw_timestamp = _header(headers, HEADER_TIMESTAMP)
    nonce = _header(headers, HEADER_NONCE).lower()
    claimed_digest = _header(headers, HEADER_CONTENT_SHA256).lower()
    claimed_signature = _header(headers, HEADER_SIGNATURE).lower()
    if not claimed_signature.startswith("sha256="):
        raise FleetProtocolError("SIGNATURE_REQUIRED")
    try:
        timestamp = int(raw_timestamp)
    except (TypeError, ValueError) as exc:
        raise FleetProtocolError("TIMESTAMP_INVALID") from exc
    current = float(time.time() if now is None else now)
    if abs(current - timestamp) > max(1, int(max_clock_skew_seconds)):
        raise FleetProtocolError("TIMESTAMP_OUT_OF_RANGE")
    actual_digest = content_sha256(body)
    if not hmac.compare_digest(actual_digest, claimed_digest):
        raise FleetProtocolError("CONTENT_DIGEST_MISMATCH")
    canonical = canonical_request(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        digest=actual_digest,
    )
    expected = hmac.new(secret.encode("ascii"), canonical, hashlib.sha256).hexdigest()
    supplied = claimed_signature[7:]
    if not _DIGEST_RE.fullmatch(supplied) or not hmac.compare_digest(expected, supplied):
        raise FleetProtocolError("SIGNATURE_INVALID")
    return VerifiedRequest(timestamp=timestamp, nonce=nonce, content_sha256=actual_digest)
