from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from typing import Any


def normalized_secret(value: Any) -> str:
    text = "".join(str(value or "").split()).upper().rstrip("=")
    try:
        raw = base64.b32decode(text + "=" * (-len(text) % 8), casefold=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid TOTP secret") from exc
    if not 20 <= len(raw) <= 64:
        raise ValueError("TOTP secret must contain 160-512 bits")
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def code_at(secret: str, counter: int) -> str:
    normalized = normalized_secret(secret)
    key = base64.b32decode(normalized + "=" * (-len(normalized) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(counter)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify(secret: str, candidate: str, *, now: float, window: int = 1) -> int | None:
    code = str(candidate or "").strip()
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int(float(now) // 30)
    for counter in range(current - max(0, int(window)), current + max(0, int(window)) + 1):
        if counter >= 0 and hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None
