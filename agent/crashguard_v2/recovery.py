"""Signed, revision-bound CrashGuard v2 recovery authorization."""
from __future__ import annotations

import copy
from dataclasses import dataclass
import json
import math
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent.crashguard_v2.failure_codes import FAILURE_CODES


REQUEST_FIELDS = frozenset(
    {
        "action",
        "service",
        "release_sha256",
        "state_generation",
        "state_revision",
        "nonce",
        "issued_at",
        "expires_at",
    }
)
ACTION = "RECOVERY_PROBE"
MAX_AUTHORIZATION_BYTES = 2048
MAX_VALIDITY_SECONDS = 15 * 60


class RecoveryAuthorizationError(RuntimeError):
    pass


def _fail(code: str) -> None:
    if code not in FAILURE_CODES:
        code = "RECOVERY_VERIFY_FAILED"
    raise RecoveryAuthorizationError(code)


def canonical_request(request: dict) -> bytes:
    if type(request) is not dict or set(request) != REQUEST_FIELDS:
        _fail("RECOVERY_AUTH_REQUIRED")
    try:
        raw = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("RECOVERY_AUTH_REQUIRED")
    if len(raw) > MAX_AUTHORIZATION_BYTES:
        _fail("RECOVERY_AUTH_REQUIRED")
    return raw


def parse_canonical_request(raw: bytes) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_AUTHORIZATION_BYTES:
        _fail("RECOVERY_AUTH_REQUIRED")

    def pairs(items):
        output = {}
        for key, value in items:
            if key in output:
                _fail("RECOVERY_AUTH_REQUIRED")
            output[key] = value
        return output

    try:
        request = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except RecoveryAuthorizationError:
        raise
    except Exception:
        _fail("RECOVERY_AUTH_REQUIRED")
    if canonical_request(request) != raw:
        _fail("RECOVERY_AUTH_REQUIRED")
    return request


@dataclass(frozen=True)
class RecoveryPublicKey:
    key_id: str
    raw: bytes
    revoked: bool = False

    def __post_init__(self):
        if (
            not self.key_id
            or len(self.key_id) > 96
            or not self.key_id.isascii()
            or type(self.raw) is not bytes
            or len(self.raw) != 32
        ):
            _fail("RECOVERY_AUTH_REQUIRED")


def _validate_request(
    request: dict,
    signature: bytes,
    public_key: RecoveryPublicKey,
    record: dict,
    *,
    expected_service: str,
    expected_release_sha256: str,
    now: int,
) -> None:
    if public_key.revoked:
        _fail("RECOVERY_AUTH_REQUIRED")
    if type(signature) is not bytes or len(signature) != 64:
        _fail("RECOVERY_SIGNATURE_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(public_key.raw).verify(signature, canonical_request(request))
    except (InvalidSignature, ValueError):
        _fail("RECOVERY_SIGNATURE_INVALID")
    if request["action"] != ACTION or request["service"] != expected_service:
        _fail("RECOVERY_BINDING_MISMATCH")
    digest = request["release_sha256"]
    if (
        digest != expected_release_sha256
        or type(digest) is not str
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        _fail("RECOVERY_BINDING_MISMATCH")
    for field in ("state_generation", "state_revision", "issued_at", "expires_at"):
        if type(request[field]) is not int or not 0 <= request[field] < 2**63:
            _fail("RECOVERY_AUTH_REQUIRED")
    nonce = request["nonce"]
    if type(nonce) is not str or not 16 <= len(nonce) <= 128 or not nonce.isascii():
        _fail("RECOVERY_AUTH_REQUIRED")
    if nonce in record["consumed_nonces"]:
        _fail("RECOVERY_REPLAYED")
    if request["state_revision"] != record["revision"] or request["state_generation"] != record["generation"]:
        _fail("RECOVERY_STALE_REVISION")
    if (
        type(now) is not int
        or request["issued_at"] > now
        or request["expires_at"] < now
        or request["expires_at"] <= request["issued_at"]
        or request["expires_at"] - request["issued_at"] > MAX_VALIDITY_SECONDS
    ):
        _fail("RECOVERY_EXPIRED")
    if record["recovery_budget_remaining"] <= 0:
        _fail("RECOVERY_BUDGET_EXHAUSTED")
    if record["lifecycle"] not in {"LATCHED", "SAFE_HOLD"}:
        _fail("RECOVERY_AUTH_REQUIRED")


def plan_recovery(
    store,
    authorization: bytes,
    signature: bytes,
    public_key: RecoveryPublicKey,
    *,
    expected_service: str,
    expected_release_sha256: str,
    now: int,
) -> dict:
    request = parse_canonical_request(authorization)
    record = store.load()
    _validate_request(
        request,
        signature,
        public_key,
        record,
        expected_service=expected_service,
        expected_release_sha256=expected_release_sha256,
        now=now,
    )
    return {
        "status": "RECOVERY_PLAN_VERIFIED",
        "service": expected_service,
        "state_revision": record["revision"],
        "state_generation": record["generation"],
        "budget_remaining": record["recovery_budget_remaining"],
        "budget_consumed": 0,
    }


def reserve_recovery(
    store,
    authorization: bytes,
    signature: bytes,
    public_key: RecoveryPublicKey,
    *,
    expected_service: str,
    expected_release_sha256: str,
    now: int,
    monotonic_ns: int,
    wall_time_ns: int,
    after_commit: Callable[[], None] | None = None,
) -> dict:
    request = parse_canonical_request(authorization)
    record = store.load()
    _validate_request(
        request,
        signature,
        public_key,
        record,
        expected_service=expected_service,
        expected_release_sha256=expected_release_sha256,
        now=now,
    )
    candidate = copy.deepcopy(record)
    candidate["lifecycle"] = "RECOVERY_PROBING"
    candidate["health"] = "UNKNOWN"
    candidate["generation"] += 1
    candidate["attempts_since_stable"] += 1
    candidate["recovery_budget_remaining"] -= 1
    candidate["consumed_nonces"] = [*candidate["consumed_nonces"], request["nonce"]][-64:]
    candidate["monotonic_ns"] = monotonic_ns
    candidate["wall_time_ns"] = wall_time_ns
    committed = store.write(candidate)
    if after_commit is not None:
        after_commit()
    return committed


def verified_stable(record: dict) -> dict:
    updated = copy.deepcopy(record)
    if updated.get("health") != "STABLE":
        _fail("RECOVERY_VERIFY_FAILED")
    updated["attempts_since_stable"] = 0
    updated["lifecycle"] = "RUNNING"
    return updated

