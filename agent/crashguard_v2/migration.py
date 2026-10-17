"""Offline one-shot v1 to v2 migration using authenticated synthetic inputs."""
from __future__ import annotations

import copy
import hashlib
import hmac
import os
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent import service_crash_store as v1
from agent.crashguard_v2.recovery import RecoveryPublicKey, canonical_request, parse_canonical_request
from agent.crashguard_v2.store import (
    MAX_RECORD_BYTES,
    _decode,
    _envelope,
    fresh_record,
    validate_record,
)


ACTION = "MIGRATE_V1_TO_V2"
STATE_MAP = {
    "READY": "READY",
    "STARTING": "LATCHED",
    "RUNNING": "READY",
    "LATCHED": "LATCHED",
    "PROBE": "LATCHED",
    "UNAVAILABLE": "SAFE_HOLD",
}


class MigrationError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise MigrationError(code)


def _read_v1(root: Path, service: str, key: bytes) -> tuple[dict, dict[str, str]]:
    files = [root / f"{service}.anchor", root / f"{service}.0.json", root / f"{service}.1.json"]
    existing = [path for path in files if path.exists()]
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in existing}

    def decode(path: Path) -> dict:
        try:
            envelope = v1.strict_json(path.read_bytes())
            if type(envelope) is not dict or set(envelope) != {"payload", "mac"}:
                _fail("MIGRATION_SOURCE_INVALID")
            expected = hmac.new(key, v1.canonical(envelope["payload"]), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, envelope["mac"]):
                _fail("MIGRATION_SOURCE_INVALID")
            return envelope["payload"]
        except MigrationError:
            raise
        except Exception:
            _fail("MIGRATION_SOURCE_INVALID")

    anchor = decode(root / f"{service}.anchor")
    if type(anchor) is not dict or anchor.get("service") != service or anchor.get("schema") != "cd.crash-anchor.v1":
        _fail("MIGRATION_SOURCE_INVALID")
    revision = anchor.get("revision")
    if type(revision) is not int or revision < 0:
        _fail("MIGRATION_SOURCE_INVALID")
    record = decode(root / f"{service}.{revision % 2}.json")
    try:
        v1.validate_record(record, service)
    except Exception:
        _fail("MIGRATION_SOURCE_INVALID")
    if record["revision"] != revision or hashlib.sha256(v1.canonical(record)).hexdigest() != anchor.get("digest"):
        _fail("MIGRATION_SOURCE_INVALID")
    after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in existing}
    if before != after:
        _fail("MIGRATION_SOURCE_INVALID")
    return record, before


def _authorize(
    authorization: bytes,
    signature: bytes,
    public_key: RecoveryPublicKey,
    source: dict,
    *,
    service: str,
    release_sha256: str,
    now: int,
) -> dict:
    request = parse_canonical_request(authorization)
    if public_key.revoked:
        _fail("MIGRATION_AUTH_REQUIRED")
    try:
        Ed25519PublicKey.from_public_bytes(public_key.raw).verify(signature, canonical_request(request))
    except (InvalidSignature, ValueError):
        _fail("MIGRATION_AUTH_REQUIRED")
    if (
        request["action"] != ACTION
        or request["service"] != service
        or request["release_sha256"] != release_sha256
        or request["state_generation"] != source["generation"]
        or request["state_revision"] != source["revision"]
        or type(request["issued_at"]) is not int
        or type(request["expires_at"]) is not int
        or not request["issued_at"] <= now <= request["expires_at"]
        or request["expires_at"] - request["issued_at"] > 900
    ):
        _fail("MIGRATION_AUTH_REQUIRED")
    return request


def map_record(source: dict, service: str, *, wall_time_ns: int) -> dict:
    lifecycle = STATE_MAP.get(source["state"])
    if lifecycle is None:
        _fail("MIGRATION_SOURCE_INVALID")
    target = fresh_record(
        service,
        boot_id=source["boot"] or "legacy-unknown-boot",
        monotonic_ns=0,
        wall_time_ns=wall_time_ns,
    )
    target.update(
        revision=source["revision"],
        generation=source["generation"],
        lifecycle=lifecycle,
        health="UNKNOWN",
        cumulative_failures=source["cumulative_failures"],
        attempts_since_stable=source["attempts_since_stable"],
        recovery_budget_remaining=0,
        last_failure_code=None,
        migration={
            "source_schema": source["schema"],
            "source_state": source["state"],
            "source_revision": source["revision"],
            "probes_used": source["probes_used"],
            "repair_count": source["repair_count"],
            "clean_stop": source["clean_stop"],
            "active_attempt": source["active_attempt"],
            "recent_failures": copy.deepcopy(source["recent_failures"]),
        },
    )
    validate_record(target, service)
    return target


def migrate(
    v1_root: Path,
    v1_key: bytes,
    v2_store,
    staging_file: Path,
    authorization: bytes,
    signature: bytes,
    public_key: RecoveryPublicKey,
    *,
    service: str,
    release_sha256: str,
    now: int,
    wall_time_ns: int,
    checkpoint: Callable[[str], None] | None = None,
) -> dict:
    if v2_store.anchor_path.exists():
        _fail("MIGRATION_DOWNGRADE_REFUSED")

    def mark(name: str) -> None:
        if checkpoint is not None:
            checkpoint(name)

    source, before = _read_v1(Path(v1_root), service, v1_key)
    mark("SOURCE_AUTHENTICATED")
    _authorize(
        authorization,
        signature,
        public_key,
        source,
        service=service,
        release_sha256=release_sha256,
        now=now,
    )
    target = map_record(source, service, wall_time_ns=wall_time_ns)
    mark("RECORD_MAPPED")
    staging_file = Path(staging_file)
    if staging_file.exists():
        _fail("MIGRATION_SOURCE_INVALID")
    staged_bytes = _envelope(target, v2_store.key)
    with staging_file.open("xb") as handle:
        handle.write(staged_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    verified = _decode(staging_file.read_bytes(), v2_store.key, MAX_RECORD_BYTES)
    validate_record(verified, service)
    mark("STAGED_VERIFIED")
    committed = v2_store.provision(verified)
    mark("COMMITTED")
    after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in Path(v1_root).iterdir() if path.is_file()}
    if any(after.get(name) != digest for name, digest in before.items()):
        _fail("MIGRATION_SOURCE_INVALID")
    return committed

