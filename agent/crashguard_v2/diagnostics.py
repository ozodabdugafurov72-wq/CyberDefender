"""Bounded sanitized v2 diagnostics independent of the authenticated store."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from agent.crashguard_v2.failure_codes import DIAGNOSTIC_FAILURE_CODES


MAX_DIAGNOSTIC_BYTES = 512


def write_diagnostic(path: Path, *, code: str, stage: str, exception_class: str) -> None:
    if code not in DIAGNOSTIC_FAILURE_CODES:
        code = "CRASH_STORE_COMMIT_FAILED"
    safe_stage = stage if stage.isascii() and stage.replace("_", "").isalnum() else "UNKNOWN_STAGE"
    safe_class = exception_class if exception_class.isidentifier() and exception_class.isascii() else "Unavailable"
    fingerprint = hashlib.sha256((safe_stage + ":" + safe_class).encode("ascii")).hexdigest()[:16]
    payload = json.dumps(
        {
            "schema": "cd.crashguard-diagnostic.v2",
            "code": code,
            "stage": safe_stage[:48],
            "exception_class": safe_class[:64],
            "fingerprint": fingerprint,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(payload) > MAX_DIAGNOSTIC_BYTES:
        raise RuntimeError("CG2_DIAGNOSTIC_OVERSIZE")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=".cg2-diagnostic-", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)

