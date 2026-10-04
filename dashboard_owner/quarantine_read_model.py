from __future__ import annotations

"""Bounded, read-only projection of Quarantine v2 records.

This adapter intentionally does not import or construct the executor.  It
verifies the persisted record, receipt, evidence metadata/object and bounded
vault paths before exposing metadata to either dashboard surface.
"""

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Any


class QuarantineReadModel:
    VERSION = "1.0"
    SCHEMA = "cd.quarantine.record.v2"
    MAX_RECORDS = 64
    MAX_BYTES = 16 * 1024 * 1024
    MAX_ITEM_BYTES = 2 * 1024 * 1024
    MAX_RESPONSE_ITEMS = 100

    def __init__(self, root: str | Path | None = None, *, tenant_id: str | None = None) -> None:
        configured = root or os.environ.get(
            "CYBERDEFENDER_LAB_QUARANTINE_VAULT",
            r"C:\CD\LAB\LiveRansomwareVault",
        )
        self.root = Path(configured).expanduser().resolve()
        self.tenant_id = tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _sha256(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _safe_text(value: Any, maximum: int = 512) -> str | None:
        if not isinstance(value, str):
            return None
        value = value.strip()
        return value[:maximum] if value else None

    @staticmethod
    def _under(path: Path, root: Path) -> bool:
        try:
            return path.resolve(strict=False) == root.resolve(strict=False) or root.resolve(strict=False) in path.resolve(strict=False).parents
        except (OSError, RuntimeError, ValueError):
            return False

    @staticmethod
    def _has_reparse_component(path: Path) -> bool:
        """Reject symlink/reparse components before reading persisted data."""
        try:
            current = path.absolute()
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            while True:
                info = os.lstat(current)
                if current.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & reparse_flag):
                    return True
                if current.parent == current:
                    return False
                current = current.parent
        except (OSError, RuntimeError, ValueError):
            return True

    @classmethod
    def _strip_secrets(cls, value: Any) -> Any:
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                key_text = str(key).lower()
                if "token_mac" in key_text or key_text in {"secret", "private_key", "storage_key", "key_material"}:
                    continue
                result[str(key)] = cls._strip_secrets(item)
            return result
        if isinstance(value, list):
            return [cls._strip_secrets(item) for item in value[:128]]
        return value

    def _read_json(self, path: Path) -> dict[str, Any] | None:
        try:
            if not path.is_file() or path.stat().st_size > self.MAX_ITEM_BYTES:
                return None
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, UnicodeError, ValueError, TypeError):
            return None

    def _verify_evidence(self, record: dict[str, Any]) -> bool:
        evidence_id = self._safe_text(record.get("evidence_quarantine_id"), 128)
        if evidence_id is None or Path(evidence_id).name != evidence_id:
            return False
        metadata_path = self.root / "v2-evidence" / "records" / f"{evidence_id}.json"
        metadata = self._read_json(metadata_path)
        if not isinstance(metadata, dict):
            return False
        filename = self._safe_text(metadata.get("evidence_file"), 256)
        expected = self._safe_text(metadata.get("raw_sha256"), 64)
        if filename is None or Path(filename).name != filename or expected is None:
            return False
        evidence_path = self.root / "v2-evidence" / "evidence" / filename
        if (not self._under(evidence_path, self.root / "v2-evidence")
                or self._has_reparse_component(evidence_path)):
            return False
        try:
            raw = evidence_path.read_bytes()
            return len(raw) <= self.MAX_ITEM_BYTES and hmac.compare_digest(self._sha256(raw), expected)
        except (OSError, ValueError):
            return False

    def _verify_receipt(self, record: dict[str, Any]) -> bool:
        quarantine_id = self._safe_text(record.get("quarantine_id"), 128)
        if quarantine_id is None or Path(quarantine_id).name != quarantine_id:
            return False
        receipt = self._read_json(self.root / "v2-receipts" / f"{quarantine_id}.json")
        if not isinstance(receipt, dict):
            return False
        supplied = receipt.get("receipt_sha256")
        unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, self._sha256(self._canonical(unsigned))):
            return False
        linked = (
            receipt.get("state") == "QUARANTINED"
            and receipt.get("target_sha256") == record.get("target_sha256")
            and all(receipt.get(key) == record.get(key) for key in (
                "incident_id", "requested_action", "evidence_ref", "decision_digest",
                "capability_id", "scope_digest", "production_authorization", "lab_authorization",
            ))
        )
        return bool(linked)

    def _verify_object(self, record: dict[str, Any]) -> bool:
        object_path_text = self._safe_text(record.get("object_path"), 1024)
        target_hash = self._safe_text(record.get("target_sha256"), 64)
        if object_path_text is None or target_hash is None:
            return False
        object_path = Path(object_path_text).expanduser()
        objects_root = self.root / "v2-objects"
        if (not self._under(object_path, objects_root)
                or self._has_reparse_component(object_path)):
            return False
        try:
            raw = object_path.read_bytes()
            return len(raw) <= self.MAX_ITEM_BYTES and len(raw) == int(record.get("target_size")) and hmac.compare_digest(self._sha256(raw), target_hash)
        except (OSError, TypeError, ValueError):
            return False

    def _project(self, record: dict[str, Any], *, detail: bool, receipt_ok: bool, evidence_ok: bool, object_ok: bool) -> dict[str, Any]:
        state = self._safe_text(record.get("state"), 64) or "UNKNOWN"
        target = self._safe_text(record.get("original_path"), 512)
        target_hash = self._safe_text(record.get("target_sha256"), 64)
        tenant = self._safe_text(record.get("tenant_id"), 128) or "UNKNOWN"
        endpoint = self._safe_text(record.get("endpoint_id"), 128) or "UNKNOWN"
        item = {
            "quarantine_id": self._safe_text(record.get("quarantine_id"), 128),
            "incident_id": self._safe_text(record.get("incident_id"), 128),
            "endpoint_id": endpoint,
            "tenant_id": tenant,
            "timestamp": self._safe_text(record.get("contained_at"), 64) or self._safe_text(record.get("created_at"), 64),
            "target_name": Path(target).name if target else "UNKNOWN",
            "target_path": target,
            "target_sha256": target_hash,
            "target_sha256_short": target_hash[:12] if target_hash else "UNKNOWN",
            "detection_type": self._safe_text(record.get("detection_type"), 128) or self._safe_text(record.get("reason"), 128) or "UNKNOWN",
            "risk_score": record.get("risk_score"),
            "risk_level": self._safe_text(record.get("risk_level"), 32) or "UNKNOWN",
            "policy_outcome": self._safe_text(record.get("policy_outcome"), 64) or "UNKNOWN",
            "production_authorization": self._safe_text(record.get("production_authorization"), 64) or "NOT_GRANTED",
            "lab_authorization": self._safe_text(record.get("lab_authorization"), 96) or "NOT_GRANTED",
            "containment_state": state,
            "verification_outcome": self._safe_text(record.get("verification_outcome"), 64) or ("VERIFIED" if state == "QUARANTINED" and object_ok and receipt_ok else "UNKNOWN"),
            "evidence_status": "VERIFIED" if evidence_ok else "INTEGRITY_FAILURE",
            "object_integrity": object_ok,
            "evidence_integrity": evidence_ok,
            "receipt_integrity": receipt_ok,
            "post_action_verification": bool(state == "QUARANTINED" and object_ok and receipt_ok and evidence_ok),
            "recovery_required": bool(record.get("recovery_required", False)),
            "integrity_problem": not (evidence_ok and receipt_ok and (state != "QUARANTINED" or object_ok)),
        }
        if detail:
            item.update({
                "evidence_ref": self._safe_text(record.get("evidence_ref"), 256),
                "decision_digest": self._safe_text(record.get("decision_digest"), 64),
                "capability_id": self._safe_text(record.get("capability_id"), 128),
                "scope_digest": self._safe_text(record.get("scope_digest"), 64),
                "created_at": self._safe_text(record.get("created_at"), 64),
                "contained_at": self._safe_text(record.get("contained_at"), 64),
                "failure_code": self._safe_text(record.get("failure_code"), 128),
                "requested_action": self._safe_text(record.get("requested_action"), 64),
            })
        return self._strip_secrets(item)

    def _load(self, *, detail: bool) -> tuple[list[dict[str, Any]], int, int, int]:
        records_dir = self.root / "v2-records"
        if not records_dir.is_dir():
            return [], 0, 0, 0
        try:
            paths = sorted(records_dir.glob("*.json"))
        except OSError:
            return [], 1, 0, 0
        if len(paths) > self.MAX_RECORDS:
            return [], 1, 0, 0
        total = 0
        rows: list[dict[str, Any]] = []
        invalid = 0
        for path in paths:
            try:
                if self._has_reparse_component(path):
                    invalid += 1
                    continue
                total += path.stat().st_size
            except OSError:
                invalid += 1
                continue
            if total > self.MAX_BYTES:
                return [], 1, 0, total
            record = self._read_json(path)
            if not isinstance(record, dict) or record.get("schema") != self.SCHEMA:
                invalid += 1
                continue
            supplied = record.get("record_sha256")
            unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
            if not isinstance(supplied, str) or not hmac.compare_digest(supplied, self._sha256(self._canonical(unsigned))):
                invalid += 1
                continue
            tenant = self._safe_text(record.get("tenant_id"), 128) or "UNKNOWN"
            if self.tenant_id is not None and tenant != self.tenant_id:
                continue
            receipt_ok = self._verify_receipt(record)
            evidence_ok = self._verify_evidence(record)
            object_ok = self._verify_object(record) if record.get("state") == "QUARANTINED" else True
            rows.append(self._project(record, detail=detail, receipt_ok=receipt_ok, evidence_ok=evidence_ok, object_ok=object_ok))
        rows.sort(key=lambda row: str(row.get("timestamp") or ""), reverse=True)
        return rows[: self.MAX_RESPONSE_ITEMS], invalid, len(paths), total

    def _bounded_usage(self) -> tuple[int, bool]:
        """Return bounded vault usage without an unbounded recursive walk."""
        total = 0
        scanned = 0
        limited = False
        scan_limit = self.MAX_RECORDS * 8
        for directory in (self.root / "v2-records", self.root / "v2-receipts",
                          self.root / "v2-evidence", self.root / "v2-objects"):
            try:
                if not directory.is_dir():
                    continue
                for path in directory.rglob("*"):
                    if not path.is_file():
                        continue
                    scanned += 1
                    if scanned > scan_limit:
                        limited = True
                        return total, limited
                    try:
                        total += path.stat().st_size
                    except OSError:
                        limited = True
                        return total, limited
                    if total > self.MAX_BYTES:
                        return total, True
            except (OSError, RuntimeError, ValueError):
                return total, True
        return total, limited

    def snapshot(self, *, detail: bool = False) -> dict[str, Any]:
        rows, invalid, scanned, bytes_scanned = self._load(detail=detail)
        root_available = (self.root / "v2-records").is_dir()
        status = "UNAVAILABLE" if not root_available else "DEGRADED" if invalid or any(row.get("integrity_problem") for row in rows) else "OPERATIONAL"
        failed = sum(1 for row in rows if row.get("containment_state") in {"FAILED", "FAILED_AFTER_EFFECT", "UNKNOWN_AFTER_EFFECT"})
        pending = sum(1 for row in rows if row.get("containment_state") not in {"QUARANTINED", "FAILED", "FAILED_AFTER_EFFECT", "UNKNOWN_AFTER_EFFECT"})
        verified = sum(1 for row in rows if row.get("post_action_verification") is True)
        recovery = sum(1 for row in rows if row.get("recovery_required") is True)
        integrity = sum(1 for row in rows if row.get("integrity_problem") is True) + invalid
        usage, usage_limited = self._bounded_usage()
        if usage_limited:
            integrity += 1
            status = "DEGRADED"
        return {
            "schema": "cyberdefender.quarantine-read-model.v1",
            "version": self.VERSION,
            "status": status,
            "read_only": True,
            "authoritative": False,
            "tenant_scope": self.tenant_id or "LOCAL_READ_SCOPE",
            "production_authorization": "NOT_GRANTED",
            "lab_authorization": (
                "QUARANTINE_CAPABILITY_CONSUMED"
                if any(row.get("lab_authorization") == "QUARANTINE_CAPABILITY_CONSUMED" for row in rows)
                else "NOT_GRANTED"
            ),
            "summary": {
                "total_quarantined": sum(1 for row in rows if row.get("containment_state") == "QUARANTINED"),
                "verified_quarantined": verified,
                "pending_verification": pending,
                "failed_unknown": failed,
                "recovery_required": recovery,
                "evidence_integrity_problems": integrity,
                "affected_endpoints": len({row.get("endpoint_id") for row in rows}),
                "affected_tenants": len({row.get("tenant_id") for row in rows}),
                "high_critical": sum(1 for row in rows if row.get("risk_level") in {"HIGH", "CRITICAL"}),
                "containment_success_ratio": round(verified / len(rows), 4) if rows else None,
            },
            "vault": {"root_configured": True, "records_scanned": scanned, "bytes_scanned": bytes_scanned, "bytes_used": usage, "max_records": self.MAX_RECORDS, "max_bytes": self.MAX_BYTES},
            "items": rows,
            "error_count": invalid,
        }

    def detail(self, quarantine_id: str) -> dict[str, Any] | None:
        if not isinstance(quarantine_id, str) or not quarantine_id or Path(quarantine_id).name != quarantine_id:
            return None
        snapshot = self.snapshot(detail=True)
        return next((row for row in snapshot.get("items", []) if row.get("quarantine_id") == quarantine_id), None)
