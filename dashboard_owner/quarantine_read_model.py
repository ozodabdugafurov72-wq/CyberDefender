from __future__ import annotations

"""Bounded, read-only projection of the approved Quarantine v2 vaults.

The dashboard is deliberately a consumer of persisted evidence. It never
constructs the executor, accepts a vault path from a request, or treats a
publication/record as proof that containment succeeded. Vault discovery is
closed over the two approved LAB locations and every record remains subject to
the existing record, receipt, evidence and object integrity checks.
"""

import hashlib
import hmac
import itertools
import json
import os
import stat
from pathlib import Path
from typing import Any


class QuarantineReadModel:
    VERSION = "1.1"
    SCHEMA = "cd.quarantine.record.v2"
    MAX_RECORDS = 64
    MAX_TOTAL_RECORDS = 128
    MAX_BYTES = 16 * 1024 * 1024
    MAX_TOTAL_BYTES = 32 * 1024 * 1024
    MAX_ITEM_BYTES = 2 * 1024 * 1024
    MAX_RESPONSE_ITEMS = 100

    # Explicit allowlist; never derived by walking C:\\CD or from a request.
    APPROVED_VAULTS = (
        ("legacy", Path(r"C:\CD\LAB\QuarantineV2_Vault")),
        ("phase6", Path(r"C:\CD\LAB\LiveRansomwareVault")),
    )

    def __init__(self, root: str | Path | None = None, *, tenant_id: str | None = None) -> None:
        self.tenant_id = tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None
        self._configuration_error = False
        # root is retained as an internal/test injection point for the
        # established read-model contract. It is still checked against the
        # approved allowlist. The dashboard server never passes request data
        # here; production discovery uses only APPROVED_VAULTS.
        self._roots = self._resolve_roots(root)

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
    def _path_key(path: Path) -> str:
        return os.path.normcase(str(path))

    @staticmethod
    def _canonical_path(value: str | Path) -> Path:
        """Normalize a path without resolving a symlink/reparse root."""
        expanded = os.path.expanduser(str(value))
        return Path(os.path.normpath(os.path.abspath(expanded)))

    @staticmethod
    def _under(path: Path, root: Path) -> bool:
        try:
            candidate = path.resolve(strict=False)
            base = root.resolve(strict=False)
            return candidate == base or base in candidate.parents
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

    @classmethod
    def _approved_paths(cls) -> dict[str, Path]:
        result: dict[str, Path] = {}
        for label, value in cls.APPROVED_VAULTS:
            try:
                result[label] = cls._canonical_path(value)
            except (OSError, RuntimeError, ValueError):
                continue
        return result

    def _resolve_roots(self, root: str | Path | None) -> list[tuple[str, Path]]:
        if root is not None:
            try:
                candidate = self._canonical_path(root)
            except (OSError, RuntimeError, ValueError):
                self._configuration_error = True
                return []
            approved = self._approved_paths()
            matching = [(label, path) for label, path in approved.items() if self._path_key(path) == self._path_key(candidate)]
            if not matching:
                self._configuration_error = True
                return []
            return [("explicit", candidate)]

        approved = self._approved_paths()
        configured = os.environ.get("CYBERDEFENDER_LAB_QUARANTINE_VAULT", "").strip()
        ordered: list[tuple[str, Path]] = []
        if configured:
            try:
                configured_path = self._canonical_path(configured)
            except (OSError, RuntimeError, ValueError):
                self._configuration_error = True
                return []
            matching = [(label, path) for label, path in approved.items() if self._path_key(path) == self._path_key(configured_path)]
            if not matching:
                # Never fall back to an arbitrary configured location.
                self._configuration_error = True
                return []
            ordered.extend(matching)
        for label, path in approved.items():
            if not any(self._path_key(path) == self._path_key(existing) for _, existing in ordered):
                ordered.append((label, path))
        return ordered

    @classmethod
    def _root_state(cls, root: Path) -> str:
        """Return MISSING, INVALID or VALID without following a reparse root."""
        try:
            if not root.exists():
                return "MISSING"
            if not root.is_dir() or cls._has_reparse_component(root):
                return "INVALID"
            records = root / "v2-records"
            if not records.is_dir() or cls._has_reparse_component(records):
                return "INVALID"
            return "VALID"
        except (OSError, RuntimeError, ValueError):
            return "INVALID"

    def _read_json(self, path: Path) -> dict[str, Any] | None:
        try:
            if not path.is_file() or path.stat().st_size > self.MAX_ITEM_BYTES:
                return None
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, UnicodeError, ValueError, TypeError):
            return None

    def _verify_evidence(self, root: Path, record: dict[str, Any]) -> bool:
        evidence_id = self._safe_text(record.get("evidence_quarantine_id"), 128)
        if evidence_id is None or Path(evidence_id).name != evidence_id:
            return False
        evidence_root = root / "v2-evidence"
        metadata = self._read_json(evidence_root / "records" / f"{evidence_id}.json")
        if not isinstance(metadata, dict):
            return False
        filename = self._safe_text(metadata.get("evidence_file"), 256)
        expected = self._safe_text(metadata.get("raw_sha256"), 64)
        if filename is None or Path(filename).name != filename or expected is None:
            return False
        evidence_path = evidence_root / "evidence" / filename
        if not self._under(evidence_path, evidence_root) or self._has_reparse_component(evidence_path):
            return False
        try:
            raw = evidence_path.read_bytes()
            return len(raw) <= self.MAX_ITEM_BYTES and hmac.compare_digest(self._sha256(raw), expected)
        except (OSError, ValueError):
            return False

    def _verify_receipt(self, root: Path, record: dict[str, Any]) -> bool:
        quarantine_id = self._safe_text(record.get("quarantine_id"), 128)
        if quarantine_id is None or Path(quarantine_id).name != quarantine_id:
            return False
        receipt = self._read_json(root / "v2-receipts" / f"{quarantine_id}.json")
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

    def _verify_object(self, root: Path, record: dict[str, Any]) -> bool:
        object_path_text = self._safe_text(record.get("object_path"), 1024)
        target_hash = self._safe_text(record.get("target_sha256"), 64)
        if object_path_text is None or target_hash is None:
            return False
        object_path = Path(object_path_text).expanduser()
        objects_root = root / "v2-objects"
        if not self._under(object_path, objects_root) or self._has_reparse_component(object_path):
            return False
        try:
            raw = object_path.read_bytes()
            return len(raw) <= self.MAX_ITEM_BYTES and len(raw) == int(record.get("target_size")) and hmac.compare_digest(self._sha256(raw), target_hash)
        except (OSError, TypeError, ValueError):
            return False

    def _project(self, record: dict[str, Any], *, detail: bool, receipt_ok: bool, evidence_ok: bool, object_ok: bool, source_label: str) -> dict[str, Any]:
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
            "source_vault": source_label,
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

    def _load_vault(self, label: str, root: Path, *, detail: bool) -> dict[str, Any]:
        state = self._root_state(root)
        result: dict[str, Any] = {"label": label, "root": root, "state": state, "rows": [], "invalid": 0, "scanned": 0, "bytes_scanned": 0, "usage": 0, "usage_limited": False}
        if state != "VALID":
            return result
        records_dir = root / "v2-records"
        try:
            paths = list(itertools.islice(records_dir.glob("*.json"), self.MAX_RECORDS + 1))
        except (OSError, RuntimeError, ValueError):
            result["invalid"] = 1
            return result
        result["scanned"] = len(paths)
        if len(paths) > self.MAX_RECORDS:
            result["invalid"] = 1
            return result
        total = 0
        for path in paths:
            try:
                if self._has_reparse_component(path):
                    result["invalid"] += 1
                    continue
                total += path.stat().st_size
            except OSError:
                result["invalid"] += 1
                continue
            if total > self.MAX_BYTES:
                result["invalid"] += 1
                result["bytes_scanned"] = total
                return result
            record = self._read_json(path)
            if not isinstance(record, dict) or record.get("schema") != self.SCHEMA:
                result["invalid"] += 1
                continue
            supplied = record.get("record_sha256")
            unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
            if not isinstance(supplied, str) or not hmac.compare_digest(supplied, self._sha256(self._canonical(unsigned))):
                result["invalid"] += 1
                continue
            quarantine_id = self._safe_text(record.get("quarantine_id"), 128)
            if quarantine_id is None or Path(quarantine_id).name != quarantine_id:
                result["invalid"] += 1
                continue
            tenant = self._safe_text(record.get("tenant_id"), 128) or "UNKNOWN"
            if self.tenant_id is not None and tenant != self.tenant_id:
                continue
            receipt_ok = self._verify_receipt(root, record)
            evidence_ok = self._verify_evidence(root, record)
            object_ok = self._verify_object(root, record) if record.get("state") == "QUARANTINED" else True
            row = self._project(record, detail=detail, receipt_ok=receipt_ok, evidence_ok=evidence_ok, object_ok=object_ok, source_label=label)
            # Absolute object paths and the record MAC differ when identical
            # evidence is copied into another approved vault. Normalize only
            # that vault-local path before comparing duplicate content.
            fingerprint_payload = dict(unsigned)
            object_path_text = self._safe_text(record.get("object_path"), 1024)
            if object_path_text:
                object_path = Path(object_path_text).expanduser()
                objects_root = root / "v2-objects"
                try:
                    if self._under(object_path, objects_root):
                        fingerprint_payload["object_path"] = str(object_path.resolve(strict=False).relative_to(objects_root.resolve(strict=False)))
                except (OSError, RuntimeError, ValueError):
                    pass
            result["rows"].append({"row": row, "fingerprint": self._sha256(self._canonical(fingerprint_payload)), "verified_content": bool(receipt_ok and evidence_ok and (record.get("state") != "QUARANTINED" or object_ok))})
        result["bytes_scanned"] = total
        result["usage"], result["usage_limited"] = self._bounded_usage(root)
        if result["usage_limited"]:
            result["invalid"] += 1
        return result

    def _bounded_usage(self, root: Path) -> tuple[int, bool]:
        """Return bounded vault usage without an unbounded recursive walk."""
        total = 0
        scanned = 0
        scan_limit = self.MAX_RECORDS * 8
        for directory in (root / "v2-records", root / "v2-receipts", root / "v2-evidence", root / "v2-objects"):
            try:
                if not directory.is_dir():
                    continue
                if self._has_reparse_component(directory):
                    return total, True
                for path in directory.rglob("*"):
                    scanned += 1
                    if scanned > scan_limit:
                        return total, True
                    if not path.is_file():
                        if path.is_symlink() or self._has_reparse_component(path):
                            return total, True
                        continue
                    if self._has_reparse_component(path):
                        return total, True
                    total += path.stat().st_size
                    if total > self.MAX_BYTES:
                        return total, True
            except (OSError, RuntimeError, ValueError):
                return total, True
        return total, False

    def _aggregate(self, loaded: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for vault in loaded:
            for entry in vault["rows"]:
                qid = entry["row"].get("quarantine_id")
                if isinstance(qid, str):
                    grouped.setdefault(qid, []).append(entry)
        rows: list[dict[str, Any]] = []
        conflicts = 0
        for entries in grouped.values():
            first = entries[0]
            if len({entry["fingerprint"] for entry in entries}) == 1 and all(entry["verified_content"] for entry in entries):
                rows.append(first["row"])
                continue
            conflicts += 1
            selected = next((entry for entry in entries if entry["verified_content"]), first)
            row = dict(selected["row"])
            row["integrity_problem"] = True
            row["integrity_conflict"] = True
            row["verification_outcome"] = "INTEGRITY_CONFLICT"
            row["evidence_status"] = "INTEGRITY_CONFLICT"
            row["post_action_verification"] = False
            row["conflict_vaults"] = sorted({str(entry["row"].get("source_vault") or "UNKNOWN") for entry in entries})
            rows.append(self._strip_secrets(row))
        rows.sort(key=lambda row: str(row.get("timestamp") or ""), reverse=True)
        return rows[: self.MAX_RESPONSE_ITEMS], conflicts, len(grouped)

    def snapshot(self, *, detail: bool = False) -> dict[str, Any]:
        loaded = [self._load_vault(label, root, detail=detail) for label, root in self._roots]
        valid = [item for item in loaded if item["state"] == "VALID"]
        rows, conflicts, unique_count = self._aggregate(valid)
        invalid = sum(int(item["invalid"]) + (1 if item["state"] == "INVALID" else 0) for item in loaded) + (1 if self._configuration_error else 0)
        total_records = sum(int(item["scanned"]) for item in loaded)
        total_bytes = sum(int(item["bytes_scanned"]) for item in loaded)
        if total_records > self.MAX_TOTAL_RECORDS or total_bytes > self.MAX_TOTAL_BYTES:
            invalid += 1
        usage = sum(int(item["usage"]) for item in valid)
        usage_limited = any(bool(item["usage_limited"]) for item in valid)
        if unique_count > self.MAX_RESPONSE_ITEMS:
            invalid += 1
        integrity = sum(1 for row in rows if row.get("integrity_problem")) + invalid
        if usage_limited:
            integrity += 1
        if not valid:
            status = "UNAVAILABLE"
        elif invalid or conflicts or usage_limited:
            status = "DEGRADED"
        else:
            status = "OPERATIONAL"
        failed = sum(1 for row in rows if row.get("containment_state") in {"FAILED", "FAILED_AFTER_EFFECT", "UNKNOWN_AFTER_EFFECT"})
        pending = sum(1 for row in rows if row.get("containment_state") not in {"QUARANTINED", "FAILED", "FAILED_AFTER_EFFECT", "UNKNOWN_AFTER_EFFECT"})
        verified = sum(1 for row in rows if row.get("post_action_verification") is True)
        recovery = sum(1 for row in rows if row.get("recovery_required") is True)
        return {
            "schema": "cyberdefender.quarantine-read-model.v1", "version": self.VERSION,
            "status": status, "read_only": True, "authoritative": False,
            "tenant_scope": self.tenant_id or "LOCAL_READ_SCOPE",
            "production_authorization": "NOT_GRANTED",
            "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED" if any(row.get("lab_authorization") == "QUARANTINE_CAPABILITY_CONSUMED" for row in rows) else "NOT_GRANTED",
            "summary": {
                "total_quarantined": sum(1 for row in rows if row.get("containment_state") == "QUARANTINED"),
                "verified_quarantined": verified, "pending_verification": pending,
                "failed_unknown": failed, "recovery_required": recovery,
                "evidence_integrity_problems": integrity,
                "affected_endpoints": len({row.get("endpoint_id") for row in rows}),
                "affected_tenants": len({row.get("tenant_id") for row in rows}),
                "high_critical": sum(1 for row in rows if row.get("risk_level") in {"HIGH", "CRITICAL"}),
                "containment_success_ratio": round(verified / len(rows), 4) if rows else None,
            },
            "vault": {"root_configured": bool(self._roots), "records_scanned": total_records, "bytes_scanned": total_bytes, "bytes_used": usage, "max_records": self.MAX_TOTAL_RECORDS, "max_bytes": self.MAX_TOTAL_BYTES},
            "vaults": [{"name": item["label"], "status": item["state"], "records_scanned": item["scanned"], "bytes_scanned": item["bytes_scanned"], "bytes_used": item["usage"], "error_count": item["invalid"]} for item in loaded],
            "integrity_conflicts": conflicts, "items": rows, "error_count": invalid,
        }

    def detail(self, quarantine_id: str) -> dict[str, Any] | None:
        if not isinstance(quarantine_id, str) or not quarantine_id or Path(quarantine_id).name != quarantine_id:
            return None
        snapshot = self.snapshot(detail=True)
        return next((row for row in snapshot.get("items", []) if row.get("quarantine_id") == quarantine_id), None)
