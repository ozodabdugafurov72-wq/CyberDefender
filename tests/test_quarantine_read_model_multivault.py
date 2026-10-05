from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard_owner.quarantine_read_model import QuarantineReadModel


REAL_LEGACY = Path(r"C:\CD\LAB\QuarantineV2_Vault")


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _copy_vault(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination)
    # Persisted object_path values are absolute. Rebind them to the isolated
    # copy and recompute only the record integrity field.
    records = destination / "v2-records"
    for path in records.glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        object_name = Path(str(record["object_path"])).name
        object_candidates = list((destination / "v2-objects" / str(record["quarantine_id"])).glob(object_name))
        record["object_path"] = str(object_candidates[0])
        record.pop("record_sha256", None)
        record["record_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
        path.write_text(json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")), encoding="utf-8")


class MultiVaultReadModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cd-multivault-")
        self.base = Path(self.temp.name)
        self.legacy = self.base / "legacy"
        self.live = self.base / "live"
        self.old_allowlist = QuarantineReadModel.APPROVED_VAULTS
        self.old_env = os.environ.pop("CYBERDEFENDER_LAB_QUARANTINE_VAULT", None)
        QuarantineReadModel.APPROVED_VAULTS = (("legacy", self.legacy), ("phase6", self.live))

    def tearDown(self) -> None:
        QuarantineReadModel.APPROVED_VAULTS = self.old_allowlist
        if self.old_env is not None:
            os.environ["CYBERDEFENDER_LAB_QUARANTINE_VAULT"] = self.old_env
        else:
            os.environ.pop("CYBERDEFENDER_LAB_QUARANTINE_VAULT", None)
        self.temp.cleanup()

    def _legacy(self) -> None:
        _copy_vault(REAL_LEGACY, self.legacy)

    def _live(self) -> None:
        _copy_vault(REAL_LEGACY, self.live)

    def test_only_legacy_and_missing_phase6_remains_operational(self) -> None:
        self._legacy()
        snapshot = QuarantineReadModel().snapshot(detail=True)
        self.assertEqual(snapshot["status"], "OPERATIONAL")
        self.assertEqual(snapshot["summary"]["total_quarantined"], 2)
        self.assertEqual(snapshot["summary"]["verified_quarantined"], 2)
        self.assertEqual({item["status"] for item in snapshot["vaults"]}, {"VALID", "MISSING"})

    def test_valid_vault_plus_existing_unusable_vault_is_degraded(self) -> None:
        self._legacy()
        self.live.mkdir()
        snapshot = QuarantineReadModel().snapshot()
        self.assertEqual(snapshot["status"], "DEGRADED")
        self.assertEqual(snapshot["summary"]["total_quarantined"], 2)
        self.assertGreaterEqual(snapshot["error_count"], 1)

    def test_only_live_vault_is_supported(self) -> None:
        self._live()
        snapshot = QuarantineReadModel().snapshot()
        self.assertEqual(snapshot["status"], "OPERATIONAL")
        self.assertEqual(snapshot["summary"]["total_quarantined"], 2)
        self.assertEqual(snapshot["vaults"][0]["status"], "MISSING")

    def test_both_vaults_deduplicate_identical_verified_records(self) -> None:
        self._legacy()
        self._live()
        snapshot = QuarantineReadModel().snapshot(detail=True)
        self.assertEqual(snapshot["status"], "OPERATIONAL")
        self.assertEqual(snapshot["summary"]["total_quarantined"], 2)
        self.assertEqual(snapshot["integrity_conflicts"], 0)
        self.assertEqual(len(snapshot["items"]), 2)

    def test_configured_approved_vault_is_first_but_does_not_hide_other_vault(self) -> None:
        self._legacy()
        self._live()
        os.environ["CYBERDEFENDER_LAB_QUARANTINE_VAULT"] = str(self.live)
        snapshot = QuarantineReadModel().snapshot()
        self.assertEqual([item["name"] for item in snapshot["vaults"]], ["phase6", "legacy"])
        self.assertEqual(snapshot["summary"]["total_quarantined"], 2)

    def test_both_missing_is_unavailable(self) -> None:
        snapshot = QuarantineReadModel().snapshot()
        self.assertEqual(snapshot["status"], "UNAVAILABLE")
        self.assertEqual(snapshot["items"], [])

    def test_conflicting_duplicate_is_degraded_and_visible(self) -> None:
        self._legacy()
        self._live()
        path = sorted((self.live / "v2-records").glob("*.json"))[0]
        record = json.loads(path.read_text(encoding="utf-8"))
        record["target_sha256"] = "f" * 64
        record.pop("record_sha256", None)
        record["record_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
        path.write_text(json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        snapshot = QuarantineReadModel().snapshot(detail=True)
        self.assertEqual(snapshot["status"], "DEGRADED")
        self.assertEqual(snapshot["integrity_conflicts"], 1)
        self.assertTrue(any(item.get("integrity_conflict") for item in snapshot["items"]))

    def test_malformed_receipt_evidence_and_object_remain_degraded(self) -> None:
        self._legacy()
        record_path = sorted((self.legacy / "v2-records").glob("*.json"))[0]
        record = json.loads(record_path.read_text(encoding="utf-8"))
        receipt_path = self.legacy / "v2-receipts" / f"{record['quarantine_id']}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["target_sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        evidence_path = next((self.legacy / "v2-evidence" / "evidence").glob("*"))
        evidence_path.write_text("tampered", encoding="utf-8")
        object_path = Path(record["object_path"])
        object_path.write_text("tampered object", encoding="utf-8")
        snapshot = QuarantineReadModel().snapshot(detail=True)
        self.assertEqual(snapshot["status"], "DEGRADED")
        self.assertGreaterEqual(snapshot["summary"]["evidence_integrity_problems"], 1)
        self.assertTrue(any(not item["receipt_integrity"] for item in snapshot["items"]))
        self.assertTrue(any(not item["object_integrity"] for item in snapshot["items"]))

    def test_malformed_record_is_retained_as_error_and_not_trusted(self) -> None:
        self._legacy()
        (self.legacy / "v2-records" / "malformed.json").write_text("{broken", encoding="utf-8")
        snapshot = QuarantineReadModel().snapshot()
        self.assertEqual(snapshot["status"], "DEGRADED")
        self.assertEqual(snapshot["summary"]["total_quarantined"], 2)
        self.assertGreaterEqual(snapshot["error_count"], 1)

    def test_unapproved_configured_path_is_rejected(self) -> None:
        os.environ["CYBERDEFENDER_LAB_QUARANTINE_VAULT"] = str(self.base / ".." / "outside")
        self._legacy()
        snapshot = QuarantineReadModel().snapshot()
        self.assertEqual(snapshot["status"], "UNAVAILABLE")
        self.assertEqual(snapshot["items"], [])

    def test_tenant_filter_and_secret_stripping(self) -> None:
        self._legacy()
        path = sorted((self.legacy / "v2-records").glob("*.json"))[0]
        record = json.loads(path.read_text(encoding="utf-8"))
        record["tenant_id"] = "tenant-a"
        record["token_mac"] = "must-never-leave-vault"
        record.pop("record_sha256", None)
        record["record_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
        path.write_text(json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        snapshot = QuarantineReadModel(tenant_id="tenant-a").snapshot(detail=True)
        self.assertTrue(snapshot["items"])
        self.assertTrue(all(item["tenant_id"] == "tenant-a" for item in snapshot["items"]))
        self.assertNotIn("token_mac", json.dumps(snapshot))

    def test_record_and_byte_limits_are_bounded(self) -> None:
        self._legacy()
        model = QuarantineReadModel()
        model.MAX_RECORDS = 1
        limited = model.snapshot()
        self.assertEqual(limited["status"], "DEGRADED")
        self.assertEqual(limited["items"], [])
        model.MAX_RECORDS = 64
        model.MAX_BYTES = 100
        limited_bytes = model.snapshot()
        self.assertEqual(limited_bytes["status"], "DEGRADED")
        self.assertEqual(limited_bytes["items"], [])

    def test_reparse_vault_root_is_not_trusted_when_supported(self) -> None:
        self._legacy()
        link = self.base / "link"
        try:
            os.symlink(self.legacy, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            # Preserve deterministic coverage on hosts where creating a real
            # Windows reparse point requires an unavailable privilege.
            link.mkdir()
            QuarantineReadModel.APPROVED_VAULTS = (("legacy", link),)
            with patch.object(QuarantineReadModel, "_has_reparse_component", staticmethod(lambda _path: True)):
                self.assertEqual(QuarantineReadModel().snapshot()["status"], "UNAVAILABLE")
            return
        QuarantineReadModel.APPROVED_VAULTS = (("legacy", link),)
        snapshot = QuarantineReadModel().snapshot()
        self.assertEqual(snapshot["status"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
