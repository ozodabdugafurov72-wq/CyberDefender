"""Offline Git→ZIP→extracted-release provenance tests (no Windows services)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

TOOLS = Path(__file__).resolve().parents[1] / "scripts" / "agent_release"
sys.path.insert(0, str(TOOLS))
import build_pinned_release as builder
import release_manager
from verify_git_zip_provenance import ProvenanceError, verify_provenance


class GitZipProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        for name in set(release_manager.REQUIRED) | {"agent/storage/durable_spool.py"}:
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"secure stable source: " + name.encode("utf-8") + b"\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=CI",
                        "-c", "user.email=ci@example.invalid", "commit", "-qm", "baseline"], check=True)
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True
        ).strip()
        self.archive = self.root / "candidate.zip"
        builder.build(self.repo, self.archive, self.commit)
        self.sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_git_zip_byte_identical_passes(self):
        result = verify_provenance(self.repo, self.archive, self.commit, self.sha)
        self.assertEqual(result["status"], "GIT_ZIP_BYTE_PROVENANCE_PASS")
        self.assertGreater(result["files_verified"], 0)

    def test_manifest_and_archive_match_each_other_but_not_git_fails(self):
        # Deliberately tamper with durable_spool AND regenerate its manifest
        # and outer ZIP SHA. Internal ZIP verifier should accept this package.
        modified = self.root / "repacked.zip"
        with zipfile.ZipFile(self.archive, "r") as original:
            members = {name: original.read(name) for name in original.namelist()}
        target = "release/agent/storage/durable_spool.py"
        members[target] += b"# post-commit unapproved change\n"
        meta = json.loads(members["PINNED_MANIFEST.json"])
        for item in meta["files"]:
            if item["path"] == "agent/storage/durable_spool.py":
                item["sha256"] = hashlib.sha256(members[target]).hexdigest()
                item["length"] = len(members[target])
                meta["total_bytes"] += len(b"# post-commit unapproved change\n")
                break
        members["PINNED_MANIFEST.json"] = json.dumps(meta).encode("utf-8")
        with zipfile.ZipFile(modified, "w") as z:
            for name, payload in members.items():
                z.writestr(name, payload)
        digest = hashlib.sha256(modified.read_bytes()).hexdigest()
        release_manager.verify(modified, digest, self.commit)
        with self.assertRaisesRegex(ProvenanceError, "GIT_MANIFEST_MISMATCH"):
            verify_provenance(self.repo, modified, self.commit, digest)

    def test_verified_extraction_byte_identical_passes(self):
        parent = self.root / "agent-releases"
        parent.mkdir()
        dest = parent / self.commit
        bootstrap = self.root / "agent_service_bootstrap.py"
        bootstrap.write_bytes(b"# bootstrap only\n")
        release_manager.unpack(self.archive, dest, self.sha, self.commit, bootstrap)
        result = verify_provenance(self.repo, self.archive, self.commit, self.sha, dest)
        self.assertEqual(result["status"], "GIT_ZIP_RELEASE_PROVENANCE_PASS")

    def test_extracted_durable_spool_tamper_blocks(self):
        parent = self.root / "agent-releases"
        parent.mkdir()
        dest = parent / self.commit
        bootstrap = self.root / "agent_service_bootstrap.py"
        bootstrap.write_bytes(b"# bootstrap only\n")
        release_manager.unpack(self.archive, dest, self.sha, self.commit, bootstrap)
        with (dest / "agent/storage/durable_spool.py").open("ab") as f:
            f.write(b"# modified by unapproved installer\n")
        with self.assertRaisesRegex(ProvenanceError, "GIT_INSTALLED_BYTE_MISMATCH"):
            verify_provenance(self.repo, self.archive, self.commit, self.sha, dest)

    def test_extracted_release_reparse_point_is_rejected_without_traversal(self):
        parent = self.root / "agent-releases"
        parent.mkdir()
        dest = parent / self.commit
        bootstrap = self.root / "agent_service_bootstrap.py"
        bootstrap.write_bytes(b"# bootstrap only\n")
        release_manager.unpack(self.archive, dest, self.sha, self.commit, bootstrap)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "untrusted.py").write_text("raise SystemExit\n", encoding="utf-8")
        try:
            (dest / "linked-outside").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlink creation is unavailable")
        with self.assertRaisesRegex(ProvenanceError, "REPARSE_POINT"):
            verify_provenance(self.repo, self.archive, self.commit, self.sha, dest)

    def test_wrong_commit_blocks(self):
        wrong = "0" * 40
        with self.assertRaises(ValueError):
            verify_provenance(self.repo, self.archive, wrong, self.sha)

    def test_outer_hash_corruption_blocks(self):
        with self.archive.open("ab") as f:
            f.write(b"CHANGED")
        with self.assertRaises(ValueError):
            verify_provenance(self.repo, self.archive, self.commit, self.sha)


if __name__ == "__main__":
    unittest.main()
