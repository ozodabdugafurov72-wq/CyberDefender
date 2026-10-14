#!/usr/bin/env python3
"""Fail-closed, read-only proof that pinned ZIP bytes match the exact Git commit.

Unlike the internal ZIP manifest verifier, this compares EVERY archived file
against the corresponding immutable Git object. No SCM, network or secret access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

from build_pinned_release import make_payload
from release_manager import verify as verify_zip


class ProvenanceError(ValueError):
    pass


def _release_inventory(root: Path, *, max_files: int, max_directories: int) -> set[str]:
    """Enumerate a release without following links or Windows reparse points."""
    observed: set[str] = set()
    observed_casefold: set[str] = set()
    stack = [root]
    directories = 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    while stack:
        current = stack.pop()
        directories += 1
        if directories > max_directories:
            raise ProvenanceError("RELEASE_DIRECTORY_LIMIT_EXCEEDED")
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    mode = info.st_mode
                    if (
                        entry.is_symlink()
                        or stat.S_ISLNK(mode)
                        or bool(getattr(info, "st_file_attributes", 0) & reparse_flag)
                    ):
                        raise ProvenanceError("RELEASE_REPARSE_POINT_REJECTED")
                    path = Path(entry.path)
                    if stat.S_ISDIR(mode):
                        stack.append(path)
                        continue
                    if not stat.S_ISREG(mode):
                        raise ProvenanceError("RELEASE_SPECIAL_FILE_REJECTED")
                    name = path.relative_to(root).as_posix()
                    folded = name.casefold()
                    if name in observed or folded in observed_casefold:
                        raise ProvenanceError("DUPLICATE_RELEASE_FILE")
                    observed.add(name)
                    observed_casefold.add(folded)
                    if len(observed) > max_files:
                        raise ProvenanceError("RELEASE_FILE_LIMIT_EXCEEDED")
        except ProvenanceError:
            raise
        except OSError as exc:
            raise ProvenanceError("RELEASE_INVENTORY_UNAVAILABLE") from exc
    return observed


def verify_provenance(
    repo: Path, package: Path, commit: str, zip_sha256: str,
    release_root: Path | None = None,
) -> dict:
    """Only Git committed regular files may be in the verified ZIP."""
    repo = Path(repo).resolve()
    package = Path(package).absolute()
    # Internal ZIP hash, bounded manifest and safe paths first.
    internal = verify_zip(package, zip_sha256, commit)
    files, expected_meta = make_payload(repo, commit)
    expected = dict(files)
    with zipfile.ZipFile(package, "r") as archive:
        try:
            meta = json.loads(archive.read("PINNED_MANIFEST.json"))
        except (KeyError, ValueError, UnicodeError) as exc:
            raise ProvenanceError("ZIP_MANIFEST_UNREADABLE") from exc
        if meta != expected_meta:
            raise ProvenanceError("GIT_MANIFEST_MISMATCH")
        for name, git_bytes in files:
            archived = archive.read("release/" + name)
            if archived != git_bytes:
                raise ProvenanceError("GIT_ZIP_BYTE_MISMATCH:" + name)
    if internal["files"] != len(files):
        raise ProvenanceError("GIT_ZIP_COUNT_MISMATCH")

    result = {
        "status": "GIT_ZIP_BYTE_PROVENANCE_PASS",
        "commit": commit.lower(),
        "zip_sha256": zip_sha256.lower(),
        "files_verified": len(files),
        "bytes_verified": sum(len(data) for _, data in files),
        "services_untouched": True,
        "credentials_untouched": True,
    }

    if release_root is not None:
        root = Path(release_root).absolute()
        if root.name != commit.lower() or not root.is_dir() or root.is_symlink():
            raise ProvenanceError("RELEASE_ROOT_REJECTED")
        # Installer adds exactly two non-archive files during extraction.
        allowed = set(expected) | {"agent_service_bootstrap.py", "source_commit.txt"}
        observed = _release_inventory(
            root,
            max_files=len(allowed),
            max_directories=max(32, len(allowed) * 2),
        )
        if observed != allowed:
            raise ProvenanceError("RELEASE_FILE_SET_MISMATCH")
        for name, git_bytes in files:
            disk_path = root.joinpath(*name.split("/"))
            if disk_path.read_bytes() != git_bytes:
                raise ProvenanceError("GIT_INSTALLED_BYTE_MISMATCH:" + name)
        marker = (root / "source_commit.txt").read_text(encoding="ascii").strip()
        if marker != commit.lower():
            raise ProvenanceError("RELEASE_COMMIT_MARKER_MISMATCH")
        result["installed_files_verified"] = len(files)
        result["status"] = "GIT_ZIP_RELEASE_PROVENANCE_PASS"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--zip", dest="package", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--release-root", type=Path)
    args = parser.parse_args()
    try:
        outcome = verify_provenance(
            args.repo, args.package, args.commit, args.sha256, args.release_root
        )
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({
            "status": "PROVENANCE_BLOCKED",
            "reason": type(exc).__name__ + ":" + str(exc)[:180],
        }, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
