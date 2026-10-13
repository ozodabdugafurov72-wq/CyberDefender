#!/usr/bin/env python3
"""Reconstruct a read-only review ZIP from Git objects at an exact reviewed commit.

No worktree changes, no elevated permissions, no deployment, no secrets read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile

PINNED_COMMIT = "1c5970e41877af4283cfe534b9441f0289b4e0e9"
DEFAULT_REPO_NAME = "CyberDefender-secure-owner-cloud-20261009"
MAX_FILE_BYTES = 30 * 1024 * 1024
MAX_TOTAL_BYTES = 150 * 1024 * 1024
MAX_FILES = 1500
EXCLUDED = frozenset({
    "scripts/install_machine.ps1",  # legacy all-three-services installer
    "cyberdefender_connect_staging.ps1",  # TEMP-only privileged wrapper
})
SECRET_COMPONENTS = frozenset({".env", "secrets", "secret", ".ssh", "credentials"})
SECRET_EXTS = frozenset({".key", ".pfx", ".p12", ".pem"})


def git(repo: Path, *args: str, binary: bool = False) -> bytes | str:
    env = dict(os.environ)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    result = subprocess.run(["git", "-C", str(repo), *args], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, timeout=60)
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def safe_relative_path(raw: bytes) -> str:
    name = raw.decode("utf-8", errors="strict")
    posix = PurePosixPath(name)
    if not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name:
        raise ValueError("unsafe archive member")
    if posix.is_absolute() or ".." in posix.parts or "." in posix.parts:
        raise ValueError("unsafe archive member")
    if any(part.lower() in SECRET_COMPONENTS for part in posix.parts):
        raise ValueError("secret-like path found in tracked source: " + name)
    if posix.suffix.lower() in SECRET_EXTS or any(part.lower().startswith(".env") for part in posix.parts):
        raise ValueError("secret-like tracked filename found: " + name)
    return name


def make_payload(repo: Path, commit: str | None = None) -> tuple[list[tuple[str, bytes]], dict]:
    if commit is None:
        commit = PINNED_COMMIT
    try:
        resolved = git(repo, "rev-parse", "--verify", commit + "^{commit}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("pinned Git commit not present locally") from exc
    if resolved != PINNED_COMMIT:
        raise ValueError("local Git commit differs from pinned reviewed revision")
    listing = git(repo, "ls-tree", "-r", "-z", "--full-tree", PINNED_COMMIT, binary=True)
    files: list[tuple[str, bytes]] = []
    manifest: list[dict] = []
    total = 0
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, typ, object_id = prefix.decode("ascii").split(" ", 2)
        name = safe_relative_path(raw_path)
        if mode not in {"100644", "100755"} or typ != "blob":
            raise ValueError("symlink/submodule or unsupported Git mode: " + name)
        if name in EXCLUDED:
            continue
        content = git(repo, "cat-file", "blob", object_id, binary=True)
        if len(content) > MAX_FILE_BYTES or total + len(content) > MAX_TOTAL_BYTES:
            raise ValueError("source exceeds bounded package limits")
        if hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest() != object_id:
            raise ValueError("Git object integrity mismatch: " + name)
        if content.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ValueError("LFS pointer cannot be used as executable source: " + name)
        files.append((name, content))
        manifest.append({"path": name, "sha256": hashlib.sha256(content).hexdigest(), "length": len(content)})
        total += len(content)
        if len(files) > MAX_FILES:
            raise ValueError("too many source files")
    required = {"agent/windows_service.py", "agent/main.py", "agent/service_lifecycle.py",
                "agent/service_runner.py", "agent/fleet/client.py", "control_plane/fleet_protocol.py",
                "control_plane/xdr_compat.py", "requirements.txt"}
    if not required.issubset({name for name, _ in files}):
        raise ValueError("critical Agent dependencies missing")
    meta = {"schema": "cyberdefender.pinned-review-source.v1", "commit": PINNED_COMMIT,
            "files": manifest, "total_bytes": total, "file_count": len(files),
            "purpose": "REVIEW_AND_PREFLIGHT_ONLY_NOT_AN_INSTALLER"}
    return files, meta


def build(repo: Path, target: Path) -> dict:
    files, meta = make_payload(repo)
    if target.exists():
        raise FileExistsError("Refusing to overwrite an existing candidate ZIP: " + str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    # ZIP is constructed from commit blobs, NOT from dirty working-tree files.
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=7) as z:
        for name, data in files:
            z.writestr("release/" + name, data)
        z.writestr("PINNED_MANIFEST.json", json.dumps(meta, sort_keys=True, indent=2) + "\n")
    return {"status": "PINNED_SOURCE_PREPARED_NO_DEPLOYMENT", "commit": PINNED_COMMIT,
            "files": len(files), "bytes": meta["total_bytes"],
            "zip_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "zip_path": str(target), "services_untouched": True,
            "credentials_untouched": True, "deployment_authorized": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(os.environ.get("TEMP", str(Path.home()))) / DEFAULT_REPO_NAME)
    p.add_argument("--out", type=Path, default=Path.home() / "Downloads" / "CD_AGENT_PINNED_REVIEW_1c5970e.zip")
    a = p.parse_args()
    try:
        result = build(a.repo.resolve(), a.out.resolve())
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)[:250],
                          "installed_untouched": True}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
