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
import re
import subprocess
import sys
import zipfile

DEFAULT_REPO_NAME = "CyberDefender-secure-owner-cloud-20261009"
MAX_FILE_BYTES = 30 * 1024 * 1024
MAX_TOTAL_BYTES = 150 * 1024 * 1024
MAX_FILES = 1500
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_COMPRESSION = zipfile.ZIP_DEFLATED
ZIP_COMPRESSION_LEVEL = 7
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


def git_blobs(repo: Path, object_ids: list[str]) -> dict[str, bytes]:
    """Read all required blobs through one bounded Git batch process."""
    if not object_ids or len(object_ids) > MAX_FILES:
        raise ValueError("invalid Git blob request count")
    if len(set(object_ids)) != len(object_ids):
        raise ValueError("duplicate Git blob object id")
    env = dict(os.environ)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    process = subprocess.Popen(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    request = b"".join(object_id.encode("ascii") + b"\n" for object_id in object_ids)
    try:
        output, error = process.communicate(request, timeout=60)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise ValueError("Git blob batch timed out") from exc
    if process.returncode != 0:
        raise ValueError("Git blob batch failed: " + error.decode("utf-8", "replace")[:160])
    cursor = 0
    result: dict[str, bytes] = {}
    for requested in object_ids:
        newline = output.find(b"\n", cursor)
        if newline < 0:
            raise ValueError("truncated Git blob batch header")
        header = output[cursor:newline].decode("ascii", "strict").split()
        cursor = newline + 1
        if len(header) != 3 or header[0] != requested or header[1] != "blob":
            raise ValueError("unexpected Git blob batch response")
        try:
            size = int(header[2])
        except ValueError as exc:
            raise ValueError("invalid Git blob size") from exc
        if size < 0 or size > MAX_FILE_BYTES or cursor + size >= len(output):
            raise ValueError("Git blob exceeds bounded size")
        content = output[cursor:cursor + size]
        cursor += size
        if output[cursor:cursor + 1] != b"\n":
            raise ValueError("malformed Git blob batch framing")
        cursor += 1
        result[requested] = content
    if cursor != len(output):
        raise ValueError("unexpected trailing Git blob batch output")
    return result


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


def make_payload(repo: Path, commit: str) -> tuple[list[tuple[str, bytes]], dict]:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ValueError("commit must be a full 40-character Git SHA")
    commit = commit.lower()
    try:
        resolved = git(repo, "rev-parse", "--verify", commit + "^{commit}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("pinned Git commit not present locally") from exc
    if resolved != commit:
        raise ValueError("local Git commit differs from requested reviewed revision")
    listing = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, binary=True)
    entries: list[tuple[str, str]] = []
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
        entries.append((name, object_id))
        if len(entries) > MAX_FILES:
            raise ValueError("too many source files")

    entries.sort(key=lambda item: item[0])

    blobs = git_blobs(repo, list(dict.fromkeys(object_id for _, object_id in entries)))
    files: list[tuple[str, bytes]] = []
    manifest: list[dict] = []
    total = 0
    for name, object_id in entries:
        content = blobs[object_id]
        if len(content) > MAX_FILE_BYTES or total + len(content) > MAX_TOTAL_BYTES:
            raise ValueError("source exceeds bounded package limits")
        if hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest() != object_id:
            raise ValueError("Git object integrity mismatch: " + name)
        if content.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ValueError("LFS pointer cannot be used as executable source: " + name)
        files.append((name, content))
        manifest.append({"path": name, "sha256": hashlib.sha256(content).hexdigest(), "length": len(content)})
        total += len(content)
    required = {"agent/windows_service.py", "agent/main.py", "agent/service_lifecycle.py",
                "agent/service_runner.py", "agent/fleet/client.py", "control_plane/fleet_protocol.py",
                "control_plane/xdr_compat.py", "requirements.txt"}
    if not required.issubset({name for name, _ in files}):
        raise ValueError("critical Agent dependencies missing")
    meta = {"schema": "cyberdefender.pinned-review-source.v1", "commit": commit,
            "files": manifest, "total_bytes": total, "file_count": len(files),
            "purpose": "REVIEW_AND_PREFLIGHT_ONLY_NOT_AN_INSTALLER"}
    return files, meta


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    info.compress_type = ZIP_COMPRESSION
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build(repo: Path, target: Path, commit: str) -> dict:
    files, meta = make_payload(repo, commit)
    if target.exists():
        raise FileExistsError("Refusing to overwrite an existing candidate ZIP: " + str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    # ZIP is constructed from commit blobs, NOT from dirty working-tree files.
    with zipfile.ZipFile(
        target, "x", compression=ZIP_COMPRESSION,
        compresslevel=ZIP_COMPRESSION_LEVEL,
    ) as z:
        for name, data in files:
            z.writestr(
                _zip_info("release/" + name), data,
                compress_type=ZIP_COMPRESSION,
                compresslevel=ZIP_COMPRESSION_LEVEL,
            )
        z.writestr(
            _zip_info("PINNED_MANIFEST.json"),
            json.dumps(meta, sort_keys=True, indent=2) + "\n",
            compress_type=ZIP_COMPRESSION,
            compresslevel=ZIP_COMPRESSION_LEVEL,
        )
    return {"status": "PINNED_SOURCE_PREPARED_NO_DEPLOYMENT", "commit": meta["commit"],
            "files": len(files), "bytes": meta["total_bytes"],
            "zip_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "zip_path": str(target), "services_untouched": True,
            "credentials_untouched": True, "deployment_authorized": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(os.environ.get("TEMP", str(Path.home()))) / DEFAULT_REPO_NAME)
    p.add_argument("--commit", required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    try:
        result = build(a.repo.resolve(), a.out.resolve(), a.commit)
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)[:250],
                          "installed_untouched": True}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
