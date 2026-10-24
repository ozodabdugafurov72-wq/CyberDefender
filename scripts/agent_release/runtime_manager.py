"""Verify and safely extract a pinned official Python runtime ZIP."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import zipfile


MAX_ZIP_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 180 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_FILES = 4000
SCHEMA = "cyberdefender.pinned-python-runtime.v1"
PYTHON_INPUT = {
    "name": "python-3.14.7-amd64.zip",
    "sha256": "ac1a727a71738e11de80b76e975f9b8a258aea6412bfc31696b929d59c6aafd0",
}
WHEEL_INPUTS = {
    "cffi-2.1.1-cp314-cp314-win_amd64.whl": "3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2c7016b8432fde48",
    "cryptography-50.0.2-cp311-abi3-win_amd64.whl": "7afa5a6602a9f29af1f3a2965f831bae7c9d5d597b7cbb716d41ab3b7d89879c",
    "psutil-7.2.2-cp37-abi3-win_amd64.whl": "eb7e81434c8d223ec4a219b5fc1c47d0417b12be7ea866e24fb5ad6e84b3d988",
    "pycparser-3.11-py3-none-any.whl": "51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80",
    "pywin32-312-cp314-cp314-win_amd64.whl": "a4dd3a848290ef724347b19f301045831d8e802fa4464f491b98b1e0a081432e",
}
REQUIRED = frozenset({
    "python.exe", "python314.dll", "python3.dll", "vcruntime140.dll",
    "Lib/encodings/__init__.py", "DLLs/_ctypes.pyd",
})
DOS_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "123456789¹²³"}
)


def _safe_name(name: str) -> bool:
    if not isinstance(name, str) or not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name:
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return False
    for part in path.parts:
        if part.endswith((" ", ".")) or part.split(".", 1)[0].upper() in DOS_NAMES:
            return False
        if re.search(r'[<>|?*\x00-\x1f]', part):
            return False
    return True


def _snapshot(package: Path, approved_sha: str) -> bytes:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", approved_sha):
        raise ValueError("approved runtime SHA-256 must be 64 hex digits")
    if not package.is_file() or package.stat().st_size > MAX_ZIP_BYTES:
        raise ValueError("runtime ZIP missing or oversized")
    with package.open("rb") as source:
        payload = source.read(MAX_ZIP_BYTES + 1)
    if len(payload) > MAX_ZIP_BYTES:
        raise ValueError("runtime ZIP exceeds bounded size")
    if hashlib.sha256(payload).hexdigest() != approved_sha.lower():
        raise ValueError("runtime ZIP SHA256 mismatch")
    return payload


def _verify(payload: bytes, approved_sha: str) -> tuple[dict, list[zipfile.ZipInfo]]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        entries = archive.infolist()
        if not 0 < len(entries) <= MAX_FILES:
            raise ValueError("invalid runtime entry count")
        names = [entry.filename for entry in entries]
        if len({name.casefold() for name in names}) != len(names):
            raise ValueError("duplicate case-insensitive runtime path")
        if "RUNTIME_MANIFEST.json" not in names:
            raise ValueError("runtime manifest missing")
        manifest_info = archive.getinfo("RUNTIME_MANIFEST.json")
        if manifest_info.file_size > 4 * 1024 * 1024:
            raise ValueError("runtime manifest oversized")
        meta = json.loads(archive.read(manifest_info))
        expected_wheels = [{"name": name, "sha256": digest} for name, digest in sorted(WHEEL_INPUTS.items())]
        if meta.get("schema") != SCHEMA or meta.get("python") != PYTHON_INPUT or meta.get("wheels") != expected_wheels:
            raise ValueError("runtime input provenance mismatch")
        manifest = meta.get("files")
        if not isinstance(manifest, list) or not manifest or len(manifest) >= MAX_FILES:
            raise ValueError("invalid runtime file manifest")
        by_name = {entry.filename: entry for entry in entries if entry.filename != "RUNTIME_MANIFEST.json"}
        if set(by_name) != {item.get("path") for item in manifest if isinstance(item, dict)}:
            raise ValueError("runtime manifest membership mismatch")
        total = 0
        files: list[zipfile.ZipInfo] = []
        seen: set[str] = set()
        for item in manifest:
            if not isinstance(item, dict):
                raise ValueError("invalid runtime manifest record")
            name, length, expected_hash = item.get("path"), item.get("length"), item.get("sha256")
            if not isinstance(name, str) or not _safe_name(name) or name.casefold() in seen:
                raise ValueError("unsafe or duplicate runtime manifest path")
            if name.lower().endswith(".pth"):
                raise ValueError("runtime .pth execution is forbidden")
            if not isinstance(length, int) or isinstance(length, bool) or length < 0 or length > MAX_FILE_BYTES:
                raise ValueError("invalid runtime manifest length")
            if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise ValueError("invalid runtime manifest digest")
            entry = by_name[name]
            if entry.is_dir() or entry.file_size != length or entry.flag_bits & 1:
                raise ValueError("unsafe runtime member")
            file_type = (entry.external_attr >> 16) & 0o170000
            if file_type not in (0, 0o100000):
                raise ValueError("nonregular runtime member")
            digest = hashlib.sha256()
            measured = 0
            with archive.open(entry, "r") as source:
                while True:
                    chunk = source.read(1 << 20)
                    if not chunk:
                        break
                    measured += len(chunk)
                    if measured > length or measured > MAX_FILE_BYTES:
                        raise ValueError("runtime member expanded unexpectedly")
                    digest.update(chunk)
            if measured != length or digest.hexdigest() != expected_hash:
                raise ValueError("runtime member integrity mismatch")
            total += measured
            if total > MAX_EXPANDED_BYTES:
                raise ValueError("runtime expands beyond limit")
            files.append(entry)
            seen.add(name.casefold())
        if total != meta.get("total_bytes") or len(files) != meta.get("file_count"):
            raise ValueError("runtime manifest totals mismatch")
        if not REQUIRED.issubset({entry.filename for entry in files}):
            raise ValueError("required runtime files missing")
        files.append(manifest_info)
    return ({
        "status": "PINNED_RUNTIME_VERIFIED",
        "files": len(files),
        "bytes": total,
        "sha256": approved_sha.lower(),
        "services_untouched": True,
    }, files)


def verify(package: Path, approved_sha: str) -> dict:
    result, _ = _verify(_snapshot(package, approved_sha), approved_sha)
    return result


def extract(package: Path, destination: Path, approved_sha: str) -> dict:
    payload = _snapshot(package, approved_sha)
    result, entries = _verify(payload, approved_sha)
    if destination.exists() or destination.name != "runtime":
        raise ValueError("runtime destination already exists or is unexpected")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("runtime parent is unavailable")
    made = False
    try:
        destination.mkdir(mode=0o700)
        made = True
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for entry in entries:
                target = destination.joinpath(*PurePosixPath(entry.filename).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with archive.open(entry, "r") as source, target.open("xb") as output:
                    total = 0
                    while True:
                        chunk = source.read(1 << 20)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > entry.file_size or total > MAX_FILE_BYTES:
                            raise ValueError("runtime member expanded unexpectedly")
                        digest.update(chunk)
                        output.write(chunk)
                if total != entry.file_size:
                    raise ValueError("runtime member length mismatch")
                with target.open("rb") as copied:
                    post = hashlib.file_digest(copied, "sha256").hexdigest()
                if post != digest.hexdigest():
                    raise ValueError("runtime post-write integrity failure")
        result["status"] = "PINNED_RUNTIME_EXTRACTED"
        result["runtime_path"] = str(destination)
        return result
    except Exception:
        if made:
            shutil.rmtree(destination, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("verify", "extract"))
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--dest", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "verify":
            result = verify(args.zip, args.sha256)
        else:
            if args.dest is None:
                raise ValueError("runtime destination required")
            result = extract(args.zip, args.dest, args.sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
