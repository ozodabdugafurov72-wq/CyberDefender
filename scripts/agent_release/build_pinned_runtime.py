"""Build a deterministic, self-contained Python runtime from pinned inputs."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile

from runtime_manager import _safe_name


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
PYWIN32_PTH_SHA256 = "e7cd73df98b91c407dfd96d1f4dd18b7f9a60f29902b92cf5ece79b6eb637b81"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _approved_bytes(path: Path, expected: str) -> bytes:
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("pinned input hash mismatch: " + path.name)
    return payload


def _member_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.is_dir() or not _safe_name(info.filename) or info.flag_bits & 1:
        raise ValueError("unsafe pinned input member")
    file_type = (info.external_attr >> 16) & 0o170000
    if file_type not in (0, 0o100000) or info.file_size > 32 * 1024 * 1024:
        raise ValueError("unsupported pinned input member")
    data = archive.read(info)
    if len(data) != info.file_size:
        raise ValueError("truncated pinned input member")
    return data


def _add(files: dict[str, bytes], name: str, data: bytes) -> None:
    if not _safe_name(name) or name.casefold() in {item.casefold() for item in files}:
        raise ValueError("unsafe or duplicate output member: " + name)
    files[name] = data


def collect(python_zip: Path, wheels_dir: Path) -> tuple[dict[str, bytes], dict]:
    files: dict[str, bytes] = {}
    python_payload = _approved_bytes(python_zip, PYTHON_INPUT["sha256"])
    with zipfile.ZipFile(io.BytesIO(python_payload)) as archive:
        for info in archive.infolist():
            if not info.is_dir():
                _add(files, info.filename, _member_bytes(archive, info))
    actual_wheels = {path.name for path in wheels_dir.glob("*.whl")}
    if actual_wheels != set(WHEEL_INPUTS):
        raise ValueError("wheel input set differs from pinned set")
    for wheel_name, expected in sorted(WHEEL_INPUTS.items()):
        wheel = wheels_dir / wheel_name
        wheel_payload = _approved_bytes(wheel, expected)
        with zipfile.ZipFile(io.BytesIO(wheel_payload)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if ".data/" in name:
                    parts = PurePosixPath(name).parts
                    data_index = next(i for i, part in enumerate(parts) if part.endswith(".data"))
                    scheme = parts[data_index + 1]
                    if scheme in ("purelib", "platlib"):
                        relative = "/".join(parts[data_index + 2 :])
                    elif scheme == "scripts":
                        continue
                    else:
                        raise ValueError("unsupported wheel data scheme: " + scheme)
                else:
                    relative = name
                target = "Lib/site-packages/" + relative
                data = _member_bytes(archive, info)
                if target.lower().endswith(".pth"):
                    if target != "Lib/site-packages/pywin32.pth" or hashlib.sha256(data).hexdigest() != PYWIN32_PTH_SHA256:
                        raise ValueError("unexpected .pth input")
                    # Avoid implicit executable .pth behavior. The bootstrap adds
                    # the three pinned pywin32 subdirectories explicitly.
                    continue
                _add(files, target, data)
    manifest_files = [
        {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files.items())
    ]
    manifest = {
        "schema": SCHEMA,
        "python": PYTHON_INPUT,
        "wheels": [{"name": name, "sha256": digest} for name, digest in sorted(WHEEL_INPUTS.items())],
        "file_count": len(manifest_files),
        "total_bytes": sum(item["length"] for item in manifest_files),
        "files": manifest_files,
    }
    return files, manifest


def _info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build(python_zip: Path, wheels_dir: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError("refusing to overwrite runtime artifact")
    files, manifest = collect(python_zip, wheels_dir)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=7) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(_info(name), data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=7)
        archive.writestr(
            _info("RUNTIME_MANIFEST.json"),
            json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n",
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=7,
        )
    return {
        "status": "PINNED_RUNTIME_BUILT",
        "files": manifest["file_count"],
        "bytes": manifest["total_bytes"],
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "path": str(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-zip", type=Path, required=True)
    parser.add_argument("--wheels-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.python_zip, args.wheels_dir, args.out), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": f"{type(exc).__name__}: {str(exc)[:180]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
