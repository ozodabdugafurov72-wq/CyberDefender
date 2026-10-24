"""Build the Windows source/install ZIP from a reviewed source-file manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]


def build(destination: Path) -> Path:
    names = [
        name.strip()
        for name in (ROOT / "distribution-files.txt").read_text(encoding="utf-8").splitlines()
        if name.strip() and not name.lstrip().startswith("#")
    ]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate distribution manifest entry")
    files = []
    entries = {}
    for name in names:
        path = ROOT / name
        if not path.resolve().is_relative_to(ROOT) or path.is_symlink() or not path.is_file():
            raise ValueError(f"Invalid or missing package source: {name}")
        data = path.read_bytes()
        files.append((name, path, data))
        entries[name] = data

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
    ).strip()
    manifest = {
        "schema": "cyberdefender.distribution-manifest.v1",
        "commit": commit,
        "tree": tree,
        "file_count": len(files),
        "files": [
            {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, _path, data in sorted(files)
        ],
    }
    entries["release-manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
        for name in sorted(entries):
            info = ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0x20
            archive.writestr(info, entries[name])
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(".zip.sha256").write_text(
        f"{digest}  {destination.name}\n", encoding="ascii"
    )
    print(f"Built {destination} ({len(files)} files + release-manifest.json, {destination.stat().st_size} bytes)")
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "CyberDefenderPackage.zip")
    build(parser.parse_args().output)
