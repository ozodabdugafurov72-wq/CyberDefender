"""Build the Windows source/install ZIP from a reviewed source-file manifest."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]


def build(destination: Path) -> Path:
    names = (ROOT / "distribution-files.txt").read_text(encoding="utf-8").splitlines()
    files = []
    for name in names:
        path = ROOT / name
        if not path.resolve().is_relative_to(ROOT) or path.is_symlink() or not path.is_file():
            raise ValueError(f"Invalid or missing package source: {name}")
        files.append((name, path))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
        for name, path in files:
            archive.write(path, name)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(".zip.sha256").write_text(
        f"{digest}  {destination.name}\n", encoding="ascii"
    )
    print(f"Built {destination} ({len(files)} files, {destination.stat().st_size} bytes)")
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "CyberDefenderPackage.zip")
    build(parser.parse_args().output)
