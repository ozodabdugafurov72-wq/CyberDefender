"""Entrypoint for a versioned Agent release.

The shared installed virtualenv remains in the original application directory,
while this bootstrap forces every CyberDefender import to resolve from the
immutable Agent release directory.
"""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    if not (root / "agent" / "windows_service.py").is_file():
        raise RuntimeError("pinned Agent package is missing")
    sys.path.insert(0, str(root))
    from agent import windows_service

    if Path(windows_service.__file__).resolve().parent.parent != root:
        raise RuntimeError("Agent import escaped protected release root")
    return windows_service.main()


if __name__ == "__main__":
    raise SystemExit(main())
