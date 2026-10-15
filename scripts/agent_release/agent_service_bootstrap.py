"""Entrypoint for a versioned Agent release.

The shared installed virtualenv remains in the original application directory,
while this bootstrap forces every CyberDefender import to resolve from the
immutable Agent release directory.
"""
from __future__ import annotations

import importlib.util
import runpy
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    if not (root / "agent" / "windows_service.py").is_file():
        raise RuntimeError("pinned Agent package is missing")
    sys.path.insert(0, str(root))
    spec = importlib.util.find_spec("agent.windows_service")
    if spec is None or spec.origin is None or Path(spec.origin).resolve().parent.parent != root:
        raise RuntimeError("Agent import escaped protected release root")
    # Preserve the known-good `python -m agent.windows_service` dispatch
    # contract: pywin32 observes the service module as __main__, including
    # its module argv[0], while all imports remain pinned to this release.
    runpy.run_module("agent.windows_service", run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
