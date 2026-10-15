"""Entrypoint for a versioned Agent release.

The shared installed virtualenv remains in the original application directory,
while this bootstrap forces every CyberDefender import to resolve from the
immutable Agent release directory.
"""
from __future__ import annotations

import importlib.util
import os
import runpy
import stat
import sys
from pathlib import Path


_STAGE_CODES = (
    "CD_BOOTSTRAP_B00_ENTER",
    "CD_BOOTSTRAP_B10_ROOT_OK",
    "CD_BOOTSTRAP_B20_PATH_PINNED",
    "CD_BOOTSTRAP_B30_ORIGIN_OK",
    "CD_BOOTSTRAP_B40_DISPATCH_ENTER",
    "CD_BOOTSTRAP_B90_DISPATCH_ERROR",
    "CD_BOOTSTRAP_B99_DISPATCH_RETURN",
)
_STAGE_CODE_SET = frozenset(_STAGE_CODES)
_MAX_STAGE_BYTES = 4096
_STAGE_PATH = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Temp" / "CyberDefenderAgent-bootstrap-v1.log"


def _stage(code: str) -> None:
    """Best-effort, bounded fixed-code evidence before SCM lifecycle starts."""
    if code not in _STAGE_CODE_SET:
        return
    try:
        if _STAGE_PATH.exists():
            info = _STAGE_PATH.lstat()
            if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return
            if info.st_size + len(code) + 1 > _MAX_STAGE_BYTES:
                return
        with _STAGE_PATH.open("ab", buffering=0) as handle:
            handle.write(code.encode("ascii") + b"\n")
    except Exception:
        pass


def main() -> int:
    _stage("CD_BOOTSTRAP_B00_ENTER")
    root = Path(__file__).resolve().parent
    if not (root / "agent" / "windows_service.py").is_file():
        raise RuntimeError("pinned Agent package is missing")
    _stage("CD_BOOTSTRAP_B10_ROOT_OK")
    sys.path.insert(0, str(root))
    _stage("CD_BOOTSTRAP_B20_PATH_PINNED")
    spec = importlib.util.find_spec("agent.windows_service")
    if spec is None or spec.origin is None or Path(spec.origin).resolve().parent.parent != root:
        raise RuntimeError("Agent import escaped protected release root")
    _stage("CD_BOOTSTRAP_B30_ORIGIN_OK")
    # Preserve the known-good `python -m agent.windows_service` dispatch
    # contract: pywin32 observes the service module as __main__, including
    # its module argv[0], while all imports remain pinned to this release.
    _stage("CD_BOOTSTRAP_B40_DISPATCH_ENTER")
    try:
        runpy.run_module("agent.windows_service", run_name="__main__", alter_sys=True)
    except BaseException:
        _stage("CD_BOOTSTRAP_B90_DISPATCH_ERROR")
        raise
    _stage("CD_BOOTSTRAP_B99_DISPATCH_RETURN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
