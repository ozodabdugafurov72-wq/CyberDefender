from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
from unittest.mock import patch
import tempfile


EXPECTED = (
    "CD_BOOTSTRAP_B00_ENTER",
    "CD_BOOTSTRAP_B10_ROOT_OK",
    "CD_BOOTSTRAP_B20_PATH_PINNED",
    "CD_BOOTSTRAP_B30_ORIGIN_OK",
    "CD_BOOTSTRAP_B40_DISPATCH_ENTER",
    "CD_BOOTSTRAP_B90_DISPATCH_ERROR",
    "CD_BOOTSTRAP_B99_DISPATCH_RETURN",
)


def main() -> int:
    source = Path(__file__).resolve().parents[1] / "scripts" / "agent_release" / "agent_service_bootstrap.py"
    spec = importlib.util.spec_from_file_location("cd_bootstrap_under_test", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert tuple(module._STAGE_CODES) == EXPECTED
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        module._STAGE_DIRECTORY = directory
        with patch.object(module.secrets, "token_hex", return_value="a" * 32):
            module._open_stage()
        marker = module._STAGE_PATH
        assert marker is not None and marker.parent == directory
        for code in EXPECTED:
            module._stage(code)
        module._stage("UNTRUSTED_DETAIL")
        module._close_stage()
        assert marker.read_text(encoding="ascii").splitlines() == list(EXPECTED)
        assert marker.stat().st_size <= module._MAX_STAGE_BYTES
        module._STAGE_DIRECTORY = directory
        complete = marker.read_bytes()
        with marker.open("r+b", buffering=0) as full:
            full.truncate(module._MAX_STAGE_BYTES)
        module._STAGE_HANDLE = marker.open("ab", buffering=0)
        before = marker.stat().st_size
        module._stage(EXPECTED[0])
        module._close_stage()
        assert marker.stat().st_size == before
        marker.write_bytes(complete)

        # A short OS write must be rolled back so the marker and byte count
        # remain at the last complete fixed-code record.
        module._STAGE_BYTES = marker.stat().st_size
        module._STAGE_HANDLE = marker.open("ab", buffering=0)
        real_write = os.write

        def short_write(descriptor: int, payload: bytes) -> int:
            return real_write(descriptor, payload[:3])

        with patch.object(module.os, "write", side_effect=short_write):
            module._stage(EXPECTED[0])
        module._close_stage()
        assert marker.read_bytes() == complete
        assert module._STAGE_BYTES == len(complete)
        module._STAGE_DIRECTORY = directory
        with patch.object(module, "_directory_is_safe", return_value=False):
            module._open_stage()
        assert module._STAGE_HANDLE is None
        collision = directory / ("CyberDefenderAgent-bootstrap-" + "b" * 32 + ".log")
        collision.write_bytes(b"existing")
        with patch.object(module.secrets, "token_hex", return_value="b" * 32):
            module._open_stage()
        assert module._STAGE_HANDLE is None
        assert collision.read_bytes() == b"existing"

        if os.name == "nt":
            target = directory / "real-target"
            target.mkdir()
            junction = directory / "real-reparse"
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert created.returncode == 0, created.stderr
            try:
                module._STAGE_DIRECTORY = junction
                module._open_stage()
                assert module._STAGE_HANDLE is None
                assert not list(target.glob("CyberDefenderAgent-bootstrap-*.log"))
            finally:
                os.rmdir(junction)
    print("PASS | bootstrap diagnostics emit only bounded fixed stage codes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
