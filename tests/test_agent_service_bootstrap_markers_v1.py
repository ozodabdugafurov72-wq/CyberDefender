from __future__ import annotations

import importlib.util
from pathlib import Path
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
        marker = Path(raw) / "marker.log"
        module._STAGE_PATH = marker
        for code in EXPECTED:
            module._stage(code)
        module._stage("UNTRUSTED_DETAIL")
        assert marker.read_text(encoding="ascii").splitlines() == list(EXPECTED)
        assert marker.stat().st_size <= module._MAX_STAGE_BYTES
    print("PASS | bootstrap diagnostics emit only bounded fixed stage codes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
