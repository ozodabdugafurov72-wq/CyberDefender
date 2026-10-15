from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main() -> int:
    source = Path(__file__).resolve().parents[1] / "scripts" / "agent_release" / "agent_service_bootstrap.py"
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        release = base / "release"
        agent = release / "agent"
        agent.mkdir(parents=True)
        (agent / "__init__.py").write_text("", encoding="utf-8")
        marker = base / "dispatch.json"
        (agent / "windows_service.py").write_text(
            "import json, pathlib, sys\n"
            f"pathlib.Path({str(marker)!r}).write_text(json.dumps({{'name': __name__, 'argv': sys.argv}}), encoding='utf-8')\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        bootstrap = release / "agent_service_bootstrap.py"
        shutil.copyfile(source, bootstrap)
        (base / "Temp").mkdir()
        environment = os.environ.copy()
        environment["WINDIR"] = str(base)
        result = subprocess.run(
            [sys.executable, str(bootstrap), "--service-run"],
            cwd=base,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        record = json.loads(marker.read_text(encoding="utf-8"))
        assert record["name"] == "__main__"
        assert Path(record["argv"][0]).resolve() == (agent / "windows_service.py").resolve()
        assert record["argv"][1:] == ["--service-run"]
    print("PASS | pinned bootstrap preserves python -m SCM dispatch semantics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
