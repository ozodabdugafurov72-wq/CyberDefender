from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from agent.sensors.rust_process_canary import RustProcessCanary, RustProcessCanaryError


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_BINARY = ROOT / "native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe"
EXAMPLE_CONFIG = ROOT / "config/process_sensor_runtime.example.json"


class NoopSupervisor:
    def __init__(self, _path: Path, **_kwargs: object) -> None:
        pass

    def close(self) -> None:
        pass


def main() -> int:
    config = json.loads(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    configured = Path(config["rust_v05"]["executable"])
    assert configured.is_absolute(), "example executable must be absolute"

    # Reproduce the observed c503021 failure boundary without touching live state.
    with tempfile.TemporaryDirectory(prefix="cd_missing_rust_") as td:
        missing = Path(td) / "missing" / configured.name
        try:
            RustProcessCanary(missing, "0" * 64, supervisor_factory=NoopSupervisor)
        except RustProcessCanaryError as exc:
            assert str(exc) == "RUST_CANARY_EXECUTABLE_NOT_FOUND"
        else:
            raise AssertionError("missing Rust executable was accepted")
    print("PASS | missing executable fails closed as RUST_CANARY_EXECUTABLE_NOT_FOUND")

    assert PACKAGE_BINARY.is_file(), f"packaged binary missing: {PACKAGE_BINARY}"
    digest = hashlib.sha256(PACKAGE_BINARY.read_bytes()).hexdigest()
    canary = RustProcessCanary(
        PACKAGE_BINARY, digest, supervisor_factory=NoopSupervisor
    )
    assert canary.executable == PACKAGE_BINARY.resolve()
    assert canary.binary_trusted is True
    canary.close()
    print("PASS | packaged release path and SHA-256 pin are accepted")
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
