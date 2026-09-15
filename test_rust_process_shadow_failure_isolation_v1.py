from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore
from agent.sensors.rust_process_shadow import (
    RustProcessShadowError,
    RustProcessShadowProbe,
    _run_bounded,
    validate_rust_v04_snapshot,
)


GOOD_VERDICTS = {
    "ALIGNED_COMMON_SET",
    "ALIGNED_COMMON_SET_WITH_COVERAGE_LIMITS",
}


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[PASS] {message}")


def counter(runtime: CyberDefenderRuntime, name: str) -> int:
    try:
        return int(getattr(runtime, name, 0))
    except (TypeError, ValueError):
        return -1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CommandFaultProbe:
    """Probe-like adapter that exercises the real bounded transport + validator."""

    VERSION = "failure-isolation-v1"

    def __init__(self, command: list[str], *, timeout: float):
        self.command = list(command)
        self.timeout = float(timeout)
        self.probe_count = 0
        self.failed_count = 0
        self.status = "NOT_STARTED"
        self.last_error: str | None = None
        self.last_snapshot: dict[str, Any] | None = None

    def probe(self) -> dict[str, Any]:
        try:
            raw = _run_bounded(
                self.command,
                timeout=self.timeout,
            )
            data = validate_rust_v04_snapshot(raw)
        except Exception as exc:
            self.failed_count += 1
            self.status = "DEGRADED"
            self.last_error = type(exc).__name__
            raise

        self.probe_count += 1
        self.status = "HEALTHY"
        self.last_error = None
        self.last_snapshot = data
        return data

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "RustProcessShadowProbe",
            "status": self.status,
            "version": self.VERSION,
            "mode": "SHADOW_ONLY",
            "probe_count": self.probe_count,
            "failed_count": self.failed_count,
            "last_error": self.last_error,
        }

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()


def write_fault_helpers(root: Path) -> dict[str, Path]:
    helpers = {
        "crash": root / "shadow_fault_crash.py",
        "timeout": root / "shadow_fault_timeout.py",
        "malformed": root / "shadow_fault_malformed.py",
    }

    helpers["crash"].write_text(
        "raise SystemExit(23)\n",
        encoding="utf-8",
    )
    helpers["timeout"].write_text(
        "import time\n"
        "time.sleep(5.0)\n",
        encoding="utf-8",
    )
    helpers["malformed"].write_text(
        "import sys\n"
        "sys.stdout.buffer.write(b'{malformed-json')\n"
        "sys.stdout.buffer.flush()\n",
        encoding="utf-8",
    )

    return helpers


def assert_authoritative_survival(
    *,
    runtime: CyberDefenderRuntime,
    graph_ingest_sources: list[str | None],
    expected_ingests: int,
    baseline_component_failures: int,
    baseline_graph_failures: int,
    baseline_sensor_failures: int,
    expected_shadow_failures: int,
    label: str,
) -> dict[str, Any]:
    result = runtime.update_process_graph()

    check(
        isinstance(result, dict) and result.get("accepted") is True,
        f"{label}: authoritative ProcessGraph ingestion still accepted",
    )
    check(
        len(graph_ingest_sources) == expected_ingests,
        f"{label}: exactly one new ProcessGraph ingest occurred",
    )
    check(
        all(source == "ProcessSensor" for source in graph_ingest_sources),
        f"{label}: every ProcessGraph ingest source remains Python ProcessSensor",
    )
    check(
        counter(runtime, "component_failures") == baseline_component_failures,
        f"{label}: security component failures did not increase",
    )
    check(
        counter(runtime, "process_graph_failures") == baseline_graph_failures,
        f"{label}: ProcessGraph failures did not increase",
    )
    check(
        counter(runtime, "process_sensor_failures") == baseline_sensor_failures,
        f"{label}: authoritative ProcessSensor failures did not increase",
    )
    check(
        counter(runtime, "rust_process_shadow_failures")
        == expected_shadow_failures,
        f"{label}: failure is isolated to Rust shadow diagnostic counter",
    )

    health = runtime.health_snapshot()
    check(
        health.get("runtime", {}).get("status") == "HEALTHY",
        f"{label}: authoritative runtime remains HEALTHY",
    )
    check(
        health.get("rust_process_shadow", {}).get("mode") == "SHADOW_ONLY",
        f"{label}: Rust health surface remains SHADOW_ONLY",
    )

    return result


def assert_real_rust_recovery(
    *,
    runtime: CyberDefenderRuntime,
    real_probe: RustProcessShadowProbe,
    graph_ingest_sources: list[str | None],
    expected_ingests: int,
    baseline_component_failures: int,
    baseline_graph_failures: int,
    baseline_sensor_failures: int,
    expected_shadow_failures: int,
    label: str,
) -> dict[str, Any]:
    runtime.rust_process_shadow = real_probe

    result = runtime.update_process_graph()
    check(
        isinstance(result, dict) and result.get("accepted") is True,
        f"{label}: authoritative ProcessGraph ingestion accepted",
    )
    check(
        len(graph_ingest_sources) == expected_ingests,
        f"{label}: exactly one new ProcessGraph ingest occurred",
    )
    check(
        all(source == "ProcessSensor" for source in graph_ingest_sources),
        f"{label}: Rust recovery never becomes ProcessGraph source",
    )

    comparison = runtime.last_rust_process_shadow_result
    check(
        isinstance(comparison, dict),
        f"{label}: live Rust comparison is recorded again",
    )
    check(
        comparison.get("mode") == "SHADOW_ONLY",
        f"{label}: live Rust remains SHADOW_ONLY",
    )
    check(
        comparison.get("verdict") in GOOD_VERDICTS,
        f"{label}: live Rust parity returns to aligned verdict",
    )
    check(
        comparison.get("identity_disagreements", {}).get("count") == 0,
        f"{label}: identity disagreements are zero after recovery",
    )
    check(
        comparison.get("parent_disagreements", {}).get("count") == 0,
        f"{label}: parent disagreements are zero after recovery",
    )
    check(
        int(comparison.get("exact_graph_identity_matches", -1))
        == int(comparison.get("common_processes", -2)),
        f"{label}: all common identities match after recovery",
    )
    check(
        runtime.last_rust_process_shadow_error is None,
        f"{label}: runtime clears current Rust shadow error after recovery",
    )
    check(
        counter(runtime, "component_failures") == baseline_component_failures,
        f"{label}: security component failures remain unchanged",
    )
    check(
        counter(runtime, "process_graph_failures") == baseline_graph_failures,
        f"{label}: ProcessGraph failures remain unchanged",
    )
    check(
        counter(runtime, "process_sensor_failures") == baseline_sensor_failures,
        f"{label}: authoritative ProcessSensor failures remain unchanged",
    )
    check(
        counter(runtime, "rust_process_shadow_failures")
        == expected_shadow_failures,
        f"{label}: historical Rust shadow failure counter is preserved",
    )

    health = runtime.health_snapshot()
    check(
        health.get("runtime", {}).get("status") == "HEALTHY",
        f"{label}: authoritative runtime is HEALTHY",
    )
    check(
        health.get("rust_process_shadow", {}).get("mode") == "SHADOW_ONLY",
        f"{label}: health surface remains SHADOW_ONLY",
    )

    return result


def main() -> int:
    executable = str(
        os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or ""
    ).strip()
    if not executable:
        raise AssertionError(
            "CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE is required"
        )

    exe_path = Path(executable).expanduser().resolve()
    check(exe_path.is_file(), "Real RustProcessSensor executable exists")

    print(
        "Rust EXE SHA-256:",
        sha256_file(exe_path),
    )

    with tempfile.TemporaryDirectory(
        prefix="cyberdefender_rust_shadow_failure_isolation_"
    ) as temp_dir:
        temp_root = Path(temp_dir)
        state_dir = temp_root / "state"
        helper_dir = temp_root / "helpers"
        helper_dir.mkdir(parents=True, exist_ok=True)

        os.environ["CYBERDEFENDER_STATE_DIR"] = str(state_dir)
        storage_key = os.urandom(32)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(
            storage_key
        ).decode()
        os.environ["CYBERDEFENDER_RUST_PROCESS_SHADOW"] = "1"
        os.environ["CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE"] = str(exe_path)
        os.environ["CYBERDEFENDER_RUST_PROCESS_SENSOR_TIMEOUT"] = "5"

        km = KeyManager(state_dir / "keys", storage_key)
        check(
            km.generate_key() and km.is_ready(),
            "Temporary signing key is provisioned",
        )

        helpers = write_fault_helpers(helper_dir)

        runtime = CyberDefenderRuntime(SafetyCore(), load_config())
        try:
            check(
                runtime.rust_process_shadow_enabled,
                "Runtime Rust shadow flag is enabled",
            )
            check(
                isinstance(
                    runtime.rust_process_shadow,
                    RustProcessShadowProbe,
                ),
                "Runtime initialized the real Rust shadow probe",
            )

            real_probe = runtime.rust_process_shadow
            graph = runtime.process_graph
            authoritative_sensor = runtime.process_sensor

            check(graph is not None, "ProcessGraph is initialized")
            check(
                authoritative_sensor is not None,
                "Python ProcessSensor is initialized",
            )

            original_ingest = graph.ingest_snapshot
            graph_ingest_sources: list[str | None] = []

            def guarded_ingest(snapshot: Any) -> dict[str, Any]:
                if not isinstance(snapshot, dict):
                    raise AssertionError(
                        "ProcessGraph received non-dict snapshot"
                    )

                source = snapshot.get("sensor")
                graph_ingest_sources.append(source)

                if source != "ProcessSensor":
                    raise AssertionError(
                        "Non-authoritative sensor attempted ProcessGraph ingestion: "
                        f"{source!r}"
                    )

                return original_ingest(snapshot)

            graph.ingest_snapshot = guarded_ingest  # type: ignore[method-assign]

            baseline_component_failures = counter(
                runtime, "component_failures"
            )
            baseline_graph_failures = counter(
                runtime, "process_graph_failures"
            )
            baseline_sensor_failures = counter(
                runtime, "process_sensor_failures"
            )
            baseline_shadow_failures = counter(
                runtime, "rust_process_shadow_failures"
            )

            # ------------------------------------------------------------
            # Baseline: real Rust probe must align before fault injection.
            # ------------------------------------------------------------
            baseline = assert_real_rust_recovery(
                runtime=runtime,
                real_probe=real_probe,
                graph_ingest_sources=graph_ingest_sources,
                expected_ingests=1,
                baseline_component_failures=baseline_component_failures,
                baseline_graph_failures=baseline_graph_failures,
                baseline_sensor_failures=baseline_sensor_failures,
                expected_shadow_failures=baseline_shadow_failures,
                label="BASELINE",
            )
            check(
                int(baseline.get("processes_valid", 0)) > 0,
                "BASELINE: authoritative ProcessGraph contains live processes",
            )

            scenarios = [
                (
                    "CRASH",
                    CommandFaultProbe(
                        [sys.executable, str(helpers["crash"])],
                        timeout=1.0,
                    ),
                    "sensor nonzero exit",
                ),
                (
                    "TIMEOUT",
                    CommandFaultProbe(
                        [sys.executable, str(helpers["timeout"])],
                        timeout=0.35,
                    ),
                    "sensor timeout",
                ),
                (
                    "MALFORMED_OUTPUT",
                    CommandFaultProbe(
                        [sys.executable, str(helpers["malformed"])],
                        timeout=1.0,
                    ),
                    "invalid JSON",
                ),
            ]

            summary_rows: list[dict[str, Any]] = []
            expected_ingests = 1
            expected_shadow_failures = baseline_shadow_failures

            for label, fault_probe, expected_error_fragment in scenarios:
                runtime.rust_process_shadow = fault_probe

                expected_ingests += 1
                expected_shadow_failures += 1

                before_comparison = runtime.last_rust_process_shadow_result

                assert_authoritative_survival(
                    runtime=runtime,
                    graph_ingest_sources=graph_ingest_sources,
                    expected_ingests=expected_ingests,
                    baseline_component_failures=baseline_component_failures,
                    baseline_graph_failures=baseline_graph_failures,
                    baseline_sensor_failures=baseline_sensor_failures,
                    expected_shadow_failures=expected_shadow_failures,
                    label=label,
                )

                check(
                    fault_probe.failed_count == 1,
                    f"{label}: injected probe records exactly one failure",
                )
                check(
                    fault_probe.probe_count == 0,
                    f"{label}: failed probe does not claim a successful sample",
                )
                check(
                    fault_probe.status == "DEGRADED",
                    f"{label}: injected probe health becomes DEGRADED",
                )
                check(
                    isinstance(
                        runtime.last_rust_process_shadow_error,
                        str,
                    )
                    and runtime.last_rust_process_shadow_error,
                    f"{label}: runtime records bounded shadow error",
                )

                # The current integration retains the last successful comparison
                # as historical evidence. It must not be replaced by fault data.
                check(
                    runtime.last_rust_process_shadow_result
                    is before_comparison,
                    f"{label}: failed shadow output never replaces successful comparison evidence",
                )

                # Exercise the transport/validator directly so the failure reason
                # is proven to be the intended boundary, not a test adapter bug.
                direct_error = None
                try:
                    raw = _run_bounded(
                        fault_probe.command,
                        timeout=fault_probe.timeout,
                    )
                    validate_rust_v04_snapshot(raw)
                except RustProcessShadowError as exc:
                    direct_error = str(exc)

                check(
                    isinstance(direct_error, str)
                    and expected_error_fragment in direct_error,
                    f"{label}: exact bounded transport/validation fault is observed",
                )

                summary_rows.append(
                    {
                        "scenario": label,
                        "runtime_status": runtime.health_snapshot()
                        .get("runtime", {})
                        .get("status"),
                        "rust_shadow_failures": counter(
                            runtime,
                            "rust_process_shadow_failures",
                        ),
                        "fault_probe_status": fault_probe.status,
                        "fault_probe_failed_count": fault_probe.failed_count,
                        "direct_error": direct_error,
                        "process_graph_ingests": len(
                            graph_ingest_sources
                        ),
                    }
                )

                # --------------------------------------------------------
                # Recovery gate after every injected fault.
                # --------------------------------------------------------
                expected_ingests += 1

                assert_real_rust_recovery(
                    runtime=runtime,
                    real_probe=real_probe,
                    graph_ingest_sources=graph_ingest_sources,
                    expected_ingests=expected_ingests,
                    baseline_component_failures=baseline_component_failures,
                    baseline_graph_failures=baseline_graph_failures,
                    baseline_sensor_failures=baseline_sensor_failures,
                    expected_shadow_failures=expected_shadow_failures,
                    label=f"{label}_RECOVERY",
                )

            final_sensor_stats = authoritative_sensor.get_stats()
            check(
                int(final_sensor_stats.get("collect_count", -1))
                == expected_ingests,
                "Python ProcessSensor collected exactly once for every gate cycle",
            )
            check(
                len(graph_ingest_sources) == expected_ingests,
                "ProcessGraph received exactly one authoritative snapshot per gate cycle",
            )
            check(
                all(
                    source == "ProcessSensor"
                    for source in graph_ingest_sources
                ),
                "No Rust/fault probe snapshot ever entered ProcessGraph",
            )
            check(
                counter(runtime, "component_failures")
                == baseline_component_failures,
                "Final security component failure count is unchanged",
            )
            check(
                counter(runtime, "process_graph_failures")
                == baseline_graph_failures,
                "Final ProcessGraph failure count is unchanged",
            )
            check(
                counter(runtime, "process_sensor_failures")
                == baseline_sensor_failures,
                "Final authoritative ProcessSensor failure count is unchanged",
            )
            check(
                counter(runtime, "rust_process_shadow_failures")
                == baseline_shadow_failures + len(scenarios),
                "Exactly three isolated Rust shadow failures were recorded",
            )
            check(
                runtime.health_snapshot()
                .get("runtime", {})
                .get("status")
                == "HEALTHY",
                "Final authoritative runtime remains HEALTHY",
            )

            summary = {
                "schema": "cd.rust-shadow-failure-isolation.v1",
                "mode": "SHADOW_ONLY",
                "authoritative_sensor": "ProcessSensor",
                "shadow_sensor": "RustProcessSensor",
                "faults_injected": [
                    "CRASH",
                    "TIMEOUT",
                    "MALFORMED_OUTPUT",
                ],
                "fault_count": len(scenarios),
                "recovery_after_each_fault": True,
                "graph_ingest_sources_all_authoritative": all(
                    source == "ProcessSensor"
                    for source in graph_ingest_sources
                ),
                "cycles_completed": expected_ingests,
                "component_failures": counter(
                    runtime, "component_failures"
                ),
                "process_graph_failures": counter(
                    runtime, "process_graph_failures"
                ),
                "process_sensor_failures": counter(
                    runtime, "process_sensor_failures"
                ),
                "rust_process_shadow_failures": counter(
                    runtime, "rust_process_shadow_failures"
                ),
                "runtime_status": runtime.health_snapshot()
                .get("runtime", {})
                .get("status"),
                "scenarios": summary_rows,
            }

            print("\nRUST SHADOW FAILURE ISOLATION SUMMARY")
            print(json.dumps(summary, indent=2, sort_keys=True))
            print(
                "\nRUST PROCESS SHADOW FAILURE ISOLATION v1: PASS"
            )
            return 0

        finally:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
