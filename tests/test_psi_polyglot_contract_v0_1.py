from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "native" / "rust" / "probabilistic_security_intelligence_v0_1" / "src" / "lib.rs"
GO = ROOT / "native" / "go" / "ndr_edge_v0_1" / "edge.go"
SPEC = ROOT / "spec" / "PSI_CORE_CONTRACT_v0_1.md"
FIXTURES = ROOT / "spec" / "fixtures" / "psi_conformance_v0_1.json"


def fuse(prior: float, evidence: list[dict]) -> float:
    assert math.isfinite(prior) and 0 < prior < 1
    log_odds = math.log(prior / (1 - prior))
    group_count: dict[str, int] = {}
    for item in evidence:
        group = item["dependency_group"]
        requested = float(item["independence"])
        effective = requested if group_count.get(group, 0) == 0 else min(requested, 0.25)
        group_count[group] = group_count.get(group, 0) + 1
        log_odds += (
            float(item["signed_log_lr"])
            * float(item["reliability"])
            * effective
            * float(item["freshness"])
            * float(item["sensor_integrity"])
        )
    log_odds = max(-20.0, min(20.0, log_odds))
    return 1 / (1 + math.exp(-log_odds))


def main() -> None:
    rust = RUST.read_text(encoding="utf-8")
    go = GO.read_text(encoding="utf-8")
    spec = SPEC.read_text(encoding="utf-8")
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))

    required_rust = [
        "#![forbid(unsafe_code)]",
        "Authorization::NotGranted",
        "CORRELATED_INDEPENDENCE_CAP",
        "AssessmentState::Abstain",
        "DuplicateEvidenceId",
        "MAX_EVIDENCE",
    ]
    for token in required_rust:
        assert token in rust, token

    forbidden_rust = [
        "std::net::",
        "std::process::Command",
        "unsafe {",
        "windows::Win32",
    ]
    for token in forbidden_rust:
        assert token not in rust, token

    required_go = [
        '"LIVE_INPUT_DISABLED"',
        '"AUTHORITY_FORBIDDEN"',
        '"NOT_GRANTED"',
        "MaxObservations",
        "MaxSources",
        "sync.Mutex",
    ]
    for token in required_go:
        assert token in go, token

    forbidden_go = [
        '"net"',
        '"os/exec"',
        "net.Listen",
        "exec.Command",
    ]
    for token in forbidden_go:
        assert token not in go, token

    for invariant in [
        "Probability != Truth",
        "Confidence != Risk",
        "Risk != Authorization",
        "AI recommendation != Authorization",
    ]:
        assert invariant in spec

    assert fixtures["authorization"] == "NOT_GRANTED"
    assert fixtures["calibration"] == "UNVERIFIED"
    for case in fixtures["cases"]:
        actual = fuse(float(case["prior"]), case["evidence"])
        expected = float(case["expected_posterior"])
        assert abs(actual - expected) <= 1e-12, (case["case"], actual, expected)

    print(f"PSI_POLYGLOT_CONTRACT: PASS ({len(fixtures['cases'])} numeric fixtures)")


if __name__ == "__main__":
    main()
