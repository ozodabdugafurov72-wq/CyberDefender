from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "native" / "rust" / "probabilistic_security_intelligence_v0_2" / "src" / "lib.rs"
GO = ROOT / "native" / "go" / "ndr_edge_v0_2" / "edge.go"
SPEC = ROOT / "spec" / "PSI_CORE_CONTRACT_v0_2.md"
NDR_SPEC = ROOT / "spec" / "NDR_EDGE_FOUNDATION_v0_2.md"
FIXTURES = ROOT / "spec" / "fixtures" / "psi_conformance_v0_2.json"

WINDOWS = [5, 30, 300, 3600, 21600, 86400]


def _unit(value: float) -> bool:
    return math.isfinite(value) and 0.0 <= value <= 1.0


def oracle(case: dict, window: int) -> dict:
    prior = float(case["prior"])
    assert math.isfinite(prior) and 0.0 < prior < 1.0
    evidence = case["evidence"]
    trusted = {
        item["source_id"]: (float(item["reliability_cap"]), float(item["integrity_cap"]))
        for item in case["trusted_sources"]
    }
    data_quality = float(case["data_quality"])
    base_uncertainty = float(case["epistemic_uncertainty"])
    assert _unit(data_quality) and _unit(base_uncertainty)

    eligible = [item for item in evidence if float(item["observed_age_seconds"]) <= window]
    if not eligible:
        return {
            "posterior_probability": prior,
            "model_confidence": 0.0,
            "effective_data_quality": data_quality,
            "epistemic_uncertainty": min(1.0, base_uncertainty + 0.25),
            "evidence_count": 0,
            "unique_source_count": 0,
            "dependency_group_count": 0,
            "supporting_evidence_count": 0,
            "counter_evidence_count": 0,
            "unknown_source_count": 0,
            "source_concentration": 0.0,
            "dependency_concentration": 0.0,
            "disposition": "UNKNOWN",
            "poisoning_signals": [],
        }

    log_odds = math.log(prior / (1.0 - prior))
    group_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    supporting = 0
    counter = 0
    unknown_sources = 0
    independence_sum = 0.0
    quality_sum = 0.0

    seen_ids: set[str] = set()
    for item in eligible:
        evidence_id = item["evidence_id"]
        assert evidence_id not in seen_ids
        seen_ids.add(evidence_id)

        group = item["dependency_group"]
        group_seen = group_counts.get(group, 0)
        requested_independence = float(item["independence_weight"])
        if group_seen == 0:
            effective_independence = requested_independence
        else:
            cap = max(0.05, 0.25 / math.sqrt(group_seen))
            effective_independence = min(requested_independence, cap)
        group_counts[group] = group_seen + 1

        source_id = item["source_id"]
        source_seen = source_counts.get(source_id, 0)
        source_repeat_weight = 1.0 if source_seen == 0 else max(0.25, 1.0 / math.sqrt(source_seen + 1))
        source_counts[source_id] = source_seen + 1

        if source_id in trusted:
            reliability_cap, integrity_cap = trusted[source_id]
        else:
            reliability_cap, integrity_cap = 0.35, 0.50
            unknown_sources += 1

        claimed_reliability = float(item["claimed_reliability"])
        sensor_integrity = float(item["sensor_integrity"])
        telemetry_quality = float(item["telemetry_quality"])
        signed_log_lr = float(item["signed_log_lr"])
        age = float(item["observed_age_seconds"])

        effective_reliability = (
            min(claimed_reliability, reliability_cap)
            * min(sensor_integrity, integrity_cap)
            * telemetry_quality
        )
        freshness = 1.0 / (1.0 + age / window)
        log_odds += signed_log_lr * effective_reliability * effective_independence * source_repeat_weight * freshness
        independence_sum += effective_independence * source_repeat_weight
        quality_sum += telemetry_quality

        if signed_log_lr > 0.0:
            supporting += 1
        elif signed_log_lr < 0.0:
            counter += 1

    log_odds = max(-20.0, min(20.0, log_odds))
    posterior = 1.0 / (1.0 + math.exp(-log_odds))
    count = len(eligible)
    source_concentration = max(source_counts.values()) / count
    dependency_concentration = max(group_counts.values()) / count
    unknown_ratio = unknown_sources / count
    average_quality = quality_sum / count

    effective_data_quality = max(
        0.0,
        min(1.0, data_quality * average_quality * (1.0 - 0.25 * unknown_ratio)),
    )
    concentration_uncertainty = 0.0
    if count >= 2:
        concentration_uncertainty = 0.15 * source_concentration + 0.15 * dependency_concentration
    uncertainty = max(
        0.0,
        min(1.0, base_uncertainty + 0.20 * unknown_ratio + concentration_uncertainty),
    )

    evidence_coverage = min(1.0, count / 4.0)
    source_diversity = 1.0 if count <= 1 else min(1.0, len(source_counts) / count)
    confidence = math.sqrt(effective_data_quality * (1.0 - uncertainty) * evidence_coverage * source_diversity)

    signals: list[str] = []
    if count >= 4 and source_concentration >= 0.75:
        signals.append("SOURCE_CONCENTRATION")
    if count >= 4 and dependency_concentration >= 0.75:
        signals.append("DEPENDENCY_CONCENTRATION")
    if count >= 2 and unknown_ratio >= 0.50:
        signals.append("UNKNOWN_SOURCE_DOMINANCE")
    if average_quality < 0.50:
        signals.append("TELEMETRY_QUALITY_DEGRADED")

    if effective_data_quality < 0.35 or uncertainty > 0.75:
        disposition = "ABSTAIN"
    elif posterior >= 0.65 and supporting > counter:
        disposition = "SUPPORT"
    elif posterior <= 0.35 and counter > supporting:
        disposition = "COUNTER"
    else:
        disposition = "UNKNOWN"

    return {
        "posterior_probability": posterior,
        "model_confidence": confidence,
        "effective_data_quality": effective_data_quality,
        "epistemic_uncertainty": uncertainty,
        "evidence_count": count,
        "unique_source_count": len(source_counts),
        "dependency_group_count": len(group_counts),
        "supporting_evidence_count": supporting,
        "counter_evidence_count": counter,
        "unknown_source_count": unknown_sources,
        "source_concentration": source_concentration,
        "dependency_concentration": dependency_concentration,
        "disposition": disposition,
        "poisoning_signals": signals,
    }


def close(actual: float, expected: float, eps: float = 1e-12) -> None:
    assert abs(actual - expected) <= eps, (actual, expected)


def main() -> None:
    rust = RUST.read_text(encoding="utf-8")
    go = GO.read_text(encoding="utf-8")
    spec = SPEC.read_text(encoding="utf-8")
    ndr_spec = NDR_SPEC.read_text(encoding="utf-8")
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))

    required_rust = [
        "#![forbid(unsafe_code)]",
        "Authorization::NotGranted",
        "WINDOWS_SECONDS",
        "TrustedSource",
        "UNKNOWN_SOURCE_RELIABILITY_CAP",
        "CORRELATED_INDEPENDENCE_CAP",
        "SourceConcentration",
        "DependencyConcentration",
        "UnknownSourceDominance",
        "HypothesisDisposition::Abstain",
        "DuplicateEvidenceId",
        "DuplicateTrustedSource",
        "MAX_EVIDENCE",
    ]
    for token in required_rust:
        assert token in rust, token

    forbidden_rust = [
        "std::net::",
        "std::process::Command",
        "unsafe {",
        "windows::Win32",
        "Authorization::Granted",
        "ProductionCalibrated",
    ]
    for token in forbidden_rust:
        assert token not in rust, token

    required_go = [
        '"LIVE_INPUT_DISABLED"',
        '"AUTHORITY_FORBIDDEN"',
        '"NOT_GRANTED"',
        '"DISABLED"',
        "WindowSeconds",
        "LongHorizonOnly",
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
        '"GRANTED"',
    ]
    for token in forbidden_go:
        assert token not in go, token

    invariants = [
        "Probability != Truth",
        "Confidence != Risk",
        "Risk != Authorization",
        "AI recommendation != Authorization",
        "Missing telemetry != benign evidence",
        "Correlated evidence != independent evidence",
    ]
    for invariant in invariants:
        assert invariant in spec, invariant

    for phrase in [
        "no live packet capture",
        "Authorization = NOT_GRANTED",
        "bounded",
        "5s / 30s / 5m / 1h / 6h / 24h",
    ]:
        assert phrase in ndr_spec, phrase

    assert fixtures["authorization"] == "NOT_GRANTED"
    assert fixtures["calibration"] == "UNVERIFIED"
    assert fixtures["windows"] == WINDOWS

    for case in fixtures["cases"]:
        for window in WINDOWS:
            actual = oracle(case, window)
            expected = case["expected_windows"][str(window)]
            for key in [
                "posterior_probability",
                "model_confidence",
                "effective_data_quality",
                "epistemic_uncertainty",
                "source_concentration",
                "dependency_concentration",
            ]:
                close(float(actual[key]), float(expected[key]))
            for key in [
                "evidence_count",
                "unique_source_count",
                "dependency_group_count",
                "supporting_evidence_count",
                "counter_evidence_count",
                "unknown_source_count",
                "disposition",
                "poisoning_signals",
            ]:
                assert actual[key] == expected[key], (case["case"], window, key, actual[key], expected[key])

    cases = {item["case"]: item for item in fixtures["cases"]}
    low = cases["low_and_slow"]
    assert oracle(low, 300)["evidence_count"] == 0
    assert oracle(low, 3600)["disposition"] == "SUPPORT"

    poison = cases["dependency_poisoning"]
    assert "DEPENDENCY_CONCENTRATION" in oracle(poison, 5)["poisoning_signals"]
    assert oracle(poison, 5)["dependency_concentration"] == 1.0

    unknown = cases["unknown_source_discount"]
    assert "UNKNOWN_SOURCE_DOMINANCE" in oracle(unknown, 5)["poisoning_signals"]
    assert oracle(unknown, 5)["unknown_source_count"] == 2

    counter = cases["counter_evidence"]
    assert oracle(counter, 5)["disposition"] == "COUNTER"

    print(f"PSI_V0_2_POLYGLOT_CONTRACT: PASS ({len(fixtures['cases'])} cases x {len(WINDOWS)} windows)")


if __name__ == "__main__":
    main()
