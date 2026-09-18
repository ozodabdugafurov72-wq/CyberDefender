from __future__ import annotations

import math
import statistics
from typing import Any


class FlowBaselineAnalyzer:
    """Robust, observation-only baseline analysis for passive interface flow.

    The analyzer consumes already-collected local interface-rate samples. It does
    not perform OS, network, DNS, packet, or remote I/O and cannot authorize or
    execute any response. An anomaly candidate is evidence for downstream
    correlation only; it is not a malicious verdict, incident, or risk change.
    """

    VERSION = "0.1.9"
    MODE = "ROBUST_ROLLING_BASELINE"
    AUTHORITY = "NONE"

    def __init__(
        self,
        *,
        min_samples: int = 15,
        max_samples: int = 60,
        min_continuity_percent: float = 95.0,
        absolute_floor_bps: float = 64.0 * 1024.0,
        median_multiplier: float = 3.0,
        mad_multiplier: float = 6.0,
    ) -> None:
        self.min_samples = max(5, min(int(min_samples), 120))
        self.max_samples = max(self.min_samples, min(int(max_samples), 300))
        self.min_continuity_percent = max(0.0, min(float(min_continuity_percent), 100.0))
        self.absolute_floor_bps = max(1024.0, min(float(absolute_floor_bps), 1024.0 * 1024.0 * 1024.0))
        self.median_multiplier = max(1.0, min(float(median_multiplier), 20.0))
        self.mad_multiplier = max(1.0, min(float(mad_multiplier), 20.0))

    @staticmethod
    def _finite(value: Any) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(number) or number < 0.0:
            return 0.0
        return number

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        if len(ordered) == 1:
            return ordered[0]
        rank = (len(ordered) - 1) * max(0.0, min(percentile, 1.0))
        low = int(math.floor(rank))
        high = int(math.ceil(rank))
        if low == high:
            return ordered[low]
        weight = rank - low
        return ordered[low] * (1.0 - weight) + ordered[high] * weight

    def _direction(self, baseline_values: list[float], current: float, confidence: float) -> dict[str, Any]:
        if not baseline_values:
            return {
                "current_bytes_per_second": round(current, 2),
                "median_bytes_per_second": 0.0,
                "mad_bytes_per_second": 0.0,
                "p95_bytes_per_second": 0.0,
                "threshold_bytes_per_second": None,
                "ratio_to_median": None,
                "candidate": False,
                "reason": "BASELINE_NOT_READY",
            }

        median = float(statistics.median(baseline_values))
        deviations = [abs(value - median) for value in baseline_values]
        mad = float(statistics.median(deviations)) if deviations else 0.0
        robust_sigma = 1.4826 * mad
        p95 = self._percentile(baseline_values, 0.95)
        threshold = median + max(
            self.absolute_floor_bps,
            median * self.median_multiplier,
            robust_sigma * self.mad_multiplier,
        )
        candidate = bool(confidence >= 70.0 and current >= threshold)
        ratio = None if median <= 0.0 else current / median
        return {
            "current_bytes_per_second": round(current, 2),
            "median_bytes_per_second": round(median, 2),
            "mad_bytes_per_second": round(mad, 2),
            "p95_bytes_per_second": round(p95, 2),
            "threshold_bytes_per_second": round(threshold, 2),
            "ratio_to_median": round(ratio, 3) if ratio is not None else None,
            "candidate": candidate,
            "reason": "ROBUST_THRESHOLD_EXCEEDED" if candidate else "WITHIN_OBSERVATIONAL_BASELINE",
        }

    def analyze(
        self,
        aggregates: list[dict[str, Any]],
        *,
        coverage_percent: float,
        stale: bool,
        sequence: int,
    ) -> dict[str, Any]:
        valid = [
            item for item in aggregates
            if isinstance(item, dict) and bool(item.get("baseline_ready", False))
        ][-self.max_samples :]

        current = valid[-1] if valid else {}
        # Never let the newest sample train its own threshold. This avoids an
        # instantaneous spike diluting the baseline that evaluates that spike.
        baseline = valid[:-1] if len(valid) > 1 else []

        rx_values = [self._finite(item.get("rx_bytes_per_second")) for item in baseline]
        tx_values = [self._finite(item.get("tx_bytes_per_second")) for item in baseline]
        baseline_count = min(len(rx_values), len(tx_values))

        coverage = max(0.0, min(self._finite(coverage_percent), 100.0))
        sample_factor = min(1.0, baseline_count / float(self.min_samples))
        continuity_factor = min(1.0, coverage / 100.0)
        freshness_factor = 0.0 if stale else 1.0
        confidence = round(100.0 * min(sample_factor, continuity_factor, freshness_factor), 1)

        if stale:
            status = "DEGRADED"
        elif baseline_count < self.min_samples:
            status = "WARMING"
        elif coverage < self.min_continuity_percent:
            status = "DEGRADED"
        else:
            status = "READY"

        rx = self._direction(rx_values, self._finite(current.get("rx_bytes_per_second")), confidence)
        tx = self._direction(tx_values, self._finite(current.get("tx_bytes_per_second")), confidence)
        candidate = bool(status == "READY" and (rx["candidate"] or tx["candidate"]))

        return {
            "schema": "cyberdefender.flow-baseline.v0.1.9",
            "version": self.VERSION,
            "mode": self.MODE,
            "status": status,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "passive": True,
            "observation_only": True,
            "creates_incident": False,
            "changes_risk": False,
            "authorization": "NOT_GRANTED",
            "sequence": int(sequence),
            "baseline_samples": baseline_count,
            "min_samples": self.min_samples,
            "max_samples": self.max_samples,
            "continuity_percent": round(coverage, 3),
            "confidence_percent": confidence,
            "anomaly_candidate": candidate,
            "candidate_semantics": "CORRELATION_EVIDENCE_ONLY_NOT_MALICIOUS_VERDICT",
            "rx": rx,
            "tx": tx,
            "method": {
                "center": "MEDIAN",
                "dispersion": "MAD",
                "tail_reference": "P95",
                "newest_sample_excluded_from_training": True,
                "absolute_floor_bytes_per_second": self.absolute_floor_bps,
                "median_multiplier": self.median_multiplier,
                "mad_multiplier": self.mad_multiplier,
            },
            "semantics": {
                "confidence": "EVIDENCE_QUALITY_NOT_ATTACK_PROBABILITY",
                "candidate": "OBSERVATION_ONLY_REQUIRES_DOWNSTREAM_CORRELATION",
                "high_traffic": "NOT_EQUIVALENT_TO_MALICIOUS_ACTIVITY",
                "authorization": "NEVER_GRANTED_BY_FLOW_BASELINE",
            },
        }
