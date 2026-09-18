from __future__ import annotations

import copy
import threading
import time
from collections import deque
from typing import Any, Callable

from .flow_baseline import FlowBaselineAnalyzer

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


_MAX_COUNTER = (1 << 63) - 1


def _bounded_text(value: Any, limit: int = 128) -> str:
    return str(value or "").strip()[:limit]


def _counter(value: Any) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(number, _MAX_COUNTER))


def _default_counter_reader() -> list[dict[str, Any]]:
    """Read cumulative local interface counters only.

    No packet capture, socket hook, ETW session, probe, DNS lookup, or remote
    operation is performed. This function is intentionally tiny so the fast
    sampler remains independent from the heavier network inventory snapshot.
    """
    if psutil is None:
        return []
    counters = psutil.net_io_counters(pernic=True, nowrap=True)
    rows: list[dict[str, Any]] = []
    for name in sorted(counters)[:128]:
        item = counters.get(name)
        if item is None:
            continue
        rows.append({
            "interface": _bounded_text(name, 128),
            "bytes_sent": _counter(getattr(item, "bytes_sent", 0)),
            "bytes_recv": _counter(getattr(item, "bytes_recv", 0)),
            "packets_sent": _counter(getattr(item, "packets_sent", 0)),
            "packets_recv": _counter(getattr(item, "packets_recv", 0)),
            "errin": _counter(getattr(item, "errin", 0)),
            "errout": _counter(getattr(item, "errout", 0)),
            "dropin": _counter(getattr(item, "dropin", 0)),
            "dropout": _counter(getattr(item, "dropout", 0)),
        })
    return rows


class PassiveInterfaceFlowSampler:
    """Low-cost continuous sampler for passive interface counters.

    Security/reliability contract:
      * local cumulative interface counters only;
      * no packet capture and no per-connection byte attribution;
      * dedicated daemon thread at a bounded cadence;
      * sequence, sample age, late/gap/failure/reset telemetry are observable;
      * raw instantaneous rate remains available alongside rolling windows;
      * stale or discontinuous evidence is never silently presented as fresh;
      * output is non-authoritative and cannot grant authorization.
    """

    VERSION = "0.1.9"
    MODE = "PASSIVE_INTERFACE_CONTINUOUS_COUNTERS"
    AUTHORITY = "NONE"

    def __init__(
        self,
        *,
        counter_reader: Callable[[], list[dict[str, Any]]] | None = None,
        cadence_seconds: float = 1.0,
        history_seconds: int = 60,
        max_interfaces: int = 64,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        autostart: bool = True,
        baseline_analyzer: FlowBaselineAnalyzer | None = None,
    ) -> None:
        self.counter_reader = counter_reader or _default_counter_reader
        self.cadence_seconds = max(0.5, min(float(cadence_seconds), 10.0))
        self.history_seconds = max(10, min(int(history_seconds), 300))
        self.max_interfaces = max(1, min(int(max_interfaces), 256))
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self.baseline_analyzer = baseline_analyzer or FlowBaselineAnalyzer()

        max_history = max(10, int(self.history_seconds / self.cadence_seconds) + 8)
        self._history: deque[dict[str, Any]] = deque(maxlen=max_history)
        self._previous: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._thread: threading.Thread | None = None

        self.started_at = self.wall_clock()
        self.started_monotonic = self.monotonic_clock()
        self.sequence = 0
        self.attempts = 0
        self.completed = 0
        self.failures = 0
        self.consecutive_failures = 0
        self.counter_resets = 0
        self.late_samples = 0
        self.gap_events = 0
        self.missed_slots_estimate = 0
        self.max_gap_seconds_observed = 0.0
        self.last_gap_seconds: float | None = None
        self.last_error: str | None = None
        self.last_sample_at: float | None = None
        self.last_sample_monotonic: float | None = None
        self.last_interval_seconds: float | None = None
        self.close_incomplete = False

        if autostart:
            self.start()

    @staticmethod
    def _normalize_rows(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in (rows if isinstance(rows, list) else [])[: limit * 2]:
            if not isinstance(item, dict):
                continue
            name = _bounded_text(item.get("interface") or item.get("name"), 128)
            key = name.lower()
            if not name or key in seen:
                continue
            seen.add(key)
            normalized.append({
                "interface": name,
                "bytes_sent": _counter(item.get("bytes_sent")),
                "bytes_recv": _counter(item.get("bytes_recv")),
                "packets_sent": _counter(item.get("packets_sent")),
                "packets_recv": _counter(item.get("packets_recv")),
                "errin": _counter(item.get("errin")),
                "errout": _counter(item.get("errout")),
                "dropin": _counter(item.get("dropin")),
                "dropout": _counter(item.get("dropout")),
            })
            if len(normalized) >= limit:
                break
        return normalized

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            if self._closed.is_set():
                return
            self._thread = threading.Thread(
                target=self._run,
                name="CyberDefenderPassiveFlowSampler",
                daemon=True,
            )
            self._thread.start()

    def _run(self) -> None:
        # Sample immediately so a full inventory snapshot does not need to wait a
        # full cadence before continuity telemetry becomes observable.
        next_due = self.monotonic_clock()
        while not self._closed.is_set():
            now = self.monotonic_clock()
            wait_for = max(0.0, next_due - now)
            if self._closed.wait(wait_for):
                break
            self.sample_once()
            after = self.monotonic_clock()
            next_due += self.cadence_seconds
            # After sleep/resume or severe scheduling delay, skip catch-up loops.
            if after - next_due > self.cadence_seconds:
                next_due = after + self.cadence_seconds

    def sample_once(self) -> bool:
        now_mono = float(self.monotonic_clock())
        now_wall = float(self.wall_clock())

        with self._lock:
            self.attempts += 1
            previous_sample_mono = self.last_sample_monotonic

        try:
            raw = self.counter_reader()
            current = self._normalize_rows(raw, self.max_interfaces)
        except Exception as exc:
            with self._lock:
                self.failures += 1
                self.consecutive_failures += 1
                self.last_error = type(exc).__name__
            return False

        with self._lock:
            interval_global = None
            if previous_sample_mono is not None:
                interval_global = max(0.0, now_mono - previous_sample_mono)
                self.last_interval_seconds = interval_global
                if interval_global > self.cadence_seconds * 1.5:
                    self.late_samples += 1
                if interval_global > self.cadence_seconds * 2.5:
                    self.gap_events += 1
                    self.last_gap_seconds = interval_global
                    self.max_gap_seconds_observed = max(self.max_gap_seconds_observed, interval_global)
                    estimated_slots = max(1, int(interval_global / self.cadence_seconds) - 1)
                    self.missed_slots_estimate += estimated_slots

            published: list[dict[str, Any]] = []
            next_previous: dict[str, dict[str, Any]] = {}
            for row in current:
                key = row["interface"].lower()
                previous = self._previous.get(key)
                baseline_ready = False
                counter_reset = False
                interval_seconds: float | None = None
                delta_sent = delta_recv = 0
                delta_packets_sent = delta_packets_recv = 0

                if previous is not None:
                    interval_seconds = max(0.0, now_mono - float(previous.get("sampled_at", now_mono)))
                    counter_reset = any(
                        row[field] < _counter(previous.get(field))
                        for field in ("bytes_sent", "bytes_recv", "packets_sent", "packets_recv")
                    )
                    if counter_reset:
                        self.counter_resets += 1
                    elif interval_seconds > 0.0:
                        # Very large post-suspend intervals are explicitly a new
                        # baseline, not a misleading "instantaneous" rate.
                        if interval_seconds <= max(10.0, self.cadence_seconds * 8.0):
                            baseline_ready = True
                            delta_sent = row["bytes_sent"] - _counter(previous.get("bytes_sent"))
                            delta_recv = row["bytes_recv"] - _counter(previous.get("bytes_recv"))
                            delta_packets_sent = row["packets_sent"] - _counter(previous.get("packets_sent"))
                            delta_packets_recv = row["packets_recv"] - _counter(previous.get("packets_recv"))

                tx_bps = (delta_sent / interval_seconds) if baseline_ready and interval_seconds else 0.0
                rx_bps = (delta_recv / interval_seconds) if baseline_ready and interval_seconds else 0.0
                tx_pps = (delta_packets_sent / interval_seconds) if baseline_ready and interval_seconds else 0.0
                rx_pps = (delta_packets_recv / interval_seconds) if baseline_ready and interval_seconds else 0.0

                published.append({
                    **row,
                    "baseline_ready": baseline_ready,
                    "counter_reset": counter_reset,
                    "interval_seconds": round(interval_seconds, 4) if interval_seconds is not None else None,
                    "delta_bytes_sent": delta_sent,
                    "delta_bytes_recv": delta_recv,
                    "delta_packets_sent": delta_packets_sent,
                    "delta_packets_recv": delta_packets_recv,
                    "tx_bytes_per_second": round(tx_bps, 2),
                    "rx_bytes_per_second": round(rx_bps, 2),
                    "tx_packets_per_second": round(tx_pps, 2),
                    "rx_packets_per_second": round(rx_pps, 2),
                    "source": "LOCAL_INTERFACE_COUNTERS",
                    "passive": True,
                    "authoritative": False,
                    "authority": "NONE",
                    "authorization": "NOT_GRANTED",
                })
                next_previous[key] = {**row, "sampled_at": now_mono}

            self._previous = next_previous
            self.sequence += 1
            self.completed += 1
            self.consecutive_failures = 0
            self.last_error = None
            self.last_sample_at = now_wall
            self.last_sample_monotonic = now_mono
            self._history.append({
                "sequence": self.sequence,
                "sampled_at": now_wall,
                "sampled_at_monotonic": now_mono,
                "interfaces": copy.deepcopy(published),
            })
            return True

    @staticmethod
    def _aggregate_sample(sample: dict[str, Any], active: set[str]) -> dict[str, float | int | bool]:
        rows = sample.get("interfaces", []) if isinstance(sample, dict) else []
        scoped = [
            row for row in rows
            if isinstance(row, dict) and str(row.get("interface", "")).lower() in active
        ]
        ready = [row for row in scoped if bool(row.get("baseline_ready", False))]
        return {
            "active_interfaces": len(scoped),
            "baseline_ready": bool(scoped) and len(ready) == len(scoped),
            "tx_bytes_per_second": round(sum(float(row.get("tx_bytes_per_second", 0.0) or 0.0) for row in ready), 2),
            "rx_bytes_per_second": round(sum(float(row.get("rx_bytes_per_second", 0.0) or 0.0) for row in ready), 2),
            "tx_packets_per_second": round(sum(float(row.get("tx_packets_per_second", 0.0) or 0.0) for row in ready), 2),
            "rx_packets_per_second": round(sum(float(row.get("rx_packets_per_second", 0.0) or 0.0) for row in ready), 2),
        }

    @staticmethod
    def _window_stats(samples: list[dict[str, Any]], active: set[str]) -> dict[str, Any]:
        aggregates = [PassiveInterfaceFlowSampler._aggregate_sample(sample, active) for sample in samples]
        ready = [item for item in aggregates if item["baseline_ready"]]
        if not ready:
            return {
                "samples": 0,
                "rx_bytes_per_second_avg": 0.0,
                "tx_bytes_per_second_avg": 0.0,
                "rx_bytes_per_second_peak": 0.0,
                "tx_bytes_per_second_peak": 0.0,
            }
        return {
            "samples": len(ready),
            "rx_bytes_per_second_avg": round(sum(float(x["rx_bytes_per_second"]) for x in ready) / len(ready), 2),
            "tx_bytes_per_second_avg": round(sum(float(x["tx_bytes_per_second"]) for x in ready) / len(ready), 2),
            "rx_bytes_per_second_peak": round(max(float(x["rx_bytes_per_second"]) for x in ready), 2),
            "tx_bytes_per_second_peak": round(max(float(x["tx_bytes_per_second"]) for x in ready), 2),
        }

    def snapshot(self, active_interfaces: set[str] | None = None) -> dict[str, Any]:
        active = {str(name).lower() for name in (active_interfaces or set()) if str(name).strip()}
        now_mono = float(self.monotonic_clock())
        with self._lock:
            history = copy.deepcopy(list(self._history))
            sequence = self.sequence
            attempts = self.attempts
            completed = self.completed
            failures = self.failures
            consecutive_failures = self.consecutive_failures
            counter_resets = self.counter_resets
            late_samples = self.late_samples
            gap_events = self.gap_events
            missed_slots = self.missed_slots_estimate
            max_gap = self.max_gap_seconds_observed
            last_gap = self.last_gap_seconds
            last_error = self.last_error
            last_sample_at = self.last_sample_at
            last_sample_mono = self.last_sample_monotonic
            last_interval = self.last_interval_seconds
            thread_alive = bool(self._thread and self._thread.is_alive())

        latest = history[-1] if history else {"interfaces": []}
        latest_aggregate = self._aggregate_sample(latest, active) if active else {
            "active_interfaces": 0,
            "baseline_ready": False,
            "tx_bytes_per_second": 0.0,
            "rx_bytes_per_second": 0.0,
            "tx_packets_per_second": 0.0,
            "rx_packets_per_second": 0.0,
        }
        latest_interfaces = []
        for row in latest.get("interfaces", []) if isinstance(latest, dict) else []:
            if not isinstance(row, dict):
                continue
            enriched = dict(row)
            enriched["active_default_route"] = str(row.get("interface", "")).lower() in active if active else False
            latest_interfaces.append(enriched)

        sample_age = None if last_sample_mono is None else max(0.0, now_mono - last_sample_mono)
        stale_after = max(3.0, self.cadence_seconds * 3.0)
        stale = sample_age is None or sample_age > stale_after

        # Select rolling windows by sample timestamp, not by list length, so
        # late/missed samples remain visible rather than silently compressed.
        now_wall = float(self.wall_clock())
        last_5 = [s for s in history if now_wall - float(s.get("sampled_at", now_wall)) <= 5.0]
        last_30 = [s for s in history if now_wall - float(s.get("sampled_at", now_wall)) <= 30.0]
        window_5 = self._window_stats(last_5, active) if active else self._window_stats([], active)
        window_30 = self._window_stats(last_30, active) if active else self._window_stats([], active)

        denominator = completed + failures + missed_slots
        coverage_ratio = (completed / denominator) if denominator > 0 else 0.0

        status = "HEALTHY"
        if consecutive_failures > 0 or stale or not thread_alive:
            status = "DEGRADED"
        elif completed < 2:
            status = "STARTING"

        aggregate = {
            "scope": "ACTIVE_DEFAULT_ROUTE_INTERFACES" if active else "NO_ACTIVE_ROUTE_CONTEXT",
            **latest_aggregate,
            "instant_rx_bytes_per_second": float(latest_aggregate["rx_bytes_per_second"]),
            "instant_tx_bytes_per_second": float(latest_aggregate["tx_bytes_per_second"]),
            "window_5s": window_5,
            "window_30s": window_30,
        }

        aggregate_history = [self._aggregate_sample(sample, active) for sample in history] if active else []
        baseline_analysis = self.baseline_analyzer.analyze(
            aggregate_history,
            coverage_percent=round(coverage_ratio * 100.0, 3),
            stale=stale,
            sequence=sequence,
        )

        return {
            "schema": "cyberdefender.interface-flow-continuity.v0.1.9",
            "version": self.VERSION,
            "mode": self.MODE,
            "status": status,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "passive": True,
            "packet_capture": False,
            "per_connection_byte_attribution": False,
            "external_enrichment": False,
            "cadence_seconds": self.cadence_seconds,
            "sequence": sequence,
            "sampled_at": last_sample_at,
            "sample_age_seconds": round(sample_age, 3) if sample_age is not None else None,
            "stale_after_seconds": stale_after,
            "stale": stale,
            "last_interval_seconds": round(last_interval, 4) if last_interval is not None else None,
            "interfaces": latest_interfaces,
            "aggregate": aggregate,
            "baseline_analysis": baseline_analysis,
            "continuity": {
                "attempts": attempts,
                "completed": completed,
                "failures": failures,
                "consecutive_failures": consecutive_failures,
                "late_samples": late_samples,
                "gap_events": gap_events,
                "missed_slots_estimate": missed_slots,
                "coverage_ratio": round(coverage_ratio, 6),
                "coverage_percent": round(coverage_ratio * 100.0, 3),
                "counter_resets": counter_resets,
                "last_gap_seconds": round(last_gap, 3) if last_gap is not None else None,
                "max_gap_seconds_observed": round(max_gap, 3),
                "last_error": last_error,
                "worker_alive": thread_alive,
            },
            "semantics": {
                "instant_rate": "LATEST_VALID_COUNTER_DELTA",
                "window_5s": "ROLLING_MEAN_AND_PEAK_OF_VALID_SAMPLES",
                "window_30s": "ROLLING_MEAN_AND_PEAK_OF_VALID_SAMPLES",
                "coverage_ratio": "SAMPLING_CONTINUITY_ESTIMATE_NOT_PACKET_DELIVERY_GUARANTEE",
                "baseline_confidence": "EVIDENCE_QUALITY_NOT_ATTACK_PROBABILITY",
                "gaps": "OBSERVABLE_NOT_FABRICATED_AWAY",
            },
            "bounds": {
                "max_interfaces": self.max_interfaces,
                "history_seconds": self.history_seconds,
            },
        }

    def health_check(self) -> dict[str, Any]:
        snapshot = self.snapshot(set())
        return {
            "component": "PassiveInterfaceFlowSampler",
            "version": self.VERSION,
            "status": snapshot["status"],
            "mode": self.MODE,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "packet_capture": False,
            "per_connection_byte_attribution": False,
            "cadence_seconds": self.cadence_seconds,
            "sequence": snapshot["sequence"],
            "sample_age_seconds": snapshot["sample_age_seconds"],
            "stale": snapshot["stale"],
            "continuity": snapshot["continuity"],
        }

    def close(self, timeout: float = 1.0) -> None:
        self._closed.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=max(0.0, min(float(timeout), 5.0)))
            self.close_incomplete = thread.is_alive()
