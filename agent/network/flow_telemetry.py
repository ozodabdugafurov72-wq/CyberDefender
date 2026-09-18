from __future__ import annotations

import time
from typing import Any, Callable


_MAX_COUNTER = (1 << 63) - 1


def _bounded_text(value: Any, limit: int = 128) -> str:
    return str(value or "").strip()[:limit]


def _counter(value: Any) -> int:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(number, _MAX_COUNTER))


class InterfaceFlowTracker:
    """Stateful, passive interface-level byte/rate telemetry.

    This intentionally does NOT attribute bytes to individual TCP connections.
    It observes local OS interface counters only, then derives bounded deltas and
    rates from consecutive samples. The output is telemetry evidence, never an
    authorization source.
    """

    VERSION = "0.1.7"
    MODE = "PASSIVE_INTERFACE_COUNTERS"
    AUTHORITY = "NONE"

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_interfaces: int = 64,
    ) -> None:
        self.clock = clock
        self.max_interfaces = max(1, min(int(max_interfaces), 256))
        self._previous: dict[str, dict[str, Any]] = {}
        self.samples = 0
        self.counter_resets = 0

    @staticmethod
    def _normalize_rows(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in rows[:limit * 2]:
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

    def observe(
        self,
        rows: list[dict[str, Any]],
        *,
        active_interfaces: set[str] | None = None,
    ) -> dict[str, Any]:
        now = float(self.clock())
        active = {str(name).lower() for name in (active_interfaces or set()) if str(name).strip()}
        current = self._normalize_rows(rows if isinstance(rows, list) else [], self.max_interfaces)
        published: list[dict[str, Any]] = []
        next_previous: dict[str, dict[str, Any]] = {}

        for row in current:
            key = row["interface"].lower()
            previous = self._previous.get(key)
            baseline_ready = False
            counter_reset = False
            interval_seconds: float | None = None
            delta_sent = 0
            delta_recv = 0
            delta_packets_sent = 0
            delta_packets_recv = 0

            if previous is not None:
                interval_seconds = max(0.0, now - float(previous.get("sampled_at", now)))
                counter_reset = any(
                    row[field] < _counter(previous.get(field))
                    for field in ("bytes_sent", "bytes_recv", "packets_sent", "packets_recv")
                )
                if counter_reset:
                    self.counter_resets += 1
                elif interval_seconds > 0.0:
                    baseline_ready = True
                    delta_sent = row["bytes_sent"] - _counter(previous.get("bytes_sent"))
                    delta_recv = row["bytes_recv"] - _counter(previous.get("bytes_recv"))
                    delta_packets_sent = row["packets_sent"] - _counter(previous.get("packets_sent"))
                    delta_packets_recv = row["packets_recv"] - _counter(previous.get("packets_recv"))

            tx_bps = (delta_sent / interval_seconds) if baseline_ready and interval_seconds else 0.0
            rx_bps = (delta_recv / interval_seconds) if baseline_ready and interval_seconds else 0.0
            tx_pps = (delta_packets_sent / interval_seconds) if baseline_ready and interval_seconds else 0.0
            rx_pps = (delta_packets_recv / interval_seconds) if baseline_ready and interval_seconds else 0.0

            entry = {
                **row,
                "active_default_route": (key in active) if active else False,
                "baseline_ready": baseline_ready,
                "counter_reset": counter_reset,
                "interval_seconds": round(interval_seconds, 3) if interval_seconds is not None else None,
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
            }
            published.append(entry)
            next_previous[key] = {**row, "sampled_at": now}

        self._previous = next_previous
        self.samples += 1

        scoped = [row for row in published if row["active_default_route"]]
        baseline_rows = [row for row in scoped if row["baseline_ready"]]
        aggregate = {
            "scope": "ACTIVE_DEFAULT_ROUTE_INTERFACES" if active else "NO_ACTIVE_ROUTE_CONTEXT",
            "active_interfaces": len(scoped),
            "baseline_ready_interfaces": len(baseline_rows),
            "baseline_ready": bool(scoped) and len(baseline_rows) == len(scoped),
            "tx_bytes_per_second": round(sum(float(row["tx_bytes_per_second"]) for row in scoped), 2),
            "rx_bytes_per_second": round(sum(float(row["rx_bytes_per_second"]) for row in scoped), 2),
            "tx_packets_per_second": round(sum(float(row["tx_packets_per_second"]) for row in scoped), 2),
            "rx_packets_per_second": round(sum(float(row["rx_packets_per_second"]) for row in scoped), 2),
            "delta_bytes_sent": sum(int(row["delta_bytes_sent"]) for row in scoped),
            "delta_bytes_recv": sum(int(row["delta_bytes_recv"]) for row in scoped),
        }

        return {
            "schema": "cyberdefender.interface-flow-telemetry.v0.1.7",
            "version": self.VERSION,
            "mode": self.MODE,
            "status": "HEALTHY",
            "authority": self.AUTHORITY,
            "authoritative": False,
            "passive": True,
            "packet_capture": False,
            "per_connection_byte_attribution": False,
            "external_enrichment": False,
            "sampled_at_monotonic": now,
            "interfaces": published,
            "aggregate": aggregate,
            "samples": self.samples,
            "counter_resets": self.counter_resets,
            "bounds": {"max_interfaces": self.max_interfaces},
        }
