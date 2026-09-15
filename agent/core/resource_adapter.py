"""
CyberDefender Resource Guard Adapter

Connects ResourceGuard to the internal EventBus.

ResourceGuard evaluates host resource pressure.
This adapter publishes the result as a security telemetry event.

Important:
    This adapter does not execute response actions.
"""

from __future__ import annotations

from typing import Any, Dict

from agent.core.resource_guard import ResourceGuard
from agent.bus.event_bus import EventBus


class ResourceGuardAdapter:
    VERSION = "1.0"

    EVENT_TYPE = "RESOURCE_STATUS"

    def __init__(
        self,
        resource_guard: ResourceGuard,
        event_bus: EventBus,
    ):
        self.resource_guard = resource_guard
        self.event_bus = event_bus

        self.publish_count = 0
        self.failed_count = 0

    def health_check(self) -> Dict[str, Any]:
        return {
            "adapter": "ResourceGuardAdapter",
            "status": "HEALTHY",
            "version": self.VERSION,
        }

    def publish_result(
        self,
        result: Dict[str, Any],
    ) -> bool:
        """
        Publish an already-evaluated ResourceGuard result.

        ResourceGuard.check() must be executed exactly once
        per runtime cycle. This adapter is responsible only
        for converting the result into trusted telemetry and
        publishing it to EventBus.

        The adapter does not execute response actions.
        """

        try:

            if not isinstance(result, dict):
                self.failed_count += 1
                return False

            state = result.get(
                "state",
                ResourceGuard.NORMAL,
            )

            severity_map = {
                ResourceGuard.NORMAL: "INFO",
                ResourceGuard.DEGRADED: "WARNING",
                ResourceGuard.CRITICAL: "CRITICAL",
            }

            event = {
                "event_type": self.EVENT_TYPE,
                "severity": severity_map.get(
                    state,
                    "INFO",
                ),
                "source": "ResourceGuardAdapter",
                "version": self.VERSION,
                "data": result,
            }

            published = self.event_bus.publish(
                event
            )

            if published:
                self.publish_count += 1
                return True

            self.failed_count += 1
            return False

        except Exception:
            self.failed_count += 1
            return False
    def get_stats(self) -> Dict[str, Any]:
        return {
            "adapter": "ResourceGuardAdapter",
            "version": self.VERSION,
            "published": self.publish_count,
            "failed": self.failed_count,
        }
