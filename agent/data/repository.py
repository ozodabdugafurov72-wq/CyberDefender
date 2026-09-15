from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class DataRepository(ABC):
    """Non-authoritative structured read-model contract.

    Implementations may fail without granting authorization or bypassing the
    canonical SecurityEvent pipeline. They exist for queryable operational
    state, incident history and decision history only.
    """

    @abstractmethod
    def sync_cycle(
        self,
        *,
        endpoint: dict[str, Any],
        incidents: list[dict[str, Any]],
        risk: dict[str, Any] | None,
        policy: dict[str, Any] | None,
        verification: dict[str, Any] | None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    def recent_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def recent_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        """Optional lifecycle hook."""
        return None
