from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from agent.disconnected.continuity_controller import (
    ContinuityInputs,
)


@dataclass(frozen=True)
class ConnectivityEvidence:
    """
    Connectivity observations supplied by external trusted observers.

    This class performs no probing itself.

    None means UNKNOWN and must never be promoted to True.
    """

    primary_reachable: Optional[bool] = None
    cloud_reachable: Optional[bool] = None
    lan_reachable: Optional[bool] = None


@dataclass(frozen=True)
class PolicyReconciliationEvidence:
    """
    Security state that must eventually come from signed/durable stores.

    Until those stores exist:
      offline_policy_valid=False
      reconciliation_required=None
    """

    offline_policy_valid: bool = False
    reconciliation_required: Optional[bool] = None


class ContinuityEvidenceProvider:
    """
    CyberDefender ACP Continuity Evidence Provider v0.1.

    Pure evidence mapper:
      runtime health + explicit connectivity/policy evidence
          -> ContinuityInputs

    Security properties:
      - no network requests;
      - no OS actions;
      - no policy changes;
      - no authorization;
      - UNKNOWN is never upgraded to trusted/healthy;
      - missing security evidence fails closed.
    """

    VERSION = "0.1"

    @staticmethod
    def _mapping(
        value: Any,
    ) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return value

        return {}

    @classmethod
    def _safety_healthy(
        cls,
        health: Mapping[str, Any],
    ) -> bool:

        safety = cls._mapping(
            health.get("safety_core")
        )

        return bool(
            safety.get("status") in {
                "SAFE",
                "HEALTHY",
            }
            and safety.get("safe_mode") is False
            and safety.get("shutdown_requested") is False
            and safety.get("fail_closed") is True
        )

    @classmethod
    def _crypto_healthy(
        cls,
        health: Mapping[str, Any],
    ) -> bool:

        key_manager = cls._mapping(
            health.get("key_manager")
        )

        return bool(
            key_manager.get("status") == "HEALTHY"
            and key_manager.get("active_key") is True
            and key_manager.get("operational") is True
            and key_manager.get("state_integrity") is True
            and key_manager.get("key_material_export") is False
        )

    @classmethod
    def _trust_healthy(
        cls,
        health: Mapping[str, Any],
    ) -> bool:

        replay = cls._mapping(
            health.get("replay_guard")
        )

        runtime_pipeline = cls._mapping(
            health.get("runtime_pipeline")
        )

        admission = cls._mapping(
            health.get("admission_gateway")
        )

        return bool(
            replay.get("status") == "HEALTHY"
            and runtime_pipeline.get("status") == "HEALTHY"
            and admission.get("status") == "HEALTHY"
        )

    @classmethod
    def _storage_healthy(
        cls,
        health: Mapping[str, Any],
    ) -> bool:

        spool = cls._mapping(
            health.get("spool")
        )

        return bool(
            spool.get("status") == "HEALTHY"
            and spool.get("bounded") is True
            and spool.get("capacity_status") == "NORMAL"
            and spool.get("pending_index_ready") is True
            and spool.get("terminal_state_safe") is True
        )

    def build_inputs(
        self,
        *,
        runtime_health: Mapping[str, Any],
        connectivity: ConnectivityEvidence | None = None,
        policy: PolicyReconciliationEvidence | None = None,
    ) -> ContinuityInputs:

        if not isinstance(runtime_health, Mapping):
            raise TypeError(
                "runtime_health mapping bo'lishi kerak"
            )

        connectivity = (
            connectivity
            if connectivity is not None
            else ConnectivityEvidence()
        )

        policy = (
            policy
            if policy is not None
            else PolicyReconciliationEvidence()
        )

        return ContinuityInputs(
            cloud_reachable=connectivity.cloud_reachable,
            primary_reachable=connectivity.primary_reachable,
            lan_reachable=connectivity.lan_reachable,

            safety_healthy=self._safety_healthy(
                runtime_health
            ),

            trust_healthy=self._trust_healthy(
                runtime_health
            ),

            crypto_healthy=self._crypto_healthy(
                runtime_health
            ),

            storage_healthy=self._storage_healthy(
                runtime_health
            ),

            offline_policy_valid=bool(
                policy.offline_policy_valid
            ),

            reconciliation_required=(
                policy.reconciliation_required
            ),
        )

    def health_snapshot(self) -> dict[str, object]:
        return {
            "component": "ContinuityEvidenceProvider",
            "version": self.VERSION,
            "status": "HEALTHY",
            "mode": "PASSIVE_ONLY",

            "authority": "NONE",
            "authorization": "NOT_GRANTED",
            "authoritative": False,

            "network_probe": False,
            "os_actions": False,
            "policy_mutation": False,

            "unknown_connectivity_preserved": True,
            "missing_security_evidence_fails_closed": True,

            "offline_policy_default": False,
            "reconciliation_default": "UNKNOWN",
        }
