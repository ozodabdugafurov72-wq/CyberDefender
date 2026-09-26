from __future__ import annotations

import unittest

from agent.disconnected.continuity_evidence_provider import (
    ConnectivityEvidence,
    ContinuityEvidenceProvider,
    PolicyReconciliationEvidence,
)


def healthy_health():
    return {
        "safety_core": {
            "status": "SAFE",
            "safe_mode": False,
            "shutdown_requested": False,
            "fail_closed": True,
        },

        "key_manager": {
            "status": "HEALTHY",
            "active_key": True,
            "operational": True,
            "state_integrity": True,
            "key_material_export": False,
        },

        "replay_guard": {
            "status": "HEALTHY",
        },

        "runtime_pipeline": {
            "status": "HEALTHY",
        },

        "admission_gateway": {
            "status": "HEALTHY",
        },

        "spool": {
            "status": "HEALTHY",
            "bounded": True,
            "capacity_status": "NORMAL",
            "pending_index_ready": True,
            "terminal_state_safe": True,
        },
    }


class ContinuityEvidenceProviderTests(unittest.TestCase):

    def test_healthy_local_security_evidence(self):
        p = ContinuityEvidenceProvider()

        i = p.build_inputs(
            runtime_health=healthy_health(),
        )

        self.assertTrue(i.safety_healthy)
        self.assertTrue(i.trust_healthy)
        self.assertTrue(i.crypto_healthy)
        self.assertTrue(i.storage_healthy)

    def test_connectivity_unknown_is_preserved(self):
        p = ContinuityEvidenceProvider()

        i = p.build_inputs(
            runtime_health=healthy_health(),
        )

        self.assertIsNone(i.primary_reachable)
        self.assertIsNone(i.cloud_reachable)
        self.assertIsNone(i.lan_reachable)

    def test_explicit_connectivity_passes_through(self):
        p = ContinuityEvidenceProvider()

        i = p.build_inputs(
            runtime_health=healthy_health(),
            connectivity=ConnectivityEvidence(
                primary_reachable=True,
                cloud_reachable=False,
                lan_reachable=True,
            ),
        )

        self.assertIs(i.primary_reachable, True)
        self.assertIs(i.cloud_reachable, False)
        self.assertIs(i.lan_reachable, True)

    def test_offline_policy_defaults_false(self):
        p = ContinuityEvidenceProvider()

        i = p.build_inputs(
            runtime_health=healthy_health(),
        )

        self.assertFalse(
            i.offline_policy_valid
        )

    def test_reconciliation_defaults_unknown(self):
        p = ContinuityEvidenceProvider()

        i = p.build_inputs(
            runtime_health=healthy_health(),
        )

        self.assertIsNone(
            i.reconciliation_required
        )

    def test_explicit_policy_evidence_passes_through(self):
        p = ContinuityEvidenceProvider()

        i = p.build_inputs(
            runtime_health=healthy_health(),
            policy=PolicyReconciliationEvidence(
                offline_policy_valid=True,
                reconciliation_required=False,
            ),
        )

        self.assertTrue(
            i.offline_policy_valid
        )

        self.assertIs(
            i.reconciliation_required,
            False,
        )

    def test_safety_safe_mode_fails_closed(self):
        h = healthy_health()
        h["safety_core"]["safe_mode"] = True

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.safety_healthy)

    def test_safety_fail_closed_invariant_required(self):
        h = healthy_health()
        h["safety_core"]["fail_closed"] = False

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.safety_healthy)

    def test_key_integrity_failure_fails_crypto(self):
        h = healthy_health()
        h["key_manager"]["state_integrity"] = False

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.crypto_healthy)

    def test_key_exportability_fails_crypto(self):
        h = healthy_health()
        h["key_manager"]["key_material_export"] = True

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.crypto_healthy)

    def test_missing_trust_component_fails_closed(self):
        h = healthy_health()
        del h["replay_guard"]

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.trust_healthy)

    def test_admission_failure_fails_trust(self):
        h = healthy_health()
        h["admission_gateway"]["status"] = "DEGRADED"

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.trust_healthy)

    def test_spool_terminal_state_required(self):
        h = healthy_health()
        h["spool"]["terminal_state_safe"] = False

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.storage_healthy)

    def test_spool_capacity_pressure_not_called_healthy(self):
        h = healthy_health()
        h["spool"]["capacity_status"] = "PRESSURE"

        i = ContinuityEvidenceProvider().build_inputs(
            runtime_health=h
        )

        self.assertFalse(i.storage_healthy)

    def test_provider_never_grants_authority(self):
        h = ContinuityEvidenceProvider().health_snapshot()

        self.assertEqual(
            h["authority"],
            "NONE",
        )

        self.assertEqual(
            h["authorization"],
            "NOT_GRANTED",
        )

        self.assertFalse(
            h["authoritative"],
        )

        self.assertFalse(
            h["network_probe"],
        )

        self.assertFalse(
            h["os_actions"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
