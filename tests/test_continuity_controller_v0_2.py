from __future__ import annotations

import unittest

from agent.disconnected.continuity_controller import (
    ContinuityController,
    ContinuityInputs,
    ContinuityMode,
)


def healthy_inputs(**overrides):
    values = dict(
        cloud_reachable=True,
        primary_reachable=True,
        lan_reachable=True,
        safety_healthy=True,
        trust_healthy=True,
        crypto_healthy=True,
        storage_healthy=True,
        offline_policy_valid=True,
        reconciliation_required=False,
    )

    values.update(overrides)

    return ContinuityInputs(**values)


class ContinuityControllerV02Tests(unittest.TestCase):

    def test_full_connected(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs()
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.FULL_CONNECTED,
        )

    def test_cloud_isolated(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                cloud_reachable=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.CLOUD_ISOLATED,
        )

    def test_cloud_unknown_is_not_full_connected(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                cloud_reachable=None,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.CLOUD_ISOLATED,
        )

        self.assertEqual(
            d.reason,
            "CLOUD_REACHABILITY_NOT_PROVEN",
        )

    def test_primary_isolated(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                primary_reachable=False,
                lan_reachable=True,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.PRIMARY_ISOLATED,
        )

    def test_full_isolated(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                primary_reachable=False,
                lan_reachable=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.FULL_ISOLATED,
        )

    def test_primary_unknown_fails_closed(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                primary_reachable=None,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

    def test_lan_unknown_while_primary_lost_fails_closed(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                primary_reachable=False,
                lan_reachable=None,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

    def test_invalid_offline_policy_fails_closed(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                primary_reachable=False,
                lan_reachable=True,
                offline_policy_valid=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

        self.assertEqual(
            d.reason,
            "OFFLINE_POLICY_NOT_VALID",
        )

    def test_safety_failure_dominates_network(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                safety_healthy=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

        self.assertEqual(
            d.reason,
            "SAFETY_UNHEALTHY",
        )

    def test_trust_failure_dominates_network(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                trust_healthy=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

    def test_crypto_failure_dominates_network(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                crypto_healthy=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

    def test_storage_failure_dominates_network(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                storage_healthy=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

    def test_reconciliation_required(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                reconciliation_required=True,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.RECONCILING,
        )

    def test_reconciliation_stays_until_external_clear(self):
        c = ContinuityController()

        inputs = healthy_inputs(
            reconciliation_required=True,
        )

        d1 = c.evaluate(inputs)
        d2 = c.evaluate(inputs)
        d3 = c.evaluate(inputs)

        self.assertEqual(
            d1.mode,
            ContinuityMode.RECONCILING,
        )

        self.assertEqual(
            d2.mode,
            ContinuityMode.RECONCILING,
        )

        self.assertEqual(
            d3.mode,
            ContinuityMode.RECONCILING,
        )

    def test_reconciliation_clears_only_from_input(self):
        c = ContinuityController()

        d1 = c.evaluate(
            healthy_inputs(
                reconciliation_required=True,
            )
        )

        d2 = c.evaluate(
            healthy_inputs(
                reconciliation_required=False,
            )
        )

        self.assertEqual(
            d1.mode,
            ContinuityMode.RECONCILING,
        )

        self.assertEqual(
            d2.mode,
            ContinuityMode.FULL_CONNECTED,
        )

    def test_reconciliation_never_overrides_safety_failure(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                safety_healthy=False,
                reconciliation_required=True,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

    def test_reconciliation_not_possible_while_primary_down(self):
        c = ContinuityController()

        d = c.evaluate(
            healthy_inputs(
                primary_reachable=False,
                lan_reachable=True,
                reconciliation_required=True,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.PRIMARY_ISOLATED,
        )

    def test_restart_determinism(self):
        inputs = healthy_inputs(
            primary_reachable=True,
            reconciliation_required=True,
        )

        c1 = ContinuityController()
        c2 = ContinuityController()

        d1 = c1.evaluate(inputs)
        d2 = c2.evaluate(inputs)

        self.assertEqual(d1, d2)

        self.assertEqual(
            d1.mode,
            ContinuityMode.RECONCILING,
        )

    def test_health_snapshot_never_grants_authority(self):
        c = ContinuityController()

        h = c.health_snapshot()

        self.assertEqual(
            h["authority"],
            "NONE",
        )

        self.assertEqual(
            h["authorization"],
            "NOT_GRANTED",
        )

        self.assertFalse(
            h["authority_increase_allowed"],
        )

        self.assertFalse(
            h["authoritative"],
        )

        self.assertTrue(
            h["local_protection_required"],
        )

        self.assertTrue(
            h["fail_closed"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
