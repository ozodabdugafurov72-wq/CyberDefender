from __future__ import annotations

import unittest

from agent.disconnected.continuity_controller import (
    ContinuityController,
    ContinuityInputs,
    ContinuityMode,
)


def inputs(**overrides):
    values = {
        "cloud_reachable": True,
        "primary_reachable": True,
        "lan_reachable": True,

        "safety_healthy": True,
        "trust_healthy": True,
        "crypto_healthy": True,
        "storage_healthy": True,

        "offline_policy_valid": True,

        # Deliberately UNKNOWN unless a test supplies
        # authenticated/durable reconciliation evidence.
        "reconciliation_required": None,
    }

    values.update(overrides)

    return ContinuityInputs(**values)


class ContinuityControllerV03Tests(unittest.TestCase):

    def test_unknown_reconciliation_fails_closed(self):
        c = ContinuityController()

        d = c.evaluate(inputs())

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

        self.assertEqual(
            d.reason,
            "RECONCILIATION_STATE_UNKNOWN",
        )

    def test_explicit_no_reconciliation_allows_connected_classification(self):
        c = ContinuityController()

        d = c.evaluate(
            inputs(
                reconciliation_required=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.FULL_CONNECTED,
        )

    def test_explicit_reconciliation_is_sticky(self):
        c = ContinuityController()

        evidence = inputs(
            reconciliation_required=True,
        )

        for _ in range(5):
            d = c.evaluate(evidence)

            self.assertEqual(
                d.mode,
                ContinuityMode.RECONCILING,
            )

    def test_cloud_isolated_requires_known_reconciliation_state(self):
        c = ContinuityController()

        d = c.evaluate(
            inputs(
                cloud_reachable=False,
                reconciliation_required=False,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.CLOUD_ISOLATED,
        )

    def test_cloud_state_does_not_override_unknown_reconciliation(self):
        c = ContinuityController()

        d = c.evaluate(
            inputs(
                cloud_reachable=False,
                reconciliation_required=None,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

        self.assertEqual(
            d.reason,
            "RECONCILIATION_STATE_UNKNOWN",
        )

    def test_safety_failure_dominates_unknown_reconciliation(self):
        c = ContinuityController()

        d = c.evaluate(
            inputs(
                safety_healthy=False,
                reconciliation_required=None,
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

    def test_reconciliation_state_irrelevant_while_primary_down(self):
        c = ContinuityController()

        d = c.evaluate(
            inputs(
                primary_reachable=False,
                lan_reachable=True,
                offline_policy_valid=True,
                reconciliation_required=None,
            )
        )

        self.assertEqual(
            d.mode,
            ContinuityMode.PRIMARY_ISOLATED,
        )

    def test_no_offline_policy_still_fails_closed(self):
        c = ContinuityController()

        d = c.evaluate(
            inputs(
                primary_reachable=False,
                lan_reachable=True,
                offline_policy_valid=False,
                reconciliation_required=None,
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

    def test_unknown_state_restart_deterministic(self):
        evidence = inputs(
            reconciliation_required=None,
        )

        d1 = ContinuityController().evaluate(evidence)
        d2 = ContinuityController().evaluate(evidence)

        self.assertEqual(d1, d2)

        self.assertEqual(
            d1.mode,
            ContinuityMode.SAFE_DEGRADED,
        )

    def test_security_contract_never_grants_authority(self):
        c = ContinuityController()

        d = c.evaluate(
            inputs(
                reconciliation_required=False,
            )
        )

        self.assertEqual(d.authority, "NONE")
        self.assertEqual(
            d.authorization,
            "NOT_GRANTED",
        )
        self.assertFalse(
            d.authority_increase_allowed,
        )
        self.assertTrue(d.fail_closed)

        h = c.health_snapshot()

        self.assertEqual(h["version"], "0.3")
        self.assertFalse(h["authoritative"])
        self.assertTrue(
            h["unknown_reconciliation_fails_closed"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
