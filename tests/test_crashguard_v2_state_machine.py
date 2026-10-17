from __future__ import annotations

import itertools
import unittest

from agent import crashguard_v2
from agent.crashguard_v2.state_machine import (
    Event,
    Health,
    HealthEvidence,
    HealthSample,
    Lifecycle,
    TRANSITIONS,
    TransitionRejected,
    observe_health,
    transition,
)


class CrashGuardV2StateMachineTests(unittest.TestCase):
    def test_feature_flag_defaults_off(self) -> None:
        self.assertIs(False, crashguard_v2.FEATURE_FLAG_DEFAULT)

    def test_transition_table_defines_and_rejects_every_state_event_pair(self) -> None:
        self.assertEqual(10, len(Lifecycle))
        self.assertEqual(14, len(Event))
        for state, event in itertools.product(Lifecycle, Event):
            with self.subTest(state=state.value, event=event.value):
                if (state, event) in TRANSITIONS:
                    result = transition(state, event)
                    self.assertIsInstance(result.state, Lifecycle)
                    self.assertTrue(result.effects)
                    self.assertTrue(all(item.isupper() for item in result.effects))
                else:
                    with self.assertRaisesRegex(TransitionRejected, "CG2_TRANSITION_UNDEFINED"):
                        transition(state, event)

    def test_latched_boot_enters_safe_hold_without_budget_debit(self) -> None:
        result = transition(Lifecycle.LATCHED, Event.BOOT_OBSERVED)
        self.assertEqual(Lifecycle.SAFE_HOLD, result.state)
        self.assertIn("NO_BUDGET_DEBIT", result.effects)
        self.assertIn("DO_NOT_START_PRIVILEGED_RUNTIME", result.effects)
        self.assertIn("SIGNAL_LATCHED", result.effects)

    def test_stable_requires_three_spaced_fresh_samples_and_fifteen_more_minutes(self) -> None:
        evidence = HealthEvidence()
        for sequence, observed_at in ((1, 0.0), (2, 59.0), (3, 60.0), (4, 120.0), (5, 1019.0)):
            evidence, health = observe_health(
                evidence,
                HealthSample(sequence, observed_at, fresh=True, progress=True, invariants_ok=True),
            )
            self.assertEqual(Health.HEALTHY, health)
        evidence, health = observe_health(
            evidence,
            HealthSample(6, 1020.0, fresh=True, progress=True, invariants_ok=True),
        )
        self.assertEqual(Health.STABLE, health)
        self.assertEqual((0.0, 60.0, 120.0), evidence.healthy_samples)

    def test_unhealthy_or_replayed_sample_cannot_earn_stability(self) -> None:
        evidence = HealthEvidence()
        evidence, _ = observe_health(
            evidence, HealthSample(1, 0.0, fresh=True, progress=True, invariants_ok=True)
        )
        evidence, health = observe_health(
            evidence, HealthSample(2, 60.0, fresh=False, progress=True, invariants_ok=True, degraded=True)
        )
        self.assertEqual(Health.DEGRADED, health)
        self.assertEqual((), evidence.healthy_samples)
        with self.assertRaisesRegex(TransitionRejected, "CG2_HEALTH_SAMPLE_INVALID"):
            observe_health(
                evidence, HealthSample(2, 61.0, fresh=True, progress=True, invariants_ok=True)
            )


if __name__ == "__main__":
    unittest.main()

