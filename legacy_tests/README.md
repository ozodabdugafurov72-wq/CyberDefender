# Legacy regression evidence

These tests are preserved as historical evidence for superseded contracts.
They are **not** part of the current release gate because newer tests replace
their assumptions:

- EventBus v2.1/v2.2 queue-full tests -> EventBus v2.4 reserve + fairness tests.
- EventBus extended adversarial v1.0 -> v1.1.
- Resource Safety Plane v1.0.1 state-transition tests -> v1.0.2/P0.4 tests.

Do not treat a failure in this folder as a current production regression unless
the test is first updated to the active component contract.
