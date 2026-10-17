from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.crashguard_v2.recovery import (
    RecoveryAuthorizationError,
    RecoveryPublicKey,
    canonical_request,
    plan_recovery,
    reserve_recovery,
    verified_stable,
)
from agent.crashguard_v2.store import StoreV2, fresh_record


ALLOW = lambda _path: None
STORE_KEY = b"S" * 32
RELEASE = "a" * 64
SERVICE = "CyberDefenderAgent"
NOW = 2_000_000_000


class CrashGuardV2RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public = RecoveryPublicKey("operator-recovery-v1", raw)

    def request(self, *, nonce="nonce-0000000001", **updates) -> dict:
        value = {
            "action": "RECOVERY_PROBE",
            "service": SERVICE,
            "release_sha256": RELEASE,
            "state_generation": 7,
            "state_revision": 0,
            "nonce": nonce,
            "issued_at": NOW - 30,
            "expires_at": NOW + 300,
        }
        value.update(updates)
        return value

    def signed(self, request: dict) -> tuple[bytes, bytes]:
        raw = canonical_request(request)
        return raw, self.private.sign(raw)

    def store(self, root: Path) -> StoreV2:
        state, anchor = root / "state", root / "anchor"
        state.mkdir()
        anchor.mkdir()
        store = StoreV2(state, anchor, SERVICE, STORE_KEY, path_validator=ALLOW)
        record = fresh_record(SERVICE, boot_id="boot-a", monotonic_ns=100, wall_time_ns=1_000_000_000_000)
        record.update(lifecycle="LATCHED", generation=7, recovery_budget_remaining=1, attempts_since_stable=2)
        store.provision(record)
        return store

    def call_plan(self, store, request):
        raw, signature = self.signed(request)
        return plan_recovery(
            store,
            raw,
            signature,
            self.public,
            expected_service=SERVICE,
            expected_release_sha256=RELEASE,
            now=NOW,
        )

    def call_reserve(self, store, request, **kwargs):
        raw, signature = self.signed(request)
        return reserve_recovery(
            store,
            raw,
            signature,
            self.public,
            expected_service=SERVICE,
            expected_release_sha256=RELEASE,
            now=NOW,
            monotonic_ns=200,
            wall_time_ns=1_000_100_000_000,
            **kwargs,
        )

    def test_plan_is_zero_debit_and_valid_reservation_is_atomic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-recovery-valid-") as raw:
            with self.store(Path(raw)) as store:
                before = store.load()
                plan = self.call_plan(store, self.request())
                after_plan = store.load()
                self.assertEqual(before, after_plan)
                self.assertEqual(0, plan["budget_consumed"])
                committed = self.call_reserve(store, self.request())
                self.assertEqual("RECOVERY_PROBING", committed["lifecycle"])
                self.assertEqual(0, committed["recovery_budget_remaining"])
                self.assertIn("nonce-0000000001", committed["consumed_nonces"])
                self.assertEqual(8, committed["generation"])
                self.assertEqual(3, committed["attempts_since_stable"])

    def test_expired_wrong_service_wrong_digest_stale_and_bad_signature_reject(self) -> None:
        cases = (
            (self.request(expires_at=NOW - 1), "RECOVERY_EXPIRED"),
            (self.request(service="OtherService"), "RECOVERY_BINDING_MISMATCH"),
            (self.request(release_sha256="b" * 64), "RECOVERY_BINDING_MISMATCH"),
            (self.request(state_revision=9), "RECOVERY_STALE_REVISION"),
        )
        for index, (request, code) in enumerate(cases):
            with self.subTest(code=code), tempfile.TemporaryDirectory(prefix=f"cg2-recovery-reject-{index}-") as raw:
                with self.store(Path(raw)) as store:
                    with self.assertRaisesRegex(RecoveryAuthorizationError, code):
                        self.call_plan(store, request)
        with tempfile.TemporaryDirectory(prefix="cg2-recovery-signature-") as raw:
            with self.store(Path(raw)) as store:
                request = self.request()
                authorization, _ = self.signed(request)
                wrong_signature = Ed25519PrivateKey.generate().sign(authorization)
                with self.assertRaisesRegex(RecoveryAuthorizationError, "RECOVERY_SIGNATURE_INVALID"):
                    plan_recovery(
                        store,
                        authorization,
                        wrong_signature,
                        self.public,
                        expected_service=SERVICE,
                        expected_release_sha256=RELEASE,
                        now=NOW,
                    )

    def test_replay_budget_and_power_loss_after_reservation_remain_consumed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-recovery-crash-") as raw:
            root = Path(raw)
            store = self.store(root)
            with self.assertRaisesRegex(RuntimeError, "simulated power loss"):
                self.call_reserve(
                    store,
                    self.request(),
                    after_commit=lambda: (_ for _ in ()).throw(RuntimeError("simulated power loss")),
                )
            store.close()
            with StoreV2(root / "state", root / "anchor", SERVICE, STORE_KEY, path_validator=ALLOW) as reopened:
                durable = reopened.load()
                self.assertEqual(0, durable["recovery_budget_remaining"])
                self.assertIn("nonce-0000000001", durable["consumed_nonces"])
                with self.assertRaisesRegex(RecoveryAuthorizationError, "RECOVERY_REPLAYED"):
                    self.call_plan(reopened, self.request())
                fresh_nonce = self.request(nonce="nonce-0000000002", state_revision=durable["revision"], state_generation=durable["generation"])
                with self.assertRaisesRegex(RecoveryAuthorizationError, "RECOVERY_BUDGET_EXHAUSTED"):
                    self.call_plan(reopened, fresh_nonce)

    def test_reboot_clean_stop_and_stable_do_not_refill_budget_or_history(self) -> None:
        record = fresh_record(SERVICE, boot_id="boot-a", monotonic_ns=100, wall_time_ns=100)
        record.update(
            lifecycle="RUNNING",
            health="STABLE",
            attempts_since_stable=4,
            cumulative_failures=9,
            recovery_budget_remaining=0,
            consumed_nonces=["nonce-0000000001"],
        )
        stable = verified_stable(record)
        self.assertEqual(0, stable["attempts_since_stable"])
        self.assertEqual(9, stable["cumulative_failures"])
        self.assertEqual(0, stable["recovery_budget_remaining"])
        self.assertEqual(record["consumed_nonces"], stable["consumed_nonces"])


if __name__ == "__main__":
    unittest.main()

