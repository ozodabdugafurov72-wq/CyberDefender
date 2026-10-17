from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.service_crash_guard import fresh_record as fresh_v1
from agent import service_crash_store as v1
from agent.crashguard_v2.migration import MigrationError, STATE_MAP, map_record, migrate
from agent.crashguard_v2.recovery import RecoveryPublicKey, canonical_request
from agent.crashguard_v2.store import StoreV2, StoreV2Error, validate_record


SERVICE = "CyberDefenderAgent"
V1_KEY = b"V" * 32
V2_KEY = b"2" * 32
RELEASE = "c" * 64
NOW = 2_000_000_000
ALLOW = lambda _path: None


def envelope(payload: dict) -> bytes:
    return v1.canonical({"payload": payload, "mac": hmac.new(V1_KEY, v1.canonical(payload), hashlib.sha256).hexdigest()})


def v1_fixture(root: Path, state: str) -> dict:
    root.mkdir()
    record = fresh_v1(SERVICE)
    record.update(
        revision=232,
        generation=14,
        state=state,
        boot="b00b-1e9ac",
        cumulative_failures=5,
        attempts_since_stable=2,
        probes_used=1,
        repair_count=17,
        clean_stop=False,
        active_attempt=state in {"STARTING", "PROBE"},
        recent_failures=[{"generation": 13, "boot": "b00b-1e9ac", "code": "UNHANDLED_EXCEPTION", "tick": 1.0}],
    )
    (root / f"{SERVICE}.{record['revision'] % 2}.json").write_bytes(envelope(record))
    anchor = {
        "schema": "cd.crash-anchor.v1",
        "service": SERVICE,
        "revision": record["revision"],
        "digest": hashlib.sha256(v1.canonical(record)).hexdigest(),
    }
    (root / f"{SERVICE}.anchor").write_bytes(envelope(anchor))
    return record


class CrashGuardV2MigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public = RecoveryPublicKey("migration-operator-v1", public)

    def authorization(self, source: dict) -> tuple[bytes, bytes]:
        request = {
            "action": "MIGRATE_V1_TO_V2",
            "service": SERVICE,
            "release_sha256": RELEASE,
            "state_generation": source["generation"],
            "state_revision": source["revision"],
            "nonce": "migration-nonce-0001",
            "issued_at": NOW - 30,
            "expires_at": NOW + 300,
        }
        raw = canonical_request(request)
        return raw, self.private.sign(raw)

    def roots(self, root: Path):
        state, anchor = root / "v2-state", root / "v2-anchor"
        state.mkdir()
        anchor.mkdir()
        return state, anchor

    def test_mapping_table_preserves_or_archives_every_v1_state_and_counter(self) -> None:
        for source_state, expected in STATE_MAP.items():
            with self.subTest(state=source_state), tempfile.TemporaryDirectory(prefix="cg2-mapping-") as raw:
                root = Path(raw)
                source = v1_fixture(root / "v1", source_state)
                state, anchor = self.roots(root)
                authorization, signature = self.authorization(source)
                with StoreV2(state, anchor, SERVICE, V2_KEY, path_validator=ALLOW) as store:
                    migrated = migrate(
                        root / "v1", V1_KEY, store, root / "staged.json", authorization, signature, self.public,
                        service=SERVICE, release_sha256=RELEASE, now=NOW, wall_time_ns=3_000_000_000_000,
                    )
                self.assertEqual(expected, migrated["lifecycle"])
                self.assertEqual(source["revision"], migrated["revision"])
                self.assertEqual(source["generation"], migrated["generation"])
                self.assertEqual(source["cumulative_failures"], migrated["cumulative_failures"])
                self.assertEqual(source["attempts_since_stable"], migrated["attempts_since_stable"])
                self.assertEqual(0, migrated["recovery_budget_remaining"])
                self.assertEqual(source["probes_used"], migrated["migration"]["probes_used"])
                self.assertEqual(source["repair_count"], migrated["migration"]["repair_count"])

    def test_every_interruption_point_yields_no_clean_state_or_budget_gain(self) -> None:
        for stop_at in ("SOURCE_AUTHENTICATED", "RECORD_MAPPED", "STAGED_VERIFIED", "COMMITTED"):
            with self.subTest(step=stop_at), tempfile.TemporaryDirectory(prefix="cg2-interrupt-") as raw:
                root = Path(raw)
                source = v1_fixture(root / "v1", "LATCHED")
                source_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (root / "v1").iterdir()}
                state, anchor = self.roots(root)
                authorization, signature = self.authorization(source)
                store = StoreV2(state, anchor, SERVICE, V2_KEY, path_validator=ALLOW)

                def checkpoint(name):
                    if name == stop_at:
                        raise RuntimeError("simulated interruption")

                with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                    migrate(
                        root / "v1", V1_KEY, store, root / "staged.json", authorization, signature, self.public,
                        service=SERVICE, release_sha256=RELEASE, now=NOW, wall_time_ns=3_000_000_000_000,
                        checkpoint=checkpoint,
                    )
                if store.anchor_path.exists():
                    committed = store.load()
                    self.assertEqual("LATCHED", committed["lifecycle"])
                    self.assertEqual(0, committed["recovery_budget_remaining"])
                else:
                    self.assertFalse(any(state.iterdir()))
                self.assertEqual(
                    source_hashes,
                    {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (root / "v1").iterdir()},
                )
                store.close()

    def test_bad_signature_and_existing_v2_refuse_migration_or_downgrade(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-downgrade-") as raw:
            root = Path(raw)
            source = v1_fixture(root / "v1", "LATCHED")
            state, anchor = self.roots(root)
            authorization, signature = self.authorization(source)
            with StoreV2(state, anchor, SERVICE, V2_KEY, path_validator=ALLOW) as store:
                with self.assertRaisesRegex(MigrationError, "MIGRATION_AUTH_REQUIRED"):
                    migrate(
                        root / "v1", V1_KEY, store, root / "bad-stage.json", authorization, b"0" * 64, self.public,
                        service=SERVICE, release_sha256=RELEASE, now=NOW, wall_time_ns=3_000_000_000_000,
                    )
                migrate(
                    root / "v1", V1_KEY, store, root / "stage.json", authorization, signature, self.public,
                    service=SERVICE, release_sha256=RELEASE, now=NOW, wall_time_ns=3_000_000_000_000,
                )
                with self.assertRaisesRegex(MigrationError, "MIGRATION_DOWNGRADE_REFUSED"):
                    migrate(
                        root / "v1", V1_KEY, store, root / "second-stage.json", authorization, signature, self.public,
                        service=SERVICE, release_sha256=RELEASE, now=NOW, wall_time_ns=3_000_000_000_000,
                    )

    def test_migration_archive_fields_remain_strictly_validated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cg2-migration-schema-") as raw:
            source = v1_fixture(Path(raw) / "v1", "LATCHED")
            record = map_record(source, SERVICE, wall_time_ns=3_000_000_000_000)
            for field, invalid in (("probes_used", 2), ("source_revision", record["revision"] + 1)):
                with self.subTest(field=field):
                    candidate = dict(record)
                    candidate["migration"] = dict(record["migration"])
                    candidate["migration"][field] = invalid
                    with self.assertRaisesRegex(StoreV2Error, "SCHEMA_INVALID"):
                        validate_record(candidate, SERVICE)


if __name__ == "__main__":
    unittest.main()

