from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import shutil
from pathlib import Path


class KeyRotationRecovery:
    """
    CyberDefender P11.6

    Key Rotation & Recovery Hardening.

    Bu komponent KeyManager state'ini mustaqil ravishda
    validate qilish va rotation transaction holatini
    aniqlash uchun ishlatiladi.

    Maqsad:

        1. At most one ACTIVE key
        2. ACTIVE key mavjud bo'lsa state consistent
        3. RETIRED/REVOKED key ACTIVE bo'la olmaydi
        4. Unknown status -> DEGRADED
        5. Duplicate key IDs -> DEGRADED
        6. Invalid state -> fail-safe
    """

    VERSION = "1.0"

    READY = "READY"
    DEGRADED = "DEGRADED"

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"

    def __init__(
        self,
        state_dir: str | Path,
        storage_key: bytes,
    ):
        if not isinstance(
            storage_key,
            bytes,
        ):
            raise TypeError(
                "storage_key bytes bo'lishi kerak"
            )

        if len(storage_key) < 32:
            raise ValueError(
                "storage_key kamida 32 byte bo'lishi kerak"
            )

        self.state_dir = Path(
            state_dir
        )

        self.state_path = (
            self.state_dir
            / "key_state.json"
        )

        self.mac_path = (
            self.state_dir
            / "key_state.mac"
        )

        self.storage_key = bytes(
            storage_key
        )

        self.status = self.READY

        self.validation_failures = 0
        self.recovery_checks = 0

    # =========================================================
    # Canonical state
    # =========================================================

    @staticmethod
    def canonicalize(
        data: dict,
    ) -> bytes:
        return (
            json.dumps(
                data,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    # =========================================================
    # MAC
    # =========================================================

    def calculate_mac(
        self,
        payload: bytes,
    ) -> str:
        return hmac.new(
            self.storage_key,
            payload,
            hashlib.sha256,
        ).hexdigest()

    # =========================================================
    # Load authenticated state
    # =========================================================

    def load_authenticated_state(
        self,
    ) -> dict | None:

        state_exists = (
            self.state_path.exists()
        )

        mac_exists = (
            self.mac_path.exists()
        )

        # Empty/new installation.
        if (
            not state_exists
            and not mac_exists
        ):
            return None

        # Partial state is unsafe.
        if (
            state_exists
            != mac_exists
        ):
            self.status = (
                self.DEGRADED
            )

            self.validation_failures += 1

            return None

        try:
            raw = (
                self.state_path.read_bytes()
            )

            stored_mac = (
                self.mac_path
                .read_text(
                    encoding="ascii"
                )
                .strip()
            )

            expected_mac = (
                self.calculate_mac(
                    raw
                )
            )

            if not hmac.compare_digest(
                stored_mac,
                expected_mac,
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return None

            data = json.loads(
                raw.decode("utf-8")
            )

            if not isinstance(
                data,
                dict,
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return None

            return data

        except Exception:
            self.status = (
                self.DEGRADED
            )

            self.validation_failures += 1

            return None

    # =========================================================
    # Structural validation
    # =========================================================

    def validate_state(
        self,
        data: dict | None,
    ) -> bool:

        self.recovery_checks += 1

        if not isinstance(
            data,
            dict,
        ):
            self.status = (
                self.DEGRADED
            )

            self.validation_failures += 1

            return False

        if (
            data.get(
                "state_version"
            )
            != "1"
        ):
            self.status = (
                self.DEGRADED
            )

            self.validation_failures += 1

            return False

        keys = data.get(
            "keys"
        )

        active_key_id = data.get(
            "active_key_id"
        )

        if not isinstance(
            keys,
            dict,
        ):
            self.status = (
                self.DEGRADED
            )

            self.validation_failures += 1

            return False

        active_keys = []

        for key_id, metadata in (
            keys.items()
        ):

            if not isinstance(
                key_id,
                str,
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            if not isinstance(
                metadata,
                dict,
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            status = metadata.get(
                "status"
            )

            algorithm = metadata.get(
                "algorithm"
            )

            material = metadata.get(
                "material"
            )

            if status not in {
                self.ACTIVE,
                self.RETIRED,
                self.REVOKED,
            }:
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            if (
                algorithm
                != "HMAC-SHA256"
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            if not isinstance(
                material,
                str,
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            if status == self.ACTIVE:
                active_keys.append(
                    key_id
                )

        # -----------------------------------------------------
        # Critical invariant:
        #
        # ACTIVE keys <= 1
        # -----------------------------------------------------

        if len(
            active_keys
        ) > 1:

            self.status = (
                self.DEGRADED
            )

            self.validation_failures += 1

            return False

        # -----------------------------------------------------
        # active_key_id consistency
        # -----------------------------------------------------

        if active_key_id is None:

            if active_keys:
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

        else:

            if not isinstance(
                active_key_id,
                str,
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            if (
                active_key_id
                not in keys
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            if (
                keys[
                    active_key_id
                ].get("status")
                != self.ACTIVE
            ):
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

            if active_keys != [
                active_key_id
            ]:
                self.status = (
                    self.DEGRADED
                )

                self.validation_failures += 1

                return False

        self.status = (
            self.READY
        )

        return True

    # =========================================================
    # Recovery validation
    # =========================================================

    def recover_and_validate(
        self,
    ) -> bool:

        data = (
            self.load_authenticated_state()
        )

        return self.validate_state(
            data
        )

    # =========================================================
    # Health
    # =========================================================

    def is_ready(self) -> bool:
        return (
            self.status
            == self.READY
        )

    def health_check(self) -> dict:
        return {
            "component":
                "KeyRotationRecovery",
            "status":
                (
                    "HEALTHY"
                    if self.is_ready()
                    else "DEGRADED"
                ),
            "version":
                self.VERSION,
            "accepting_new_events":
                self.is_ready(),
        }

    def get_stats(self) -> dict:
        return {
            "component":
                "KeyRotationRecovery",
            "version":
                self.VERSION,
            "status":
                self.status,
            "validation_failures":
                self.validation_failures,
            "recovery_checks":
                self.recovery_checks,
        }
