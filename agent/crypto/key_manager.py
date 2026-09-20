from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import uuid
from pathlib import Path
from threading import Lock
from typing import Optional


class KeyManager:
    """
    CyberDefender P11.5 - Key Management.

    Prototype key lifecycle manager.

    Lifecycle:

        ACTIVE
          |
          | rotate
          v
        RETIRED

        ACTIVE
          |
          | revoke
          v
        REVOKED

        RETIRED
          |
          | revoke
          v
        REVOKED

    Security rules:

    - Key material is never returned by normal metadata APIs.
    - REVOKED keys cannot authenticate data.
    - RETIRED keys cannot be used for new authentication.
    - Only ACTIVE key can be used for new operations.
    - Key state is persisted atomically.
    - Key state has authenticated integrity.
    - Prototype storage only.

    Production:
        TPM / HSM / OS protected key storage.
    """

    VERSION = "1.1"
    STATE_VERSION = "1"

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"

    STATUS_READY = "READY"
    STATUS_UNPROVISIONED = "UNPROVISIONED"
    STATUS_DEGRADED = "DEGRADED"

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

        self.state_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.state_path = (
            self.state_dir
            / "key_state.json"
        )

        self.mac_path = (
            self.state_dir
            / "key_state.mac"
        )

        self._storage_key = bytes(
            storage_key
        )

        self._lock = Lock()

        # A valid KeyManager is not automatically operational.  Fresh
        # state has no ACTIVE key yet, therefore it starts explicitly as
        # UNPROVISIONED.  READY means an ACTIVE key is present and usable.
        self._status = (
            self.STATUS_UNPROVISIONED
        )

        self._keys: dict[
            str,
            dict,
        ] = {}

        self._active_key_id: Optional[
            str
        ] = None

        self._generated = 0
        self._rotations = 0
        self._revocations = 0
        self._authentication_rejected = 0
        self._persist_failures = 0

        self._load_state()

    # =========================================================
    # Canonical state
    # =========================================================

    def _canonical_state_bytes(
        self,
    ) -> bytes:
        """
        Persistent metadata only.

        Key material is stored separately inside the
        authenticated state representation below.

        Prototype only.
        Production should use OS/TPM/HSM protected key slots.
        """

        payload = {
            "state_version":
                self.STATE_VERSION,
            "active_key_id":
                self._active_key_id,
            "keys":
                self._keys,
        }

        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    def _calculate_mac(
        self,
        payload: bytes,
    ) -> str:
        return hmac.new(
            self._storage_key,
            payload,
            hashlib.sha256,
        ).hexdigest()

    # =========================================================
    # Persistence
    # =========================================================

    def _persist_state(self) -> bool:
        payload = (
            self._canonical_state_bytes()
        )

        mac = self._calculate_mac(
            payload
        )

        state_tmp = None
        mac_tmp = None

        try:
            self.state_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            state_fd, state_tmp = (
                tempfile.mkstemp(
                    prefix=".key_state_",
                    suffix=".tmp",
                    dir=str(
                        self.state_dir
                    ),
                )
            )

            with os.fdopen(
                state_fd,
                "wb",
            ) as file:
                file.write(
                    payload
                )

                file.flush()

                os.fsync(
                    file.fileno()
                )

            os.replace(
                state_tmp,
                self.state_path,
            )

            state_tmp = None

            mac_fd, mac_tmp = (
                tempfile.mkstemp(
                    prefix=".key_mac_",
                    suffix=".tmp",
                    dir=str(
                        self.state_dir
                    ),
                )
            )

            with os.fdopen(
                mac_fd,
                "w",
                encoding="ascii",
            ) as file:
                file.write(
                    mac
                )

                file.write(
                    "\n"
                )

                file.flush()

                os.fsync(
                    file.fileno()
                )

            os.replace(
                mac_tmp,
                self.mac_path,
            )

            mac_tmp = None

            return True

        except Exception:
            self._persist_failures += 1
            return False

        finally:
            if state_tmp is not None:
                try:
                    os.remove(
                        state_tmp
                    )
                except OSError:
                    pass

            if mac_tmp is not None:
                try:
                    os.remove(
                        mac_tmp
                    )
                except OSError:
                    pass

    # =========================================================
    # Degraded state
    # =========================================================

    def _enter_degraded(
        self,
    ) -> None:
        self._status = (
            self.STATUS_DEGRADED
        )

        self._keys.clear()
        self._active_key_id = None

        self._authentication_rejected += 1

    # =========================================================
    # Recovery
    # =========================================================

    def _load_state(self) -> None:
        state_exists = (
            self.state_path.exists()
        )

        mac_exists = (
            self.mac_path.exists()
        )

        if (
            not state_exists
            and not mac_exists
        ):
            self._status = (
                self.STATUS_UNPROVISIONED
            )
            return

        if (
            state_exists
            != mac_exists
        ):
            self._enter_degraded()
            return

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
                self._calculate_mac(
                    raw
                )
            )

            if not hmac.compare_digest(
                stored_mac,
                expected_mac,
            ):
                self._enter_degraded()
                return

            data = json.loads(
                raw.decode("utf-8")
            )

            if not isinstance(
                data,
                dict,
            ):
                self._enter_degraded()
                return

            if (
                data.get(
                    "state_version"
                )
                != self.STATE_VERSION
            ):
                self._enter_degraded()
                return

            active_key_id = data.get(
                "active_key_id"
            )

            keys = data.get(
                "keys"
            )

            if not isinstance(
                keys,
                dict,
            ):
                self._enter_degraded()
                return

            for key_id, metadata in keys.items():

                if not isinstance(
                    key_id,
                    str,
                ):
                    self._enter_degraded()
                    return

                if not isinstance(
                    metadata,
                    dict,
                ):
                    self._enter_degraded()
                    return

                status = metadata.get(
                    "status"
                )

                encoded_material = (
                    metadata.get(
                        "material"
                    )
                )

                if status not in {
                    self.ACTIVE,
                    self.RETIRED,
                    self.REVOKED,
                }:
                    self._enter_degraded()
                    return

                if not isinstance(
                    encoded_material,
                    str,
                ):
                    self._enter_degraded()
                    return

                try:
                    base64.b64decode(
                        encoded_material.encode(
                            "ascii"
                        ),
                        validate=True,
                    )
                except Exception:
                    self._enter_degraded()
                    return

            if (
                active_key_id is not None
                and active_key_id not in keys
            ):
                self._enter_degraded()
                return

            active_ids = [
                key_id
                for key_id, metadata
                in keys.items()
                if metadata.get("status")
                == self.ACTIVE
            ]

            # The persisted state must have one coherent ACTIVE-key
            # identity, or no ACTIVE key at all.  An orphan ACTIVE entry
            # is ambiguous and therefore fails closed.
            if active_key_id is None:
                if active_ids:
                    self._enter_degraded()
                    return
            else:
                if (
                    len(active_ids) != 1
                    or active_ids[0]
                    != active_key_id
                ):
                    self._enter_degraded()
                    return

            self._keys = keys
            self._active_key_id = (
                active_key_id
            )

            self._status = (
                self.STATUS_READY
                if self._active_key_id
                is not None
                else self.STATUS_UNPROVISIONED
            )

        except Exception:
            self._enter_degraded()

    # =========================================================
    # Key generation
    # =========================================================

    def generate_key(
        self,
    ) -> Optional[str]:
        """
        Create a new ACTIVE key.

        If an active key already exists,
        this operation is rejected.

        Rotation should be used instead.
        """

        with self._lock:

            if self._status not in {
                self.STATUS_READY,
                self.STATUS_UNPROVISIONED,
            }:
                return None

            if (
                self._active_key_id
                is not None
            ):
                return None

            key_id = (
                "key-"
                + uuid.uuid4().hex
            )

            material = (
                secrets.token_bytes(32)
            )

            self._keys[
                key_id
            ] = {
                "status":
                    self.ACTIVE,
                "algorithm":
                    "HMAC-SHA256",
                "material":
                    base64.b64encode(
                        material
                    ).decode(
                        "ascii"
                    ),
            }

            self._active_key_id = (
                key_id
            )

            previous_status = (
                self._status
            )

            self._status = (
                self.STATUS_READY
            )

            if not self._persist_state():
                del self._keys[
                    key_id
                ]

                self._active_key_id = None

                self._status = (
                    previous_status
                )

                return None

            self._generated += 1

            return key_id

    # =========================================================
    # Active key
    # =========================================================

    def active_key_id(
        self,
    ) -> Optional[str]:
        with self._lock:
            if (
                self._status
                != self.STATUS_READY
            ):
                return None

            return self._active_key_id

    def _get_active_material(
        self,
    ) -> Optional[bytes]:
        if (
            self._status
            != self.STATUS_READY
        ):
            return None

        if (
            self._active_key_id
            is None
        ):
            return None

        metadata = self._keys.get(
            self._active_key_id
        )

        if metadata is None:
            return None

        if (
            metadata.get("status")
            != self.ACTIVE
        ):
            return None

        try:
            return base64.b64decode(
                metadata[
                    "material"
                ].encode(
                    "ascii"
                ),
                validate=True,
            )
        except Exception:
            return None

    # =========================================================
    # Authentication
    # =========================================================

    def sign(
        self,
        payload: bytes,
    ) -> Optional[str]:
        if not isinstance(
            payload,
            bytes,
        ):
            return None

        with self._lock:

            material = (
                self._get_active_material()
            )

            if material is None:
                self._authentication_rejected += 1
                return None

            return hmac.new(
                material,
                payload,
                hashlib.sha256,
            ).hexdigest()


    def sign_with_active_key_id(
        self,
        payload: bytes,
    ) -> Optional[tuple[str, str]]:
        """
        Atomically return (ACTIVE key_id, HMAC).

        Security purpose:
        prevents a key-rotation race between reading active_key_id
        and signing the payload.

        This method does not change trust/authorization semantics.
        """
        if not isinstance(payload, bytes):
            return None

        with self._lock:
            if (
                self._status != self.STATUS_READY
                or self._active_key_id is None
            ):
                self._authentication_rejected += 1
                return None

            key_id = self._active_key_id
            metadata = self._keys.get(key_id)

            if (
                metadata is None
                or metadata.get("status") != self.ACTIVE
            ):
                self._authentication_rejected += 1
                return None

            try:
                material = base64.b64decode(
                    metadata["material"].encode("ascii"),
                    validate=True,
                )
            except Exception:
                self._authentication_rejected += 1
                return None

            signature = hmac.new(
                material,
                payload,
                hashlib.sha256,
            ).hexdigest()

            return key_id, signature

    def verify_for_recovery(
        self,
        payload: bytes,
        mac: str,
        key_id: str,
    ) -> bool:
        """
        Verify durable recovery proof.

        ACTIVE and RETIRED keys may verify historical durable proof.
        REVOKED keys never verify.

        IMPORTANT:
        this API is recovery-only. It does NOT authorize new admission,
        privileged actions, policy decisions, or response execution.
        """
        if not isinstance(payload, bytes):
            return False
        if not isinstance(mac, str):
            return False
        if not isinstance(key_id, str):
            return False

        with self._lock:
            if self._status != self.STATUS_READY:
                self._authentication_rejected += 1
                return False

            metadata = self._keys.get(key_id)

            if metadata is None:
                self._authentication_rejected += 1
                return False

            status = metadata.get("status")

            if status not in {self.ACTIVE, self.RETIRED}:
                self._authentication_rejected += 1
                return False

            try:
                material = base64.b64decode(
                    metadata["material"].encode("ascii"),
                    validate=True,
                )
            except Exception:
                self._authentication_rejected += 1
                return False

            expected = hmac.new(
                material,
                payload,
                hashlib.sha256,
            ).hexdigest()

            return hmac.compare_digest(expected, mac)

    def verify(
        self,
        payload: bytes,
        mac: str,
        key_id: str,
    ) -> bool:
        if not isinstance(
            payload,
            bytes,
        ):
            return False

        if not isinstance(
            mac,
            str,
        ):
            return False

        if not isinstance(
            key_id,
            str,
        ):
            return False

        with self._lock:

            if (
                self._status
                != self.STATUS_READY
            ):
                self._authentication_rejected += 1
                return False

            metadata = self._keys.get(
                key_id
            )

            if metadata is None:
                self._authentication_rejected += 1
                return False

            # New authentication must use ACTIVE key.
            if (
                metadata.get("status")
                != self.ACTIVE
            ):
                self._authentication_rejected += 1
                return False

            try:
                material = (
                    base64.b64decode(
                        metadata[
                            "material"
                        ].encode(
                            "ascii"
                        ),
                        validate=True,
                    )
                )
            except Exception:
                self._authentication_rejected += 1
                return False

            expected = hmac.new(
                material,
                payload,
                hashlib.sha256,
            ).hexdigest()

            return hmac.compare_digest(
                expected,
                mac,
            )

    # =========================================================
    # Rotation
    # =========================================================

    def rotate(
        self,
    ) -> Optional[str]:
        """
        Retire current ACTIVE key and create
        a new ACTIVE key.

        Operation is atomic from the manager's
        state perspective.
        """

        with self._lock:

            if (
                self._status
                != self.STATUS_READY
            ):
                return None

            old_key_id = (
                self._active_key_id
            )

            if old_key_id is None:
                return None

            new_key_id = (
                "key-"
                + uuid.uuid4().hex
            )

            new_material = (
                secrets.token_bytes(32)
            )

            old_status = (
                self._keys[
                    old_key_id
                ]["status"]
            )

            self._keys[
                old_key_id
            ]["status"] = (
                self.RETIRED
            )

            self._keys[
                new_key_id
            ] = {
                "status":
                    self.ACTIVE,
                "algorithm":
                    "HMAC-SHA256",
                "material":
                    base64.b64encode(
                        new_material
                    ).decode(
                        "ascii"
                    ),
            }

            self._active_key_id = (
                new_key_id
            )

            if not self._persist_state():

                self._keys[
                    old_key_id
                ]["status"] = (
                    old_status
                )

                del self._keys[
                    new_key_id
                ]

                self._active_key_id = (
                    old_key_id
                )

                return None

            self._rotations += 1

            return new_key_id

    # =========================================================
    # Revocation
    # =========================================================

    def revoke(
        self,
        key_id: str,
    ) -> bool:
        if not isinstance(
            key_id,
            str,
        ):
            return False

        with self._lock:

            if (
                self._status
                != self.STATUS_READY
            ):
                return False

            metadata = self._keys.get(
                key_id
            )

            if metadata is None:
                return False

            if (
                metadata.get(
                    "status"
                )
                == self.REVOKED
            ):
                return False

            old_status = metadata[
                "status"
            ]

            metadata[
                "status"
            ] = self.REVOKED

            if (
                self._active_key_id
                == key_id
            ):
                self._active_key_id = None

                self._status = (
                    self.STATUS_UNPROVISIONED
                )

            if not self._persist_state():

                metadata[
                    "status"
                ] = old_status

                if old_status == self.ACTIVE:
                    self._active_key_id = (
                        key_id
                    )

                    self._status = (
                        self.STATUS_READY
                    )

                return False

            self._revocations += 1

            return True

    # =========================================================
    # Metadata
    # =========================================================

    def get_key_metadata(
        self,
        key_id: str,
    ) -> Optional[dict]:
        with self._lock:

            metadata = self._keys.get(
                key_id
            )

            if metadata is None:
                return None

            return {
                "key_id":
                    key_id,
                "status":
                    metadata["status"],
                "algorithm":
                    metadata["algorithm"],
            }

    def list_key_metadata(
        self,
    ) -> list[dict]:
        with self._lock:

            return [
                {
                    "key_id":
                        key_id,
                    "status":
                        metadata[
                            "status"
                        ],
                    "algorithm":
                        metadata[
                            "algorithm"
                        ],
                }
                for key_id, metadata
                in self._keys.items()
            ]

    # =========================================================
    # State
    # =========================================================

    def is_ready(self) -> bool:
        return (
            self._status
            == self.STATUS_READY
            and self._active_key_id
            is not None
        )

    def is_unprovisioned(self) -> bool:
        return (
            self._status
            == self.STATUS_UNPROVISIONED
            and self._active_key_id
            is None
        )

    def is_fresh_unprovisioned(self) -> bool:
        """
        True only for a brand-new installation that has never persisted
        key state.  This distinction lets runtime perform one controlled
        initial bootstrap without silently replacing a revoked/lost key.
        """
        return (
            self.is_unprovisioned()
            and not self._keys
            and not self.state_path.exists()
            and not self.mac_path.exists()
        )

    def is_degraded(self) -> bool:
        return (
            self._status
            == self.STATUS_DEGRADED
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "component":
                    "KeyManager",
                "version":
                    self.VERSION,
                "status":
                    self._status,
                "active_key_id":
                    self._active_key_id,
                "key_count":
                    len(self._keys),
                "generated":
                    self._generated,
                "rotations":
                    self._rotations,
                "revocations":
                    self._revocations,
                "authentication_rejected":
                    self._authentication_rejected,
                "persist_failures":
                    self._persist_failures,
            }

    def health_check(self) -> dict:
        if self.is_ready():
            health_status = "HEALTHY"
        elif self.is_unprovisioned():
            health_status = "UNPROVISIONED"
        else:
            health_status = "DEGRADED"

        return {
            "component":
                "KeyManager",
            "status":
                health_status,
            "version":
                self.VERSION,
            "active_key":
                self._active_key_id
                is not None,
            "operational":
                self.is_ready(),
            "state_integrity":
                not self.is_degraded(),
            "algorithm":
                "HMAC-SHA256",
            "key_material_export":
                False,
        }


def generate_storage_key() -> bytes:
    """
    Development/test only.

    Production:
        TPM / HSM / OS protected storage.
    """

    return secrets.token_bytes(32)
