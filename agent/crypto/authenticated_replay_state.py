from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Optional


class AuthenticatedReplayState:
    """
    CyberDefender P11.4

    Authenticated Persistent Replay State.

    P11.3:
        state + SHA-256

    P11.4:
        state + HMAC-SHA256(secret)

    Security property:

        Attacker changes state
              |
              v
        HMAC verification
              |
          INVALID
              |
              v
          DEGRADED
              |
              v
        REJECT NEW EVENTS

    Prototype key storage only.

    Production:
        TPM / HSM / OS protected key storage.
    """

    VERSION = "1.0"
    STATE_VERSION = "1"

    STATUS_READY = "READY"
    STATUS_DEGRADED = "DEGRADED"

    def __init__(
        self,
        state_dir: str | Path,
        key: bytes,
        max_entries: int = 100_000,
    ):
        if not isinstance(
            key,
            bytes,
        ):
            raise TypeError(
                "key bytes bo'lishi kerak"
            )

        if len(key) < 32:
            raise ValueError(
                "HMAC key kamida 32 byte bo'lishi kerak"
            )

        if not isinstance(
            max_entries,
            int,
        ):
            raise TypeError(
                "max_entries integer bo'lishi kerak"
            )

        if max_entries <= 0:
            raise ValueError(
                "max_entries 0 dan katta bo'lishi kerak"
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
            / "authenticated_replay_state.json"
        )

        self.mac_path = (
            self.state_dir
            / "authenticated_replay_state.mac"
        )

        self.max_entries = max_entries

        self._key = bytes(key)

        self._seen: OrderedDict[
            str,
            None,
        ] = OrderedDict()

        self._lock = Lock()

        self._status = (
            self.STATUS_READY
        )

        self._accepted = 0
        self._duplicates = 0
        self._invalid_ids = 0
        self._evictions = 0
        self._recovered = 0
        self._authentication_rejected = 0
        self._persist_failures = 0

        self._load_state()

    # =========================================================
    # Canonical state
    # =========================================================

    def _canonical_state_bytes(
        self,
    ) -> bytes:
        payload = {
            "state_version":
                self.STATE_VERSION,
            "event_ids":
                list(
                    self._seen.keys()
                ),
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

    # =========================================================
    # HMAC
    # =========================================================

    def _calculate_mac(
        self,
        payload: bytes,
    ) -> str:
        return hmac.new(
            self._key,
            payload,
            hashlib.sha256,
        ).hexdigest()

    # =========================================================
    # Persistent state
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

            # -------------------------------------------------
            # State
            # -------------------------------------------------

            state_fd, state_tmp = (
                tempfile.mkstemp(
                    prefix=".auth_replay_state_",
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

            # -------------------------------------------------
            # MAC
            # -------------------------------------------------

            mac_fd, mac_tmp = (
                tempfile.mkstemp(
                    prefix=".auth_replay_mac_",
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
    # Recovery
    # =========================================================

    def _enter_degraded(
        self,
    ) -> None:
        self._status = (
            self.STATUS_DEGRADED
        )

        self._authentication_rejected += 1

        self._seen.clear()

    def _load_state(self) -> None:
        state_exists = (
            self.state_path.exists()
        )

        mac_exists = (
            self.mac_path.exists()
        )

        # Fresh installation.
        if (
            not state_exists
            and not mac_exists
        ):
            self._status = (
                self.STATUS_READY
            )

            return

        # Partial state is unsafe.
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

            event_ids = data.get(
                "event_ids"
            )

            if not isinstance(
                event_ids,
                list,
            ):
                self._enter_degraded()
                return

            loaded = OrderedDict()

            for event_id in event_ids:
                if not isinstance(
                    event_id,
                    str,
                ):
                    self._enter_degraded()
                    return

                event_id = event_id.strip()

                if not event_id:
                    self._enter_degraded()
                    return

                if event_id in loaded:
                    self._enter_degraded()
                    return

                loaded[event_id] = None

            if (
                len(loaded)
                > self.max_entries
            ):
                self._enter_degraded()
                return

            self._seen = loaded

            self._recovered = len(
                loaded
            )

            self._status = (
                self.STATUS_READY
            )

        except Exception:
            self._enter_degraded()

    # =========================================================
    # Security decision
    # =========================================================

    def check_and_remember(
        self,
        event_id: Optional[str],
    ) -> bool:
        if not isinstance(
            event_id,
            str,
        ):
            self._invalid_ids += 1
            return False

        event_id = event_id.strip()

        if not event_id:
            self._invalid_ids += 1
            return False

        with self._lock:

            # -------------------------------------------------
            # Fail-safe boundary
            # -------------------------------------------------

            if (
                self._status
                != self.STATUS_READY
            ):
                return False

            # -------------------------------------------------
            # Replay
            # -------------------------------------------------

            if event_id in self._seen:
                self._duplicates += 1
                return False

            # -------------------------------------------------
            # Tentative insertion
            # -------------------------------------------------

            self._seen[event_id] = None

            if (
                len(self._seen)
                > self.max_entries
            ):
                self._seen.popitem(
                    last=False
                )

                self._evictions += 1

            # -------------------------------------------------
            # Authentication state persistence
            # -------------------------------------------------

            if not self._persist_state():

                self._seen.pop(
                    event_id,
                    None,
                )

                return False

            self._accepted += 1

            return True

    # =========================================================
    # Inspection
    # =========================================================

    def contains(
        self,
        event_id: Optional[str],
    ) -> bool:
        if not isinstance(
            event_id,
            str,
        ):
            return False

        event_id = event_id.strip()

        if not event_id:
            return False

        with self._lock:
            return event_id in self._seen

    def size(self) -> int:
        with self._lock:
            return len(
                self._seen
            )

    def is_ready(self) -> bool:
        return (
            self._status
            == self.STATUS_READY
        )

    def is_degraded(self) -> bool:
        return (
            self._status
            == self.STATUS_DEGRADED
        )

    def get_status(self) -> str:
        return self._status

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "component":
                    "AuthenticatedReplayState",
                "version":
                    self.VERSION,
                "state_version":
                    self.STATE_VERSION,
                "status":
                    self._status,
                "tracked":
                    len(self._seen),
                "max_entries":
                    self.max_entries,
                "accepted":
                    self._accepted,
                "duplicates":
                    self._duplicates,
                "invalid_ids":
                    self._invalid_ids,
                "evictions":
                    self._evictions,
                "recovered":
                    self._recovered,
                "authentication_rejected":
                    self._authentication_rejected,
                "persist_failures":
                    self._persist_failures,
            }

    def health_check(self) -> dict:
        return {
            "component":
                "AuthenticatedReplayState",
            "status":
                (
                    "HEALTHY"
                    if self.is_ready()
                    else "DEGRADED"
                ),
            "version":
                self.VERSION,
            "state_version":
                self.STATE_VERSION,
            "authentication":
                "HMAC-SHA256",
            "accepting_new_events":
                self.is_ready(),
        }


def generate_key() -> bytes:
    """
    Development/test key generation.

    Production:
        key must come from TPM/HSM/OS protected storage.
    """

    return secrets.token_bytes(32)
