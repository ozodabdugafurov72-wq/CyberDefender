from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Optional


class PersistentReplayGuard:
    """
    CyberDefender P11.3 - Persistent Replay Protection v1.2.

    Security properties:

    1. Replay state persistent.
    2. State is verified during startup.
    3. Corrupted/tampered state => DEGRADED.
    4. DEGRADED state NEVER accepts new event IDs.
    5. State writes are atomic.
    6. Integrity digest is calculated over the EXACT bytes written.
    7. Restart preserves previously accepted event IDs.

    IMPORTANT:
    SHA-256 here protects against accidental corruption and
    detects unauthorized modification only when the attacker
    cannot also replace the integrity digest.

    Production hardening:
        HMAC / device-bound key / TPM / HSM.
    """

    VERSION = "1.2"
    STATE_VERSION = "1"

    STATUS_READY = "READY"
    STATUS_DEGRADED = "DEGRADED"

    def __init__(
        self,
        state_dir: str | Path,
        max_entries: int = 100_000,
    ):
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
            / "replay_state.json"
        )

        self.integrity_path = (
            self.state_dir
            / "replay_state.integrity"
        )

        self.max_entries = max_entries

        self._seen: OrderedDict[
            str,
            None,
        ] = OrderedDict()

        self._lock = Lock()

        self._status = self.STATUS_READY

        self._accepted = 0
        self._duplicates = 0
        self._invalid_ids = 0
        self._evictions = 0
        self._recovered = 0
        self._integrity_rejected = 0
        self._persist_failures = 0

        self._load_state()

    # =========================================================
    # Canonical state
    # =========================================================

    def _canonical_state_bytes(
        self,
    ) -> bytes:
        payload = {
            "state_version": self.STATE_VERSION,
            "event_ids": list(
                self._seen.keys()
            ),
        }

        # EXACT bytes that will be persisted.
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _digest(
        payload: bytes,
    ) -> str:
        return hashlib.sha256(
            payload
        ).hexdigest()

    # =========================================================
    # Persistent state
    # =========================================================

    def _persist_state(self) -> bool:
        payload = (
            self._canonical_state_bytes()
        )

        digest = self._digest(
            payload
        )

        state_tmp = None
        integrity_tmp = None

        try:
            self.state_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            # -------------------------------------------------
            # State file
            # -------------------------------------------------

            state_fd, state_tmp = (
                tempfile.mkstemp(
                    prefix=".replay_state_",
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
                file.write(payload)
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
            # Integrity file
            # -------------------------------------------------

            integrity_fd, integrity_tmp = (
                tempfile.mkstemp(
                    prefix=".replay_integrity_",
                    suffix=".tmp",
                    dir=str(
                        self.state_dir
                    ),
                )
            )

            with os.fdopen(
                integrity_fd,
                "w",
                encoding="ascii",
            ) as file:
                file.write(digest)
                file.write("\n")
                file.flush()
                os.fsync(
                    file.fileno()
                )

            os.replace(
                integrity_tmp,
                self.integrity_path,
            )

            integrity_tmp = None

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

            if integrity_tmp is not None:
                try:
                    os.remove(
                        integrity_tmp
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

        self._integrity_rejected += 1

        # Do not use potentially untrusted state.
        self._seen.clear()

    def _load_state(self) -> None:
        state_exists = (
            self.state_path.exists()
        )

        integrity_exists = (
            self.integrity_path.exists()
        )

        # Fresh installation.
        if (
            not state_exists
            and not integrity_exists
        ):
            self._status = (
                self.STATUS_READY
            )
            return

        # One file exists without the other.
        if (
            state_exists
            != integrity_exists
        ):
            self._enter_degraded()
            return

        try:
            # Read exact persisted bytes.
            raw = (
                self.state_path.read_bytes()
            )

            stored_digest = (
                self.integrity_path
                .read_text(
                    encoding="ascii"
                )
                .strip()
            )

            actual_digest = self._digest(
                raw
            )

            # -------------------------------------------------
            # Integrity verification
            # -------------------------------------------------

            if (
                stored_digest
                != actual_digest
            ):
                self._enter_degraded()
                return

            # -------------------------------------------------
            # JSON validation
            # -------------------------------------------------

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
                    # Duplicate IDs inside persistent state
                    # indicate malformed state.
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
    # Replay decision
    # =========================================================

    def check_and_remember(
        self,
        event_id: Optional[str],
    ) -> bool:
        """
        Returns:

            True:
                Event is new AND state was persisted.

            False:
                Replay, invalid ID, degraded state,
                or persistence failure.
        """

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
            # FAIL-SAFE BOUNDARY
            # -------------------------------------------------

            if (
                self._status
                != self.STATUS_READY
            ):
                return False

            # -------------------------------------------------
            # Replay detection
            # -------------------------------------------------

            if event_id in self._seen:
                self._duplicates += 1
                return False

            # -------------------------------------------------
            # Tentative state mutation
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
            # Persistence is part of acceptance.
            # -------------------------------------------------

            if not self._persist_state():
                # Roll back the newly inserted event.
                self._seen.pop(
                    event_id,
                    None,
                )

                # We cannot safely claim acceptance.
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

    def clear(self) -> bool:
        """
        Explicit administrative/test cleanup.

        A failed persistence operation restores
        the previous in-memory state.
        """

        with self._lock:
            previous = self._seen

            self._seen = OrderedDict()

            if self._persist_state():
                return True

            self._seen = previous

            return False

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "component":
                    "PersistentReplayGuard",
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
                "integrity_rejected":
                    self._integrity_rejected,
                "persist_failures":
                    self._persist_failures,
            }

    def health_check(self) -> dict:
        return {
            "component":
                "PersistentReplayGuard",
            "status":
                (
                    "HEALTHY"
                    if self._status
                    == self.STATUS_READY
                    else "DEGRADED"
                ),
            "version":
                self.VERSION,
            "state_version":
                self.STATE_VERSION,
            "accepting_new_events":
                self.is_ready(),
        }
