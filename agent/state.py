from __future__ import annotations

import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


class EventStateIntegrityError(RuntimeError):
    """
    Raised when persisted EventState cannot be trusted.

    Security principle:
    corrupted security state must NEVER silently become
    an empty valid state.
    """


class EventState:
    """
    CyberDefender Event State Manager.

    Event lifecycle:

        NEW
          ↓
        UPDATE
          ↓
        UPDATE
          ↓
        RECOVERED

    Security properties:

    - fail-closed state loading
    - schema validation
    - transactional update
    - transactional recovery
    - atomic persistence
    - fsync durability
    - defensive copies
    - corrupted state is never silently discarded
    - no system modification
    """

    VERSION = "2.2"

    REQUIRED_STATE_FIELDS = {
        "state",
        "lifecycle",
        "severity",
        "value",
        "first_seen",
        "last_seen",
        "occurrence_count",
    }

    VALID_LIFECYCLES = {
        "NEW",
        "UPDATE",
    }

    VALID_STATE_VALUES = {
        "ACTIVE",
    }

    def __init__(self, state_path=None):
        if state_path is None:
            state_path = (
                Path(__file__).resolve().parent.parent
                / "state"
                / "state.json"
            )

        self.state_path = Path(state_path)

        self.state_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.active_events: dict[str, dict] = {}

        # =====================================================
        # HEALTH CONTRACT TELEMETRY
        # =====================================================

        self._health_checks = 0
        self._health_failures = 0
        self._last_error = None
        self._last_error_component = None

        self._load()

    # =========================================================
    # LOAD
    # =========================================================

    def _load(self) -> None:
        """
        Load persisted state.

        Security rule:
        corrupted or structurally invalid state MUST NOT
        silently become {}.
        """

        if not self.state_path.exists():
            self.active_events = {}
            return

        try:
            with self.state_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

        except json.JSONDecodeError as exc:
            raise EventStateIntegrityError(
                "EventState persistence is corrupted: "
                "invalid JSON."
            ) from exc

        except OSError as exc:
            raise EventStateIntegrityError(
                f"EventState persistence cannot be read: {exc}"
            ) from exc

        self._validate_state_document(data)

        self.active_events = deepcopy(data)

    # =========================================================
    # VALIDATION
    # =========================================================

    @classmethod
    def _validate_state_document(
        cls,
        data,
    ) -> None:
        """
        Validate the complete persisted state structure.
        """

        if not isinstance(data, dict):
            raise EventStateIntegrityError(
                "EventState root must be a JSON object."
            )

        for event_type, state in data.items():

            if not isinstance(event_type, str):
                raise EventStateIntegrityError(
                    "EventState event type must be a string."
                )

            if not event_type.strip():
                raise EventStateIntegrityError(
                    "EventState contains an empty event type."
                )

            if not isinstance(state, dict):
                raise EventStateIntegrityError(
                    f"State for '{event_type}' must be an object."
                )

            missing = (
                cls.REQUIRED_STATE_FIELDS
                - set(state.keys())
            )

            if missing:
                raise EventStateIntegrityError(
                    f"State for '{event_type}' is missing fields: "
                    f"{sorted(missing)}"
                )

            if state["state"] not in cls.VALID_STATE_VALUES:
                raise EventStateIntegrityError(
                    f"Invalid state value for '{event_type}': "
                    f"{state['state']!r}"
                )

            if state["lifecycle"] not in cls.VALID_LIFECYCLES:
                raise EventStateIntegrityError(
                    f"Invalid lifecycle for '{event_type}': "
                    f"{state['lifecycle']!r}"
                )

            if not isinstance(
                state["occurrence_count"],
                int,
            ):
                raise EventStateIntegrityError(
                    f"Invalid occurrence_count for '{event_type}'."
                )

            if state["occurrence_count"] < 1:
                raise EventStateIntegrityError(
                    f"Invalid occurrence_count for '{event_type}'."
                )

            if not isinstance(
                state["first_seen"],
                str,
            ):
                raise EventStateIntegrityError(
                    f"Invalid first_seen for '{event_type}'."
                )

            if not isinstance(
                state["last_seen"],
                str,
            ):
                raise EventStateIntegrityError(
                    f"Invalid last_seen for '{event_type}'."
                )

            if "tenant_id" in state:
                tenant_id = state["tenant_id"]
                if tenant_id is not None and (
                    not isinstance(tenant_id, str) or not tenant_id.strip()
                ):
                    raise EventStateIntegrityError(
                        f"Invalid tenant_id for '{event_type}'."
                    )

    # =========================================================
    # PERSISTENCE
    # =========================================================

    def _save(
        self,
        state: dict[str, dict] | None = None,
    ) -> None:
        """
        Atomically persist state.

        Important:
        The caller's in-memory state is NOT changed by this method.

        Persistence order:

            serialize
                ↓
            temporary file
                ↓
            flush
                ↓
            fsync
                ↓
            atomic replace
        """

        if state is None:
            state = self.active_events

        candidate = deepcopy(state)

        self._validate_state_document(candidate)

        payload = json.dumps(
            candidate,
            ensure_ascii=False,
            indent=4,
            sort_keys=True,
        ).encode("utf-8")

        self.state_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd = None
        temporary_path = None

        try:
            fd, temporary_name = tempfile.mkstemp(
                prefix=self.state_path.name + ".",
                suffix=".tmp",
                dir=str(self.state_path.parent),
            )

            temporary_path = Path(temporary_name)

            with os.fdopen(
                fd,
                "wb",
            ) as file:
                fd = None

                file.write(payload)
                file.flush()
                os.fsync(file.fileno())

            os.replace(
                temporary_path,
                self.state_path,
            )

            temporary_path = None

            self._fsync_parent_directory()

        finally:

            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

            if temporary_path is not None:
                try:
                    temporary_path.unlink(
                        missing_ok=True
                    )
                except OSError:
                    pass

    # =========================================================
    # DIRECTORY DURABILITY
    # =========================================================

    def _fsync_parent_directory(self) -> None:
        """
        Best-effort directory durability.

        Some Windows filesystems do not allow opening directories
        for fsync. In that environment the atomic replace still
        protects against partial-file replacement.
        """

        try:
            directory_fd = os.open(
                str(self.state_path.parent),
                os.O_RDONLY,
            )

        except OSError:
            return

        try:
            os.fsync(directory_fd)

        except OSError:
            pass

        finally:
            try:
                os.close(directory_fd)
            except OSError:
                pass

    # =========================================================
    # UPDATE
    # =========================================================

    def update(self, event):
        """
        Add or update an event state.

        Transactional behavior:

            build candidate
                ↓
            validate
                ↓
            persist
                ↓
            commit in memory

        If persistence fails, current state remains unchanged.
        """

        event_type = event.event_type

        current_state = deepcopy(
            self.active_events
        )

        previous = current_state.get(
            event_type
        )

        now = datetime.now(
            timezone.utc
        ).isoformat()

        if previous is None:

            lifecycle = "NEW"
            occurrence_count = 1
            first_seen = now

        else:

            lifecycle = "UPDATE"

            occurrence_count = (
                previous.get(
                    "occurrence_count",
                    1,
                )
                + 1
            )

            first_seen = previous.get(
                "first_seen",
                now,
            )

        tenant_id = getattr(event, "tenant_id", None)
        if tenant_id is None and isinstance(previous, dict):
            tenant_id = previous.get("tenant_id")

        candidate_state = {
            "state": "ACTIVE",
            "lifecycle": lifecycle,
            "severity": event.severity,
            "value": event.value,
            "first_seen": first_seen,
            "last_seen": now,
            "occurrence_count": occurrence_count,
        }
        if tenant_id is not None:
            candidate_state["tenant_id"] = tenant_id

        current_state[event_type] = (
            candidate_state
        )

        self._validate_state_document(
            current_state
        )

        self._save(
            current_state
        )

        self.active_events = current_state

        return lifecycle

    # =========================================================
    # RECOVERY
    # =========================================================

    def recover(self, event_type):
        """
        Recover an active event.

        Transactional behavior:

            build candidate
                ↓
            persist
                ↓
            commit in memory

        If persistence fails, the event remains active.
        """

        if event_type not in self.active_events:
            return None

        current_state = deepcopy(
            self.active_events
        )

        previous = current_state.pop(
            event_type
        )

        self._validate_state_document(
            current_state
        )

        self._save(
            current_state
        )

        self.active_events = current_state

        return deepcopy(previous)

    # =========================================================
    # TRANSACTIONAL RESTORE
    # =========================================================

    def restore_active_state(self, event_type, state):
        """Restore an exact previously ACTIVE state transactionally."""
        if not isinstance(event_type, str) or not event_type.strip():
            raise EventStateIntegrityError("Invalid event_type for restore.")
        if not isinstance(state, dict):
            raise EventStateIntegrityError("Invalid state object for restore.")

        current_state = deepcopy(self.active_events)
        current_state[event_type] = deepcopy(state)
        self._validate_state_document(current_state)
        self._save(current_state)
        self.active_events = current_state
        return deepcopy(state)

    # =========================================================
    # READ
    # =========================================================

    def get_state(self, event_type):
        """
        Return a defensive copy of one event state.
        """

        state = self.active_events.get(
            event_type
        )

        if state is None:
            return None

        return deepcopy(state)

    def get_active_event_types(self):
        """
        Return active event types.
        """

        return list(
            self.active_events.keys()
        )

    def get_all_states(self):
        """
        Return a defensive copy of all active states.
        """

        return deepcopy(
            self.active_events
        )
    # =========================================================
    # HEALTH CONTRACT
    # =========================================================

    def health_check(self) -> dict:
        """
        EventState health contract.

        Security-first qoidalar:
        - health check read-only.
        - state yaratmaydi.
        - state o'chirmaydi.
        - recovery transition qilmaydi.
        - persistence yozmaydi.
        - corruptionni yashirmaydi.
        - exception tashqariga chiqarmaydi.
        """

        self._health_checks += 1

        try:
            # -------------------------------------------------
            # 01. State path sanity
            # -------------------------------------------------

            if not self.state_path.exists():
                # Fresh installation uchun state fayli
                # mavjud bo'lmasligi normal.
                pending_state = {}

            else:

                if not self.state_path.is_file():
                    raise EventStateIntegrityError(
                        "EventState path file emas."
                    )

                # -------------------------------------------------
                # 02. Persisted state readability
                # -------------------------------------------------

                with self.state_path.open(
                    "r",
                    encoding="utf-8",
                ) as file:

                    persisted = json.load(file)

                # -------------------------------------------------
                # 03. Persisted state integrity
                # -------------------------------------------------

                self._validate_state_document(
                    persisted
                )

                pending_state = persisted

            # -------------------------------------------------
            # 04. In-memory state integrity
            # -------------------------------------------------

            self._validate_state_document(
                self.active_events
            )

            # -------------------------------------------------
            # 05. Defensive consistency check
            # -------------------------------------------------

            if not isinstance(
                pending_state,
                dict,
            ):
                raise EventStateIntegrityError(
                    "Persisted EventState object emas."
                )

            self._last_error = None
            self._last_error_component = None

            return {
                "component": "EventState",
                "status": "HEALTHY",
                "version": self.VERSION,

                "state_path": str(
                    self.state_path
                ),

                "active_events": len(
                    self.active_events
                ),

                "persisted_events": len(
                    pending_state
                ),

                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_error":
                    None,

                "last_error_component":
                    None,
            }

        except Exception as exc:

            self._health_failures += 1

            self._last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            self._last_error_component = (
                "EventState.health_check"
            )

            return {
                "component": "EventState",
                "status": "DEGRADED",
                "version": self.VERSION,

                "state_path": str(
                    self.state_path
                ),

                "active_events":
                    len(self.active_events),

                "persisted_events":
                    None,

                "health_checks":
                    self._health_checks,

                "health_failures":
                    self._health_failures,

                "last_error":
                    self._last_error,

                "last_error_component":
                    self._last_error_component,
            }

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(self) -> dict:
        """
        EventState runtime statistikasi.
        """

        return {
            "component": "EventState",
            "version": self.VERSION,

            "state_path": str(
                self.state_path
            ),

            "active_events":
                len(self.active_events),

            "health_checks":
                self._health_checks,

            "health_failures":
                self._health_failures,

            "last_error":
                self._last_error,

            "last_error_component":
                self._last_error_component,
        }
