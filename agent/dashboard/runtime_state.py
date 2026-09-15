from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class RuntimeStatePublisher:
    """
    CyberDefender Runtime -> Dashboard read-only state bridge.

    Security properties:
        - Dashboard has no control over Runtime.
        - State is written atomically.
        - Partial JSON files are avoided.
        - Runtime publication failure does not stop security runtime.
        - Dashboard can detect stale runtime state.
    """

    SCHEMA_VERSION = "1.0"
    DEFAULT_FILENAME = "dashboard_runtime.json"

    def __init__(self, state_root: Path):
        if not isinstance(state_root, Path):
            raise TypeError(
                "state_root Path bo'lishi kerak"
            )

        self.state_root = (
            state_root.resolve()
        )

        self.state_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.state_file = (
            self.state_root
            / self.DEFAULT_FILENAME
        )

        self.sequence = 0

        self.last_publish_time: float | None = None

        self.publish_count = 0
        self.publish_failures = 0

    # =========================================================
    # JSON SAFETY
    # =========================================================

    @staticmethod
    def _safe_value(
        value: Any,
    ) -> Any:
        """
        Convert runtime objects into JSON-safe values.
        """

        if value is None:
            return None

        if isinstance(
            value,
            (
                str,
                int,
                float,
                bool,
            ),
        ):
            return value

        if isinstance(
            value,
            dict,
        ):
            return {
                str(key):
                    RuntimeStatePublisher._safe_value(
                        item
                    )
                for key, item in value.items()
            }

        if isinstance(
            value,
            (list, tuple, set),
        ):
            return [
                RuntimeStatePublisher._safe_value(
                    item
                )
                for item in value
            ]

        return str(value)

    # =========================================================
    # SNAPSHOT BUILDER
    # =========================================================

    def build_snapshot(
        self,
        *,
        runtime: dict[str, Any],
        health: dict[str, Any],
        observation: dict[str, Any] | None,
        incidents: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:

        self.sequence += 1

        return {
            "schema_version":
                self.SCHEMA_VERSION,

            "publisher": {
                "component":
                    "RuntimeStatePublisher",

                "sequence":
                    self.sequence,

                "generated_at":
                    time.time(),
            },

            "runtime":
                self._safe_value(
                    runtime
                ),

            "health":
                self._safe_value(
                    health
                ),

            "observation":
                self._safe_value(
                    observation or {}
                ),

            "incidents":
                self._safe_value(
                    incidents or []
                ),
        }

    # =========================================================
    # ATOMIC WRITE
    # =========================================================

    def _atomic_write(
        self,
        snapshot: dict[str, Any],
    ) -> None:

        payload = json.dumps(
            snapshot,
            ensure_ascii=False,
            separators=(
                ",",
                ":",
            ),
        ).encode("utf-8")

        fd = None
        temp_path: str | None = None

        try:

            fd, temp_path = tempfile.mkstemp(
                prefix=".dashboard_runtime_",
                suffix=".tmp",
                dir=str(
                    self.state_root
                ),
            )

            with os.fdopen(
                fd,
                "wb",
            ) as tmp:

                fd = None

                tmp.write(
                    payload
                )

                tmp.flush()

                try:
                    os.fsync(
                        tmp.fileno()
                    )
                except OSError:
                    pass

            os.replace(
                temp_path,
                self.state_file,
            )

            temp_path = None

        finally:

            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

            if temp_path is not None:
                try:
                    os.unlink(
                        temp_path
                    )
                except OSError:
                    pass

    # =========================================================
    # PUBLISH
    # =========================================================

    def publish(
        self,
        *,
        runtime: dict[str, Any],
        health: dict[str, Any],
        observation: dict[str, Any] | None,
        incidents: list[dict[str, Any]] | None = None,
    ) -> bool:

        try:

            snapshot = (
                self.build_snapshot(
                    runtime=runtime,
                    health=health,
                    observation=observation,
                    incidents=incidents,
                )
            )

            self._atomic_write(
                snapshot
            )

            self.last_publish_time = (
                time.time()
            )

            self.publish_count += 1

            return True

        except Exception:

            self.publish_failures += 1

            return False

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(
        self,
    ) -> dict[str, Any]:

        return {
            "component":
                "RuntimeStatePublisher",

            "status":
                "HEALTHY",

            "schema_version":
                self.SCHEMA_VERSION,

            "state_file":
                str(
                    self.state_file
                ),

            "publish_count":
                self.publish_count,

            "publish_failures":
                self.publish_failures,

            "last_publish_time":
                self.last_publish_time,
        }