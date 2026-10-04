from __future__ import annotations

import time
import uuid
from collections import deque
from threading import Lock
from typing import Any, Callable


class CorrelationEngine:
    """
    CyberDefender Correlation Engine v1.2

    Pipeline:

        DETECTION
            в†“
        Validation
            в†“
        Normalization
            в†“
        Duplicate Suppression
            в†“
        Correlation
            в†“
        Risk Calculation
            в†“
        INCIDENT

    Analysis only.

    This component NEVER:
        - kills processes
        - modifies firewall
        - modifies registry
        - deletes files
        - disconnects network
        - executes remediation
    """

    VERSION = "1.4"

    DEFAULT_WINDOW_SECONDS = 60

    MAX_RECENT_EVENTS = 5000
    MAX_EVENTS_PER_INCIDENT = 50
    MAX_ACTIVE_INCIDENTS = 1000

    SEVERITY_SCORE = {
        "INFO": 5,
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 35,
        "CRITICAL": 50,
    }

    SEVERITY_ORDER = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    SEVERITY_ALIASES = {
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "NOTICE": "LOW",
        "ERROR": "HIGH",
        "FATAL": "CRITICAL",
    }

    # Host-wide resource conditions from independent detectors must coalesce
    # into one operational incident family instead of producing one incident
    # per source.  Only explicitly host-wide resource signal types are mapped
    # here; unknown/security signals keep the existing identity rules.
    RESOURCE_FAMILY_TYPES = {
        "HIGH_MEMORY_USAGE": "MEMORY_PRESSURE",
        "LOW_AVAILABLE_MEMORY": "MEMORY_PRESSURE",
        "HIGH_CPU_USAGE": "CPU_PRESSURE",
        "HIGH_PROCESS_COUNT": "PROCESS_PRESSURE",
        "HIGH_DISK_USAGE": "DISK_PRESSURE",
        "LOW_DISK_SPACE": "DISK_PRESSURE",
    }

    def __init__(
        self,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ):
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, int)
        ):
            raise TypeError(
                "window_seconds integer bo'lishi kerak"
            )

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds 0 dan katta bo'lishi kerak"
            )

        self.window_seconds = window_seconds

        self._active_incidents: dict[
            str,
            dict,
        ] = {}

        self._recent_events = deque(
            maxlen=self.MAX_RECENT_EVENTS
        )

        self._lock = Lock()

        # Counters
        self._received = 0
        self._ignored = 0
        self._duplicates = 0
        self._correlated = 0
        self._incidents_created = 0
        self._incidents_updated = 0
        self._failed = 0

        # Diagnostics
        self._validation_failed = 0
        self._processing_failed = 0

        self._last_error: str | None = None
        self._last_error_type: str | None = None
        self._last_error_at: float | None = None

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(self) -> dict:
        return {
            "component": "CorrelationEngine",
            "status": "HEALTHY",
            "version": self.VERSION,
        }

    # =========================================================
    # PUBLIC INGEST
    # =========================================================

    def ingest(
        self,
        event: Any,
        *,
        strict: bool = False,
        publish: Callable[[dict], bool] | None = None,
    ) -> dict | None:
        """
        Accept only DETECTION events.

        Processing is transactional:
        internal state is committed only after
        validation, correlation and risk calculation
        succeed.
        """

        if not isinstance(event, dict):
            with self._lock:
                self._ignored += 1
                self._validation_failed += 1

            if strict:
                raise ValueError("invalid detection input")
            return None

        if event.get("event_type") != "DETECTION":
            with self._lock:
                self._ignored += 1
                self._validation_failed += 1

            if strict:
                raise ValueError("invalid detection type")
            return None

        with self._lock:
            self._received += 1

        # -----------------------------------------------------
        # NORMALIZE / VALIDATE
        # -----------------------------------------------------

        try:
            detection = self._normalize_detection(
                event
            )

        except ValueError as exc:
            self._record_validation_error(
                exc
            )

            with self._lock:
                self._ignored += 1

            if strict:
                raise
            return None

        except Exception as exc:
            self._record_processing_error(
                exc
            )

            if strict:
                raise
            return None

        # -----------------------------------------------------
        # CORRELATION
        # -----------------------------------------------------

        try:
            with self._lock:

                now = detection["timestamp"]

                self._expire_old_incidents(
                    now
                )

                # ---------------------------------------------
                # DUPLICATE CHECK
                # ---------------------------------------------

                if self._is_duplicate(
                    detection
                ):
                    self._duplicates += 1
                    self._ignored += 1
                    return None

                # ---------------------------------------------
                # CORRELATION KEY
                # ---------------------------------------------

                correlation_key = (
                    self._build_correlation_key(
                        detection
                    )
                )

                existing_incident = (
                    self._active_incidents.get(
                        correlation_key
                    )
                )

                # ---------------------------------------------
                # BUILD CANDIDATE STATE
                # ---------------------------------------------

                if existing_incident is None:

                    candidate = (
                        self._create_incident(
                            correlation_key,
                            detection,
                        )
                    )

                    operation = "CREATE"

                else:

                    candidate = (
                        self._clone_incident(
                            existing_incident
                        )
                    )

                    self._update_incident(
                        candidate,
                        detection,
                    )

                    operation = "UPDATE"

                # ---------------------------------------------
                # COMMIT
                # ---------------------------------------------

                # Delivery callers require publication before committing
                # duplicate suppression. A rejected publication can retry
                # through the existing durable pending-event path.
                incident_event = self._incident_event(candidate)
                if publish is not None and publish(incident_event) is not True:
                    raise RuntimeError("incident publication rejected")

                self._recent_events.append(
                    detection
                )

                self._active_incidents[
                    correlation_key
                ] = candidate

                self._enforce_incident_limit()

                self._correlated += 1

                if operation == "CREATE":
                    self._incidents_created += 1
                else:
                    self._incidents_updated += 1

                return incident_event

        except Exception as exc:
            self._record_processing_error(
                exc
            )

            if strict:
                raise
            return None

    # =========================================================
    # NORMALIZATION
    # =========================================================

    def _normalize_detection(
        self,
        event: dict,
    ) -> dict:

        data = event.get(
            "data"
        )

        if not isinstance(
            data,
            dict,
        ):
            raise ValueError(
                "DETECTION data dict bo'lishi kerak"
            )

        raw_type = data.get(
            "type"
        )

        if raw_type is None:
            raise ValueError(
                "DETECTION type mavjud emas"
            )

        detection_type = str(
            raw_type
        ).strip()

        if not detection_type:
            raise ValueError(
                "DETECTION type bo'sh bo'lishi mumkin emas"
            )

        severity = self._normalize_severity(
            data.get(
                "severity",
                "INFO",
            )
        )

        source = str(
            data.get(
                "source",
                "unknown",
            )
        ).strip()

        if not source:
            source = "unknown"

        source_event_id = event.get("event_id")
        if not isinstance(source_event_id, str) or not source_event_id.strip():
            source_event_id = None
        else:
            source_event_id = source_event_id.strip()

        raw_timestamp = event.get("timestamp")
        try:
            event_timestamp = float(raw_timestamp)
            if event_timestamp != event_timestamp or event_timestamp in (float("inf"), float("-inf")):
                raise ValueError
        except (TypeError, ValueError):
            event_timestamp = time.time()

        raw_provenance = data.get("provenance")
        provenance = {}
        if isinstance(raw_provenance, dict):
            # Keep only bounded linkage fields.  Provenance is evidence, not
            # an authorization input, and must never carry arbitrary secrets.
            for key in (
                "activity_event_id",
                "target",
                "approved_root",
                "lab_canary",
                "execution_mode",
            ):
                value = raw_provenance.get(key)
                if isinstance(value, (str, bool)):
                    provenance[key] = str(value)[:512] if isinstance(value, str) else value

        return {
            "timestamp": event_timestamp,
            "source_event_id": source_event_id,
            "type": detection_type,
            "severity": severity,
            "source": source,
            "value": data.get("value"),
            "message": str(
                data.get(
                    "message",
                    "",
                )
            ),
            "host_id": data.get(
                "host_id"
            ),
            "process_id": data.get(
                "process_id"
            ),
            "parent_process_id": data.get(
                "parent_process_id"
            ),
            "user_id": data.get(
                "user_id"
            ),
            "session_id": data.get(
                "session_id"
            ),
            "entity_id": data.get(
                "entity_id"
            ),
            "asset_id": data.get(
                "asset_id"
            ),
            "sensor_id": data.get(
                "sensor_id"
            ),
            "tenant_id": data.get(
                "tenant_id"
            ),
            "provenance": provenance,
        }

    # =========================================================
    # SEVERITY NORMALIZATION
    # =========================================================

    def _normalize_severity(
        self,
        severity: Any,
    ) -> str:

        if severity is None:
            return "INFO"

        normalized = str(
            severity
        ).strip().upper()

        if not normalized:
            return "INFO"

        if normalized in self.SEVERITY_SCORE:
            return normalized

        alias = self.SEVERITY_ALIASES.get(
            normalized
        )

        if alias:
            return alias

        # Unknown severity must never
        # crash the correlation engine.
        return "INFO"

    # =========================================================
    # CORRELATION IDENTITY
    # =========================================================

    @classmethod
    def _resource_family(
        cls,
        detection: dict,
    ) -> str | None:
        """Return a bounded host-wide resource incident family.

        Recovery signals intentionally map back to the same family so a
        SystemObserver/RuleEngine/EventState view of one memory-pressure
        episode does not fan out into separate active incidents.
        """
        raw_type = str(detection.get("type", "")).strip().upper()
        if raw_type.endswith("_RECOVERED"):
            raw_type = raw_type[:-10]
        return cls.RESOURCE_FAMILY_TYPES.get(raw_type)

    @staticmethod
    def _resource_scope(
        detection: dict,
    ) -> str:
        """Choose the narrowest available endpoint scope.

        Different endpoints must never merge merely because they report the
        same resource family.  If no explicit endpoint identity is present,
        the CorrelationEngine is local-agent scoped by construction.
        """
        for field, prefix in (
            ("host_id", "host"),
            ("asset_id", "asset"),
            ("sensor_id", "sensor"),
        ):
            value = detection.get(field)
            if value is not None and str(value).strip():
                return f"{prefix}:{str(value).strip()}"
        return "agent-local"

    def _build_correlation_key(
        self,
        detection: dict,
    ) -> str:
        """
        Correlation identity priority:

        1. explicit host-wide resource family + endpoint scope
        2. entity_id
        3. process_id + host_id
        4. process_id
        5. session_id + host_id
        6. session_id
        7. user_id + host_id
        8. host_id
        9. isolated agent/source fallback

        This is intentionally designed so that
        unrelated hosts/processes do not accidentally
        enter the same incident.
        """

        resource_family = self._resource_family(detection)
        if resource_family:
            return (
                "resource:"
                f"{self._resource_scope(detection)}:"
                f"{resource_family}"
            )

        entity_id = detection.get(
            "entity_id"
        )

        if entity_id:
            return (
                f"entity:{entity_id}"
            )

        process_id = detection.get(
            "process_id"
        )

        host_id = detection.get(
            "host_id"
        )

        if process_id and host_id:
            return (
                f"process:{host_id}:"
                f"{process_id}"
            )

        if process_id:
            return (
                f"process:{process_id}"
            )

        session_id = detection.get(
            "session_id"
        )

        if session_id and host_id:
            return (
                f"session:{host_id}:"
                f"{session_id}"
            )

        if session_id:
            return (
                f"session:{session_id}"
            )

        user_id = detection.get(
            "user_id"
        )

        if user_id and host_id:
            return (
                f"user:{host_id}:"
                f"{user_id}"
            )

        if host_id:
            return (
                f"host:{host_id}"
            )

        # Deliberately isolated fallback.
        return (
            "agent-local:"
            f"{detection['source']}"
        )

    # =========================================================
    # DUPLICATE SUPPRESSION
    # =========================================================

    def _is_duplicate(
        self,
        detection: dict,
    ) -> bool:

        current_timestamp = detection[
            "timestamp"
        ]

        current_key = (
            self._build_correlation_key(
                detection
            )
        )

        for existing in reversed(
            self._recent_events
        ):

            age = (
                current_timestamp
                - existing["timestamp"]
            )

            if age > self.window_seconds:
                break

            if age < 0:
                continue

            existing_key = (
                self._build_correlation_key(
                    existing
                )
            )

            if (
                detection["type"]
                == existing["type"]
                and detection["source"]
                == existing["source"]
                and detection["value"]
                == existing["value"]
                and current_key
                == existing_key
            ):
                return True

        return False

    # =========================================================
    # INCIDENT CREATION
    # =========================================================

    def _create_incident(
        self,
        correlation_key: str,
        detection: dict,
    ) -> dict:

        source_event_id = detection.get("source_event_id")
        if isinstance(source_event_id, str) and source_event_id.strip():
            # Stable semantic identity makes at-least-once replay
            # duplicate-addressable across crash/restart. It does not claim
            # transport exactly-once semantics.
            incident_uuid = uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"CyberDefender/incident/v1/{source_event_id.strip()}",
            )
            incident_id = f"INC-{incident_uuid.hex.upper()}"
        else:
            # Legacy direct engine callers may not carry a source event id.
            incident_id = f"INC-{uuid.uuid4().hex.upper()}"

        incident = {
            "incident_id": incident_id,
            "correlation_key": correlation_key,
            "incident_family": self._resource_family(detection),
            "sources": [detection.get("source", "unknown")],
            "detection_types": [detection.get("type")],
            "created_at": detection[
                "timestamp"
            ],
            "updated_at": detection[
                "timestamp"
            ],
            "detections": [
                detection
            ],
            "event_count": 1,
            "evidence_count": 1,
            "risk_score": 0,
            "severity": "INFO",
            "current_state": "RECOVERED" if str(detection.get("type", "")).upper().endswith("_RECOVERED") else "ACTIVE",
            "active_now": not str(detection.get("type", "")).upper().endswith("_RECOVERED"),
            "recovered_at": detection["timestamp"] if str(detection.get("type", "")).upper().endswith("_RECOVERED") else None,
        }

        self._recalculate_risk(
            incident
        )

        return incident

    # =========================================================
    # INCIDENT CLONE
    # =========================================================

    def _clone_incident(
        self,
        incident: dict,
    ) -> dict:

        return {
            **incident,
            "detections": list(
                incident["detections"]
            ),
            "sources": list(incident.get("sources", [])),
            "detection_types": list(incident.get("detection_types", [])),
        }

    # =========================================================
    # INCIDENT UPDATE
    # =========================================================

    def _update_incident(
        self,
        incident: dict,
        detection: dict,
    ) -> None:

        detections = incident[
            "detections"
        ]

        # Keep only a bounded forensic evidence window in memory while
        # preserving the true cumulative occurrence count.  The previous
        # implementation set event_count=len(detections), which silently
        # stopped at MAX_EVENTS_PER_INCIDENT after compaction.
        prior_total = incident.get(
            "event_count",
            len(detections),
        )
        try:
            prior_total = int(prior_total)
        except (TypeError, ValueError):
            prior_total = len(detections)
        if prior_total < len(detections):
            prior_total = len(detections)

        if len(detections) >= (
            self.MAX_EVENTS_PER_INCIDENT
        ):
            detections.pop(0)

        detections.append(
            detection
        )

        incident["event_count"] = prior_total + 1
        incident["evidence_count"] = len(detections)

        source = detection.get("source", "unknown")
        sources = incident.setdefault("sources", [])
        if source not in sources:
            sources.append(source)

        detection_type = detection.get("type")
        detection_types = incident.setdefault("detection_types", [])
        if detection_type and detection_type not in detection_types:
            detection_types.append(detection_type)

        if incident.get("incident_family") is None:
            incident["incident_family"] = self._resource_family(detection)

        incident["updated_at"] = (
            detection["timestamp"]
        )
        recovered = str(detection.get("type", "")).upper().endswith("_RECOVERED")
        incident["current_state"] = "RECOVERED" if recovered else "ACTIVE"
        incident["active_now"] = not recovered
        incident["recovered_at"] = detection["timestamp"] if recovered else None

        self._recalculate_risk(
            incident
        )

    # =========================================================
    # RISK CALCULATION
    # =========================================================

    def _recalculate_risk(
        self,
        incident: dict,
    ) -> None:
        """
        Risk calculation v2.

        Security principle:

            repeated identical observations
                !=
            new independent threat

        Repeated observations of the same detection type
        must not blindly stack severity until CRITICAL.

        Risk is primarily based on:
            - highest observed severity
            - distinct detection types
            - limited correlation diversity bonus

        This prevents persistent resource pressure or another
        repeated telemetry condition from artificially escalating
        an incident to CRITICAL.
        """

        detections = incident.get(
            "detections",
            [],
        )

        if not detections:
            incident["risk_score"] = 0
            incident["severity"] = "INFO"
            return

        unique_types = set()

        highest_severity = "INFO"
        highest_score = 0

        for detection in detections:

            severity = self._normalize_severity(
                detection.get(
                    "severity",
                    "INFO",
                )
            )

            severity_score = self.SEVERITY_SCORE[
                severity
            ]

            if severity_score > highest_score:
                highest_score = severity_score

            if (
                self.SEVERITY_ORDER[severity]
                >
                self.SEVERITY_ORDER[highest_severity]
            ):
                highest_severity = severity

            detection_type = detection.get(
                "type"
            )

            if detection_type:
                unique_types.add(
                    detection_type
                )

        # -----------------------------------------------------
        # DISTINCT SIGNAL BONUS
        # -----------------------------------------------------
        #
        # Bonus faqat turli detection type'lar uchun.
        # Bir xil signalni qayta-qayta olish bonus bermaydi.
        #

        diversity_bonus = 0

        if len(unique_types) >= 2:
            diversity_bonus += 10

        if len(unique_types) >= 3:
            diversity_bonus += 10

        if len(unique_types) >= 5:
            diversity_bonus += 15

        score = min(
            highest_score + diversity_bonus,
            100,
        )

        score_level = self._risk_level(
            score
        )

        # Yuqori severity hech qachon pasaytirilmaydi.
        if (
            self.SEVERITY_ORDER[
                highest_severity
            ]
            >
            self.SEVERITY_ORDER[
                score_level
            ]
        ):
            incident["severity"] = (
                highest_severity
            )
        else:
            incident["severity"] = (
                score_level
            )

        incident["risk_score"] = score
    # =========================================================
    # RISK LEVEL
    # =========================================================

    def _risk_level(
        self,
        score: int,
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        if score >= 10:
            return "LOW"

        return "INFO"

    # =========================================================
    # EXPIRATION
    # =========================================================

    def _expire_old_incidents(
        self,
        now: float,
    ) -> None:

        expired = []

        for (
            key,
            incident,
        ) in self._active_incidents.items():

            if (
                now
                - incident["updated_at"]
                > self.window_seconds
            ):
                expired.append(
                    key
                )

        for key in expired:
            self._active_incidents.pop(
                key,
                None,
            )

    # =========================================================
    # INCIDENT LIMIT
    # =========================================================

    def _enforce_incident_limit(
        self,
    ) -> None:

        while (
            len(self._active_incidents)
            > self.MAX_ACTIVE_INCIDENTS
        ):

            oldest_key = min(
                self._active_incidents,
                key=lambda key:
                    self._active_incidents[
                        key
                    ]["updated_at"],
            )

            self._active_incidents.pop(
                oldest_key,
                None,
            )

    # =========================================================
    # INCIDENT EVENT
    # =========================================================

    def _incident_event(
        self,
        incident: dict,
    ) -> dict:

        detections = incident.get("detections", [])
        trigger_event_id = None
        if isinstance(detections, list) and detections:
            candidate = detections[-1]
            if isinstance(candidate, dict):
                value = candidate.get("source_event_id")
                if isinstance(value, str) and value.strip():
                    trigger_event_id = value.strip()

        incident_id = incident["incident_id"]
        idempotency_key = (
            f"INCIDENT:{incident_id}:{trigger_event_id}"
            if trigger_event_id is not None
            else None
        )

        return {
            "event_type": "INCIDENT",
            "tenant_id": (
                detections[-1].get("tenant_id")
                if isinstance(detections, list)
                and detections
                and isinstance(detections[-1], dict)
                else None
            ),
            "source_event_id": trigger_event_id,
            "idempotency_key": idempotency_key,
            "source": "CorrelationEngine",
            "incident_id":
                incident["incident_id"],
            "severity":
                incident["severity"],
            "risk_score":
                incident["risk_score"],
            "event_count":
                incident["event_count"],
            "evidence_count":
                incident.get(
                    "evidence_count",
                    len(incident["detections"]),
                ),
            "evidence_limit":
                self.MAX_EVENTS_PER_INCIDENT,
            "correlation_key":
                incident["correlation_key"],
            "incident_family":
                incident.get("incident_family"),
            "sources":
                list(incident.get("sources", [])),
            "detection_types":
                list(incident.get("detection_types", [])),
            "window_seconds":
                self.window_seconds,
            "detections":
                list(
                    incident["detections"]
                ),
            "created_at":
                incident["created_at"],
            "updated_at":
                incident["updated_at"],
            "current_state": incident.get("current_state", "ACTIVE"),
            "active_now": bool(incident.get("active_now", True)),
            "recovered_at": incident.get("recovered_at"),
        }

    # =========================================================
    # PUBLIC INCIDENT ACCESS
    # =========================================================

    def get_incident(
        self,
        incident_id: str,
    ) -> dict | None:

        with self._lock:

            for incident in (
                self._active_incidents.values()
            ):

                if (
                    incident["incident_id"]
                    == incident_id
                ):
                    return self._incident_event(
                        incident
                    )

        return None

    def get_recent_incidents(
        self,
        limit: int = 20,
    ) -> list[dict]:

        if limit <= 0:
            return []

        with self._lock:

            incidents = list(
                self._active_incidents.values()
            )

            incidents.sort(
                key=lambda item:
                    item["updated_at"]
            )

            return [
                self._incident_event(
                    incident
                )
                for incident in incidents[
                    -limit:
                ]
            ]

    # =========================================================
    # ERROR RECORDING
    # =========================================================

    def _record_validation_error(
        self,
        error: Exception,
    ) -> None:

        with self._lock:

            self._validation_failed += 1

            self._last_error = str(
                error
            )

            self._last_error_type = (
                type(error).__name__
            )

            self._last_error_at = (
                time.time()
            )

    def _record_processing_error(
        self,
        error: Exception,
    ) -> None:

        with self._lock:

            self._failed += 1
            self._processing_failed += 1

            self._last_error = str(
                error
            )

            self._last_error_type = (
                type(error).__name__
            )

            self._last_error_at = (
                time.time()
            )

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(self) -> dict:

        with self._lock:

            return {
                "component":
                    "CorrelationEngine",

                "version":
                    self.VERSION,

                "received":
                    self._received,

                "ignored":
                    self._ignored,

                "duplicates":
                    self._duplicates,

                "correlated":
                    self._correlated,

                "incidents_created":
                    self._incidents_created,

                "incidents_updated":
                    self._incidents_updated,

                "failed":
                    self._failed,

                "validation_failed":
                    self._validation_failed,

                "processing_failed":
                    self._processing_failed,

                "active_incidents":
                    len(
                        self._active_incidents
                    ),

                "recent_events":
                    len(
                        self._recent_events
                    ),

                "window_seconds":
                    self.window_seconds,

                "last_error":
                    self._last_error,

                "last_error_type":
                    self._last_error_type,

                "last_error_at":
                    self._last_error_at,
            }
