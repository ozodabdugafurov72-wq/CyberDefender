from __future__ import annotations

import copy
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional


class SecurityEvent:
    """
    CyberDefender Canonical Security Event v2.

    Security-first event contract.

    Guarantees:
    - Event faqat security data tashiydi.
    - Event o'z-o'zidan system modification qilmaydi.
    - Har bir event unique event_id oladi.
    - Integrity canonical SHA-256 orqali hisoblanadi.
    - Deserialization vaqtida integrity majburiy tekshiriladi.
    - Schema va field types qat'iy validatsiya qilinadi.
    - External mutable inputlar defensive-copy qilinadi.
    - JSON serialization deterministic.
    - Tampered event from_dict()/from_json() orqali qabul qilinmaydi.
    """

    VERSION = "2.0"

    VALID_SEVERITIES = {
        "INFO",
        "LOW",
        "MEDIUM",
        "WARNING",
        "HIGH",
        "CRITICAL",
    }

    DEFAULT_ACTION = "OBSERVE_ONLY"

    # ==========================================
    # CONSTRUCTOR
    # ==========================================

    def __init__(
        self,
        event_type: str,
        severity: str,
        value: Any,
        source: str,
        message: str,
        *,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        confidence: Optional[float] = None,
        host_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        sensor_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        correlation_keys: Optional[list[str]] = None,
        provenance: Optional[dict[str, Any]] = None,
        action: str = DEFAULT_ACTION,
    ):
        # ------------------------------------------
        # Identity
        # ------------------------------------------

        self.event_id = (
            str(uuid.uuid4())
            if event_id is None
            else self._validate_non_empty_string(
                event_id,
                "event_id",
            )
        )

        self.schema_version = self.VERSION

        # ------------------------------------------
        # Timestamp
        # ------------------------------------------

        self.timestamp = (
            datetime.now(
                timezone.utc
            ).isoformat()
            if timestamp is None
            else self._validate_timestamp(
                timestamp
            )
        )

        # ------------------------------------------
        # Core event fields
        # ------------------------------------------

        self.event_type = (
            self._validate_non_empty_string(
                event_type,
                "event_type",
            )
        )

        self.severity = (
            self._normalize_severity(
                severity
            )
        )

        self.value = copy.deepcopy(
            value
        )

        self.source = (
            self._validate_non_empty_string(
                source,
                "source",
            )
        )

        self.message = (
            self._validate_non_empty_string(
                message,
                "message",
            )
        )

        # ------------------------------------------
        # Confidence
        # ------------------------------------------

        self.confidence = (
            self._normalize_confidence(
                confidence
            )
        )

        # ------------------------------------------
        # Optional identity fields
        # ------------------------------------------

        self.host_id = (
            self._validate_optional_string(
                host_id,
                "host_id",
            )
        )

        self.asset_id = (
            self._validate_optional_string(
                asset_id,
                "asset_id",
            )
        )

        self.sensor_id = (
            self._validate_optional_string(
                sensor_id,
                "sensor_id",
            )
        )

        self.tenant_id = (
            self._validate_optional_string(
                tenant_id,
                "tenant_id",
            )
        )

        # ------------------------------------------
        # Correlation keys
        # ------------------------------------------

        self.correlation_keys = (
            self._normalize_correlation_keys(
                correlation_keys
            )
        )

        # ------------------------------------------
        # Provenance
        # ------------------------------------------

        self.provenance = (
            self._normalize_provenance(
                provenance
            )
        )

        # ------------------------------------------
        # Action
        # ------------------------------------------

        self.action = (
            self._validate_non_empty_string(
                action,
                "action",
            )
        )

        # ------------------------------------------
        # Validate JSON serializability before
        # calculating integrity.
        # ------------------------------------------

        self._ensure_json_serializable(
            self._canonical_payload()
        )

        # ------------------------------------------
        # Integrity
        # ------------------------------------------

        self.integrity = (
            self.compute_integrity()
        )

    # ==========================================
    # VALIDATION HELPERS
    # ==========================================

    @staticmethod
    def _validate_non_empty_string(
        value: Any,
        field_name: str,
    ) -> str:

        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{field_name} string bo'lishi kerak"
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                f"{field_name} bo'sh bo'lishi mumkin emas"
            )

        return normalized

    @staticmethod
    def _validate_optional_string(
        value: Optional[str],
        field_name: str,
    ) -> Optional[str]:

        if value is None:
            return None

        return SecurityEvent._validate_non_empty_string(
            value,
            field_name,
        )

    @staticmethod
    def _validate_timestamp(
        timestamp: str,
    ) -> str:

        if not isinstance(
            timestamp,
            str,
        ):
            raise TypeError(
                "timestamp string bo'lishi kerak"
            )

        timestamp = timestamp.strip()

        if not timestamp:
            raise ValueError(
                "timestamp bo'sh bo'lishi mumkin emas"
            )

        try:
            parsed = datetime.fromisoformat(
                timestamp.replace(
                    "Z",
                    "+00:00",
                )
            )
        except ValueError as error:
            raise ValueError(
                "timestamp valid ISO-8601 formatida bo'lishi kerak"
            ) from error

        # Normalize UTC timestamps only when
        # timezone information is present.
        if parsed.tzinfo is None:
            raise ValueError(
                "timestamp timezone bilan berilishi kerak"
            )

        return timestamp

    # ==========================================
    # SEVERITY
    # ==========================================

    @classmethod
    def _normalize_severity(
        cls,
        severity: str,
    ) -> str:

        if not isinstance(
            severity,
            str,
        ):
            raise TypeError(
                "severity string bo'lishi kerak"
            )

        normalized = (
            severity.upper().strip()
        )

        if normalized not in cls.VALID_SEVERITIES:
            raise ValueError(
                f"Noto'g'ri severity: {severity}"
            )

        return normalized

    # ==========================================
    # CONFIDENCE
    # ==========================================

    @staticmethod
    def _normalize_confidence(
        confidence: Optional[float],
    ) -> Optional[float]:

        if confidence is None:
            return None

        if isinstance(
            confidence,
            bool,
        ):
            raise TypeError(
                "confidence boolean bo'lishi mumkin emas"
            )

        try:
            normalized = float(
                confidence
            )
        except (
            TypeError,
            ValueError,
        ) as error:
            raise TypeError(
                "confidence numeric bo'lishi kerak"
            ) from error

        if not 0.0 <= normalized <= 1.0:
            raise ValueError(
                "confidence 0.0 va 1.0 oralig'ida bo'lishi kerak"
            )

        return normalized

    # ==========================================
    # CORRELATION KEYS
    # ==========================================

    @staticmethod
    def _normalize_correlation_keys(
        correlation_keys: Optional[list[str]],
    ) -> list[str]:

        if correlation_keys is None:
            return []

        if not isinstance(
            correlation_keys,
            list,
        ):
            raise TypeError(
                "correlation_keys list bo'lishi kerak"
            )

        normalized: list[str] = []

        for index, key in enumerate(
            correlation_keys
        ):
            if not isinstance(
                key,
                str,
            ):
                raise TypeError(
                    "correlation_keys["
                    f"{index}"
                    "] string bo'lishi kerak"
                )

            key = key.strip()

            if not key:
                raise ValueError(
                    "correlation_keys ichida "
                    "bo'sh qiymat bo'lishi mumkin emas"
                )

            normalized.append(
                key
            )

        # Deterministic and duplicate-free.
        return list(
            dict.fromkeys(
                normalized
            )
        )

    # ==========================================
    # PROVENANCE
    # ==========================================

    @staticmethod
    def _normalize_provenance(
        provenance: Optional[dict[str, Any]],
    ) -> dict[str, Any]:

        if provenance is None:
            return {}

        if not isinstance(
            provenance,
            dict,
        ):
            raise TypeError(
                "provenance dict bo'lishi kerak"
            )

        normalized = copy.deepcopy(
            provenance
        )

        SecurityEvent._ensure_json_serializable(
            normalized,
            field_name="provenance",
        )

        return normalized

    # ==========================================
    # JSON SAFETY
    # ==========================================

    @staticmethod
    def _ensure_json_serializable(
        value: Any,
        *,
        field_name: str = "value",
    ) -> None:

        try:
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (
            TypeError,
            ValueError,
        ) as error:
            raise TypeError(
                f"{field_name} JSON serializable "
                "bo'lishi kerak"
            ) from error

    # ==========================================
    # CANONICAL PAYLOAD
    # ==========================================

    def _canonical_payload(self) -> dict[str, Any]:
        """
        Integrity hisoblash uchun deterministic payload.

        Muhim:
            integrity payload ichiga kiritilmaydi.
        """

        return {
            "event_id": self.event_id,
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "value": copy.deepcopy(
                self.value
            ),
            "source": self.source,
            "message": self.message,
            "host_id": self.host_id,
            "asset_id": self.asset_id,
            "sensor_id": self.sensor_id,
            "tenant_id": self.tenant_id,
            "correlation_keys": list(
                self.correlation_keys
            ),
            "provenance": copy.deepcopy(
                self.provenance
            ),
            "action": self.action,
        }

    # ==========================================
    # INTEGRITY
    # ==========================================

    def compute_integrity(self) -> str:
        """
        Canonical payload uchun SHA-256.
        """

        payload = self._canonical_payload()

        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def verify_integrity(self) -> bool:
        """
        Eventning hozirgi state'i saqlangan
        integrity bilan mos keladimi?
        """

        try:
            expected = (
                self.compute_integrity()
            )

            actual = self.integrity

            if not isinstance(
                actual,
                str,
            ):
                return False

            # SHA-256 digest comparison.
            return (
                hmac.compare_digest(
                    actual,
                    expected,
                )
            )

        except Exception:
            # Security boundary:
            # verification failure = reject.
            return False

    # ==========================================
    # SERIALIZATION
    # ==========================================

    def to_dict(self) -> dict[str, Any]:
        """
        Canonical dictionary representation.
        """

        return {
            **self._canonical_payload(),
            "integrity": self.integrity,
        }

    def to_json(self) -> str:
        """
        Deterministic JSON representation.
        """

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    # ==========================================
    # DESERIALIZATION
    # ==========================================

    @classmethod
    def from_dict(
        cls,
        data: dict,
    ) -> "SecurityEvent":
        """
        Dictionary'dan SecurityEvent tiklaydi.

        Security rules:
        1. data dict bo'lishi kerak.
        2. Barcha schema fields mavjud bo'lishi kerak.
        3. schema_version aynan qo'llab-quvvatlanishi kerak.
        4. supplied integrity string bo'lishi kerak.
        5. Constructor orqali yangi canonical integrity
           hisoblanadi.
        6. supplied integrity va computed integrity
           mos kelishi shart.
        """

        if not isinstance(
            data,
            dict,
        ):
            raise TypeError(
                "SecurityEvent data dict bo'lishi kerak"
            )

        required_fields = {
            "event_id",
            "schema_version",
            "timestamp",
            "event_type",
            "severity",
            "value",
            "source",
            "message",
            "confidence",
            "host_id",
            "asset_id",
            "sensor_id",
            "tenant_id",
            "correlation_keys",
            "provenance",
            "action",
            "integrity",
        }

        missing = (
            required_fields
            - set(data.keys())
        )

        if missing:
            raise ValueError(
                "SecurityEvent fieldlari "
                "yetishmayapti: "
                f"{sorted(missing)}"
            )

        supplied_schema_version = (
            data["schema_version"]
        )

        if (
            supplied_schema_version
            != cls.VERSION
        ):
            raise ValueError(
                "Qo'llab-quvvatlanmaydigan "
                f"schema_version: "
                f"{supplied_schema_version}"
            )

        supplied_integrity = (
            data["integrity"]
        )

        if not isinstance(
            supplied_integrity,
            str,
        ):
            raise ValueError(
                "integrity string bo'lishi kerak"
            )

        supplied_integrity = (
            supplied_integrity.strip()
        )

        if not supplied_integrity:
            raise ValueError(
                "integrity bo'sh bo'lishi mumkin emas"
            )

        # SHA-256 hex digest must be exactly 64 chars.
        if (
            len(supplied_integrity)
            != 64
        ):
            raise ValueError(
                "integrity valid SHA-256 "
                "digest bo'lishi kerak"
            )

        try:
            int(
                supplied_integrity,
                16,
            )
        except ValueError as error:
            raise ValueError(
                "integrity valid hexadecimal "
                "SHA-256 digest bo'lishi kerak"
            ) from error

        # ------------------------------------------
        # Reconstruct trusted event.
        # ------------------------------------------

        event = cls(
            event_id=data["event_id"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            severity=data["severity"],
            value=data["value"],
            source=data["source"],
            message=data["message"],
            confidence=data["confidence"],
            host_id=data["host_id"],
            asset_id=data["asset_id"],
            sensor_id=data["sensor_id"],
            tenant_id=data["tenant_id"],
            correlation_keys=data[
                "correlation_keys"
            ],
            provenance=data[
                "provenance"
            ],
            action=data["action"],
        )

        # ------------------------------------------
        # Integrity binding.
        # ------------------------------------------

        if not hmac.compare_digest(
            event.integrity,
            supplied_integrity,
        ):
            raise ValueError(
                "SecurityEvent integrity mismatch: "
                "event tampered yoki buzilgan"
            )

        if not event.verify_integrity():
            raise ValueError(
                "SecurityEvent reconstructed "
                "integrity verification failed"
            )

        return event

    # ==========================================
    # JSON DESERIALIZATION
    # ==========================================

    @classmethod
    def from_json(
        cls,
        data: str,
    ) -> "SecurityEvent":
        """
        JSON string'dan SecurityEvent tiklaydi.
        """

        if not isinstance(
            data,
            str,
        ):
            raise TypeError(
                "JSON string bo'lishi kerak"
            )

        try:
            payload = json.loads(
                data
            )
        except json.JSONDecodeError as error:
            raise ValueError(
                f"SecurityEvent JSON noto'g'ri: "
                f"{error}"
            ) from error

        return cls.from_dict(
            payload
        )

    # ==========================================
    # OUTPUT
    # ==========================================

    def print_event(self) -> None:

        print()
        print("Security Event:")

        print(
            f"Event ID: "
            f"{self.event_id}"
        )

        print(
            f"Schema Version: "
            f"{self.schema_version}"
        )

        print(
            f"Timestamp: "
            f"{self.timestamp}"
        )

        print(
            f"Type: "
            f"{self.event_type}"
        )

        print(
            f"Severity: "
            f"{self.severity}"
        )

        print(
            f"Confidence: "
            f"{self.confidence}"
        )

        print(
            f"Value: "
            f"{self.value}"
        )

        print(
            f"Source: "
            f"{self.source}"
        )

        print(
            f"Message: "
            f"{self.message}"
        )

        print(
            f"Host ID: "
            f"{self.host_id}"
        )

        print(
            f"Asset ID: "
            f"{self.asset_id}"
        )

        print(
            f"Sensor ID: "
            f"{self.sensor_id}"
        )

        print(
            f"Tenant ID: "
            f"{self.tenant_id}"
        )

        print(
            f"Correlation Keys: "
            f"{self.correlation_keys}"
        )

        print(
            f"Action: "
            f"{self.action}"
        )

        print(
            f"Integrity: "
            f"{self.integrity}"
        )

