from __future__ import annotations

"""Bounded, observation-only endpoint threat signal analysis.

This component is owned by ``RuleEngine``.  It normalizes activity telemetry,
retains only a bounded evidence window, and emits detections.  It never reads
files, starts processes, changes the host, or authorizes a response.
"""

from collections import deque
import hashlib
import math
import re
import time
from pathlib import PurePath
from typing import Any


class ThreatSignalEngine:
    VERSION = "1.0"
    EVENT_TYPES = frozenset({"PROCESS_START", "FILE_ACTIVITY", "SCRIPT_ACTIVITY", "FILE_INDICATOR"})
    MAX_ACTIVITY_EVENTS = 512
    MAX_ACTIVITY_WINDOW_SECONDS = 120.0
    DEFAULT_FILE_WINDOW_SECONDS = 30.0
    DEFAULT_MASS_FILE_THRESHOLD = 8
    DEFAULT_RENAME_BURST_THRESHOLD = 4
    DEFAULT_REPEAT_MUTATION_THRESHOLD = 6
    MAX_TEXT = 512
    MAX_EVIDENCE_ITEMS = 16

    SCRIPT_INTERPRETERS = frozenset({
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe",
    })
    SCRIPT_PARENTS = frozenset({
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    })
    SCRIPT_TOKENS = (
        "-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
        "bypass", "downloadstring", "invoke-expression", "invokewebrequest", "frombase64string",
        "certutil", "bitsadmin", "regsvr32", "mshta", "curl", "wget",
    )
    RANSOM_NOTE_RE = re.compile(r"(?:decrypt|recover|restore|ransom|how[_ -]?to)[^\\/]{0,80}", re.IGNORECASE)
    HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config if isinstance(config, dict) else {}
        threat = config.get("threat_detection", {})
        threat = threat if isinstance(threat, dict) else {}
        self.file_window_seconds = self._bounded_float(
            threat.get("file_window_seconds", self.DEFAULT_FILE_WINDOW_SECONDS),
            self.DEFAULT_FILE_WINDOW_SECONDS,
            1.0,
            self.MAX_ACTIVITY_WINDOW_SECONDS,
        )
        self.mass_file_threshold = self._bounded_int(
            threat.get("mass_file_threshold", self.DEFAULT_MASS_FILE_THRESHOLD),
            self.DEFAULT_MASS_FILE_THRESHOLD,
            3,
            128,
        )
        self.rename_burst_threshold = self._bounded_int(
            threat.get("rename_burst_threshold", self.DEFAULT_RENAME_BURST_THRESHOLD),
            self.DEFAULT_RENAME_BURST_THRESHOLD,
            2,
            64,
        )
        self.repeat_mutation_threshold = self._bounded_int(
            threat.get("repeat_mutation_threshold", self.DEFAULT_REPEAT_MUTATION_THRESHOLD),
            self.DEFAULT_REPEAT_MUTATION_THRESHOLD,
            3,
            128,
        )
        raw_iocs = threat.get("lab_ioc_hashes", ())
        ioc_values = list(raw_iocs)[:128] if isinstance(raw_iocs, (list, tuple, set)) else []
        self.lab_ioc_hashes = frozenset(
            value.lower()
            for value in ioc_values
            if isinstance(value, str) and self.HASH_RE.fullmatch(value.strip())
        )
        self._activity: deque[dict[str, Any]] = deque(maxlen=self.MAX_ACTIVITY_EVENTS)
        self._signals: deque[dict[str, Any]] = deque(maxlen=self.MAX_ACTIVITY_EVENTS)
        self._detections = 0
        self._ignored = 0

    @staticmethod
    def _bounded_float(value: Any, default: float, minimum: float, maximum: float) -> float:
        try:
            value = float(value)
            if not math.isfinite(value):
                raise ValueError
            return max(minimum, min(maximum, value))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
        if isinstance(value, bool):
            return default
        try:
            return max(minimum, min(maximum, int(value)))
        except (TypeError, ValueError):
            return default

    @classmethod
    def _text(cls, value: Any, maximum: int = MAX_TEXT) -> str:
        if not isinstance(value, str):
            return ""
        return value.strip()[:maximum]

    @staticmethod
    def _timestamp(event: dict[str, Any]) -> float:
        value = event.get("timestamp")
        try:
            value = float(value)
            now = time.time()
            # Activity windows must not be attacker-extended with an
            # arbitrarily future timestamp.  Historical fixtures remain
            # usable, while implausible values are observed at receipt time.
            if math.isfinite(value) and abs(value - now) <= 86400.0:
                return value
        except (TypeError, ValueError):
            pass
        return time.time()

    @classmethod
    def _name(cls, value: Any) -> str:
        value = cls._text(value, 256).replace("\\", "/")
        return value.rsplit("/", 1)[-1].lower()

    @classmethod
    def _scope(cls, data: dict[str, Any]) -> tuple[str, str, str | None, str | None]:
        tenant = cls._text(data.get("tenant_id"), 128) or "local"
        host = cls._text(data.get("host_id"), 128) or cls._text(data.get("asset_id"), 128) or "agent-local"
        entity = f"threat:{tenant}:{host}"
        return tenant, host, entity, cls._text(data.get("sensor_id"), 128) or None

    @classmethod
    def _safe_evidence(cls, event_type: str, event_id: str, timestamp: float, data: dict[str, Any]) -> dict[str, Any]:
        """Retain bounded normalized evidence without exporting raw secrets."""
        keys = (
            "operation", "path", "old_path", "new_path", "process_name", "parent_process_name",
            "pid", "parent_pid", "interpreter", "script_path", "indicator_type", "indicator",
            "sha256", "scope", "tenant_id", "host_id", "asset_id", "sensor_id",
        )
        evidence: dict[str, Any] = {"event_type": event_type, "event_id": event_id, "timestamp": timestamp}
        for key in keys:
            value = data.get(key)
            if isinstance(value, (str, int, float, bool)):
                text = cls._text(value) if isinstance(value, str) else value
                evidence[key] = text
        command_line = cls._text(data.get("command_line"), 2048)
        if command_line:
            evidence["command_line_sha256"] = hashlib.sha256(command_line.encode("utf-8")).hexdigest()
            evidence["command_line_indicators"] = [
                token for token in cls.SCRIPT_TOKENS if token in command_line.lower()
            ][: cls.MAX_EVIDENCE_ITEMS]
        return evidence

    def _emit(
        self,
        *,
        kind: str,
        severity: str,
        value: Any,
        message: str,
        category: str,
        event_type: str,
        event_id: str,
        timestamp: float,
        data: dict[str, Any],
        confidence: float,
    ) -> dict[str, Any]:
        tenant, host, entity, sensor = self._scope(data)
        self._detections += 1
        return {
            "type": kind,
            "severity": severity,
            "value": value,
            "message": message[: self.MAX_TEXT],
            "source": "ThreatRuleEngine",
            "timestamp": timestamp,
            "event_id": event_id,
            "confidence": max(0.0, min(1.0, confidence)),
            "tenant_id": tenant,
            "host_id": host,
            "sensor_id": sensor,
            "entity_id": entity,
            "signal_category": category,
            "evidence": self._safe_evidence(event_type, event_id, timestamp, data),
        }

    def _expire(self, now: float) -> None:
        cutoff = now - self.MAX_ACTIVITY_WINDOW_SECONDS
        while self._activity and self._activity[0]["timestamp"] < cutoff:
            self._activity.popleft()
        while self._signals and self._signals[0]["timestamp"] < cutoff:
            self._signals.popleft()

    def _record_signal(self, scope: str, category: str, timestamp: float) -> None:
        self._signals.append({"scope": scope, "category": category, "timestamp": timestamp})

    def _combined_detection(
        self,
        *,
        scope: str,
        event_type: str,
        event_id: str,
        timestamp: float,
        data: dict[str, Any],
    ) -> dict[str, Any] | None:
        categories = {
            row["category"]
            for row in self._signals
            if row["scope"] == scope and timestamp - row["timestamp"] <= self.file_window_seconds
        }
        # A single weak signal never becomes a ransomware verdict.  The
        # aggregate requires multiple independent behavioral categories.
        if len(categories) < 3:
            return None
        severity = "CRITICAL" if len(categories) >= 4 else "HIGH"
        return self._emit(
            kind="RANSOMWARE_BEHAVIOR",
            severity=severity,
            value={"signal_categories": sorted(categories), "window_seconds": self.file_window_seconds},
            message="Multiple independent file/script/process signals indicate ransomware-like behavior.",
            category="ransomware_behavior",
            event_type=event_type,
            event_id=event_id,
            timestamp=timestamp,
            data=data,
            confidence=0.95 if len(categories) >= 4 else 0.85,
        )

    def _process_start(self, event: dict[str, Any], data: dict[str, Any], event_id: str, timestamp: float) -> list[dict[str, Any]]:
        child = self._name(data.get("process_name") or data.get("image") or data.get("path"))
        parent = self._name(data.get("parent_process_name") or data.get("parent_image") or data.get("parent_path"))
        command_line = self._text(data.get("command_line"), 2048).lower()
        if not child:
            return []
        detections: list[dict[str, Any]] = []
        scope = self._scope(data)[2] or "threat:local:agent-local"
        if child in self.SCRIPT_INTERPRETERS and parent in self.SCRIPT_PARENTS and parent != child:
            self._record_signal(scope, "process_chain", timestamp)
            detections.append(self._emit(
                kind="SUSPICIOUS_PROCESS_CHAIN", severity="HIGH", value={"parent": parent, "child": child},
                message=f"Suspicious script-capable child {child} launched by {parent}.", category="process_chain",
                event_type="PROCESS_START", event_id=event_id, timestamp=timestamp, data=data, confidence=0.88,
            ))
        indicators = [token for token in self.SCRIPT_TOKENS if token in command_line]
        if child in self.SCRIPT_INTERPRETERS and indicators:
            category = "script_abuse"
            self._record_signal(scope, category, timestamp)
            detections.append(self._emit(
                kind="SCRIPT_ABUSE_INDICATOR", severity="HIGH" if len(indicators) >= 2 else "MEDIUM",
                value={"interpreter": child, "indicator_count": len(indicators)},
                message="Script interpreter command-line indicators require behavioral correlation.", category=category,
                event_type="PROCESS_START", event_id=event_id, timestamp=timestamp, data=data,
                confidence=0.78 if len(indicators) >= 2 else 0.62,
            ))
        combined = self._combined_detection(scope=scope, event_type="PROCESS_START", event_id=event_id, timestamp=timestamp, data=data)
        if combined:
            detections.append(combined)
        return detections

    def _script_activity(self, event: dict[str, Any], data: dict[str, Any], event_id: str, timestamp: float) -> list[dict[str, Any]]:
        interpreter = self._name(data.get("interpreter") or data.get("process_name"))
        command_line = self._text(data.get("command_line"), 2048).lower()
        indicators = [token for token in self.SCRIPT_TOKENS if token in command_line]
        if not interpreter and not indicators:
            self._ignored += 1
            return []
        scope = self._scope(data)[2] or "threat:local:agent-local"
        detections: list[dict[str, Any]] = []
        if indicators:
            self._record_signal(scope, "script_abuse", timestamp)
            detections.append(self._emit(
                kind="SCRIPT_ABUSE_INDICATOR", severity="HIGH" if len(indicators) >= 2 else "MEDIUM",
                value={"interpreter": interpreter or "unknown", "indicator_count": len(indicators)},
                message="Suspicious script execution indicators observed; no execution is performed by detection.",
                category="script_abuse", event_type="SCRIPT_ACTIVITY", event_id=event_id, timestamp=timestamp,
                data=data, confidence=0.80 if len(indicators) >= 2 else 0.64,
            ))
        combined = self._combined_detection(scope=scope, event_type="SCRIPT_ACTIVITY", event_id=event_id, timestamp=timestamp, data=data)
        if combined:
            detections.append(combined)
        return detections

    def _file_activity(self, event: dict[str, Any], data: dict[str, Any], event_id: str, timestamp: float) -> list[dict[str, Any]]:
        operation = self._text(data.get("operation") or data.get("action") or data.get("activity"), 32).upper()
        if operation not in {"CREATE", "WRITE", "MODIFY", "RENAME", "DELETE"}:
            self._ignored += 1
            return []
        tenant, host, scope, _ = self._scope(data)
        path = self._text(data.get("path") or data.get("new_path") or data.get("target"), 512)
        old_path = self._text(data.get("old_path"), 512)
        record = {"timestamp": timestamp, "operation": operation, "path": path, "old_path": old_path, "scope": scope}
        self._activity.append(record)
        self._expire(timestamp)
        recent = [row for row in self._activity if row["scope"] == scope and timestamp - row["timestamp"] <= self.file_window_seconds]
        writes = {row["path"] for row in recent if row["operation"] in {"CREATE", "WRITE", "MODIFY"} and row["path"]}
        renames = [row for row in recent if row["operation"] == "RENAME"]
        mutations = [row for row in recent if row["operation"] in {"CREATE", "WRITE", "MODIFY", "RENAME"}]
        detections: list[dict[str, Any]] = []
        note_like = bool(path and self.RANSOM_NOTE_RE.search(PurePath(path).name))
        if note_like and operation in {"CREATE", "WRITE", "MODIFY"}:
            self._record_signal(scope, "ransom_note", timestamp)
            detections.append(self._emit(
                kind="RANSOM_NOTE_LIKE_FILE", severity="MEDIUM", value=path,
                message="Ransom-note-like filename observed as one supporting signal.", category="ransom_note",
                event_type="FILE_ACTIVITY", event_id=event_id, timestamp=timestamp, data=data, confidence=0.60,
            ))
        if len(writes) >= self.mass_file_threshold:
            self._record_signal(scope, "mass_file_modification", timestamp)
            detections.append(self._emit(
                kind="MASS_FILE_MODIFICATION", severity="HIGH", value=len(writes),
                message=f"{len(writes)} distinct files modified inside the bounded activity window.", category="mass_file_modification",
                event_type="FILE_ACTIVITY", event_id=event_id, timestamp=timestamp, data=data, confidence=0.82,
            ))
        changed_extensions = sum(
            1 for row in renames
            if PurePath(row["old_path"]).suffix.lower() != PurePath(row["path"]).suffix.lower()
        )
        if len(renames) >= self.rename_burst_threshold and changed_extensions >= max(1, self.rename_burst_threshold // 2):
            self._record_signal(scope, "rapid_rename", timestamp)
            detections.append(self._emit(
                kind="RAPID_RENAME_BURST", severity="HIGH", value={"renames": len(renames), "extension_changes": changed_extensions},
                message="Rapid rename/extension-change burst observed inside the bounded activity window.", category="rapid_rename",
                event_type="FILE_ACTIVITY", event_id=event_id, timestamp=timestamp, data=data, confidence=0.84,
            ))
        if len(mutations) >= self.repeat_mutation_threshold:
            detections.append(self._emit(
                kind="REPEATED_FILE_MUTATION", severity="LOW", value=len(mutations),
                message="Repeated file write/rename activity observed; correlation is required.", category="repeated_mutation",
                event_type="FILE_ACTIVITY", event_id=event_id, timestamp=timestamp, data=data, confidence=0.45,
            ))
        combined = self._combined_detection(scope=scope, event_type="FILE_ACTIVITY", event_id=event_id, timestamp=timestamp, data=data)
        if combined:
            detections.append(combined)
        return detections

    def _file_indicator(self, event: dict[str, Any], data: dict[str, Any], event_id: str, timestamp: float) -> list[dict[str, Any]]:
        indicator_type = self._text(data.get("indicator_type") or data.get("type"), 32).upper()
        indicator = self._text(data.get("sha256") or data.get("indicator"), 128).lower()
        scope_name = self._text(data.get("scope"), 32).upper()
        if indicator_type not in {"SHA256", "SHA-256", "HASH"} or not self.HASH_RE.fullmatch(indicator):
            self._ignored += 1
            return []
        if scope_name != "LAB" or indicator not in self.lab_ioc_hashes:
            return []
        scope = self._scope(data)[2] or "threat:local:agent-local"
        self._record_signal(scope, "explicit_ioc", timestamp)
        detections = [self._emit(
            kind="EXPLICIT_LAB_IOC_MATCH", severity="HIGH", value={"indicator_type": "SHA256", "matched": True},
            message="Configured lab IOC/hash matched; this is evidence only and grants no authority.", category="explicit_ioc",
            event_type="FILE_INDICATOR", event_id=event_id, timestamp=timestamp, data=data, confidence=0.98,
        )]
        combined = self._combined_detection(scope=scope, event_type="FILE_INDICATOR", event_id=event_id, timestamp=timestamp, data=data)
        if combined:
            detections.append(combined)
        return detections

    def analyze_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(event, dict) or event.get("event_type") not in self.EVENT_TYPES:
            return []
        data = event.get("data")
        if not isinstance(data, dict):
            return []
        event_id = self._text(event.get("event_id"), 256) or "activity-unknown"
        timestamp = self._timestamp(event)
        self._expire(timestamp)
        event_type = event["event_type"]
        if event_type == "PROCESS_START":
            return self._process_start(event, data, event_id, timestamp)
        if event_type == "SCRIPT_ACTIVITY":
            return self._script_activity(event, data, event_id, timestamp)
        if event_type == "FILE_ACTIVITY":
            return self._file_activity(event, data, event_id, timestamp)
        return self._file_indicator(event, data, event_id, timestamp)

    def health_check(self) -> dict[str, Any]:
        return {
            "component": "ThreatSignalEngine",
            "version": self.VERSION,
            "status": "HEALTHY",
            "activity_events": len(self._activity),
            "signal_events": len(self._signals),
            "detections": self._detections,
            "ignored": self._ignored,
            "lab_ioc_count": len(self.lab_ioc_hashes),
            "fail_closed": True,
            "authorization": "NOT_GRANTED",
        }


__all__ = ["ThreatSignalEngine"]
