from __future__ import annotations

from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any


class SafetyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class SafetyReason(str, Enum):
    SAFE_MODE = "SAFE_MODE"
    SHUTDOWN_REQUESTED = "SHUTDOWN_REQUESTED"
    PROTECTED_PATH = "PROTECTED_PATH"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"
    SYSTEM_MODIFICATION_DISABLED = (
        "SYSTEM_MODIFICATION_DISABLED"
    )
    INVALID_PATH = "INVALID_PATH"
    SAFETY_POLICY = "SAFETY_POLICY"


class SafetyCore:
    """
    CyberDefender Security-First Safety Boundary.

    Security principles:

    1. Fail-closed:
       Unknown or unsafe operations are denied.

    2. No autonomous privileged modification:
       CyberDefender cannot directly modify:
         - operating system
         - firewall
         - registry
         - services

    3. Safe Mode:
       Once entered, security-sensitive operations remain denied.

    4. Protected paths:
       Critical operating-system paths are protected.

    5. Central decision boundary:
       Runtime components must ask SafetyCore before
       attempting security-sensitive actions.

    6. AI boundary:
       AI output is never treated as a trusted security
       decision and cannot bypass this class.

    7. Thread-safe state:
       Safety state transitions are protected by a lock.

    This class does NOT itself modify the operating system.
    It is a defensive authorization boundary.
    """

    VERSION = "2.2"

    PROTECTED_PATHS = (
        Path("C:/Windows"),
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
        Path("C:/ProgramData"),
    )

    # Explicitly deny all privileged modification classes.
    DENIED_OPERATIONS = frozenset(
        {
            "SYSTEM_MODIFY",
            "FIREWALL_MODIFY",
            "REGISTRY_MODIFY",
            "SERVICE_MODIFY",
            "PROCESS_TERMINATE",
            "PROCESS_SUSPEND",
            "DRIVER_INSTALL",
            "DRIVER_MODIFY",
            "SECURITY_POLICY_MODIFY",
            "BOOT_MODIFY",
        }
    )

    def __init__(self) -> None:
        self._lock = RLock()

        self.safe_mode = False
        self.shutdown_requested = False

        self._safe_mode_reason: str | None = None
        self._decision_count = 0
        self._deny_count = 0

    # =========================================================
    # SAFE MODE
    # =========================================================

    def enter_safe_mode(
        self,
        reason: str,
    ) -> None:
        """
        Enter fail-safe state.

        Safe mode is sticky for the lifetime of this
        SafetyCore instance.
        """

        with self._lock:
            self.safe_mode = True
            self._safe_mode_reason = str(
                reason or "Unknown reason"
            )

        print(
            f"[SAFE MODE] {self._safe_mode_reason}"
        )

    def is_safe_mode(self) -> bool:
        with self._lock:
            return self.safe_mode

    def safe_mode_reason(self) -> str | None:
        with self._lock:
            return self._safe_mode_reason

    # =========================================================
    # SHUTDOWN
    # =========================================================

    def request_shutdown(self) -> None:
        """
        Request CyberDefender agent shutdown.

        This method NEVER shuts down or restarts Windows.
        """

        with self._lock:
            self.shutdown_requested = True

    def is_shutdown_requested(self) -> bool:
        with self._lock:
            return self.shutdown_requested

    # =========================================================
    # LEGACY CAPABILITY CHECKS
    # =========================================================

    def can_modify_system(self) -> bool:
        return False

    def can_modify_firewall(self) -> bool:
        return False

    def can_modify_registry(self) -> bool:
        return False

    def can_modify_services(self) -> bool:
        return False

    # =========================================================
    # UNIFIED SECURITY DECISION
    # =========================================================

    def evaluate(
        self,
        operation: str,
        *,
        path: str | Path | None = None,
    ) -> dict[str, Any]:
        """
        Central SafetyCore decision boundary.

        Unknown operations are DENIED.

        Returns a JSON-safe decision record.
        """

        operation_name = str(
            operation or ""
        ).strip().upper()

        with self._lock:
            self._decision_count += 1

            if self.safe_mode:
                self._deny_count += 1

                return self._decision(
                    SafetyDecision.DENY,
                    SafetyReason.SAFE_MODE,
                    operation_name,
                    path,
                )

            if self.shutdown_requested:
                self._deny_count += 1

                return self._decision(
                    SafetyDecision.DENY,
                    SafetyReason.SHUTDOWN_REQUESTED,
                    operation_name,
                    path,
                )

            if not operation_name:
                self._deny_count += 1

                return self._decision(
                    SafetyDecision.DENY,
                    SafetyReason.UNKNOWN_OPERATION,
                    operation_name,
                    path,
                )

            if operation_name in self.DENIED_OPERATIONS:
                self._deny_count += 1

                return self._decision(
                    SafetyDecision.DENY,
                    self._reason_for_operation(
                        operation_name
                    ),
                    operation_name,
                    path,
                )

            if path is not None:
                if self.is_protected_path(path):
                    self._deny_count += 1

                    return self._decision(
                        SafetyDecision.DENY,
                        SafetyReason.PROTECTED_PATH,
                        operation_name,
                        path,
                    )

            # IMPORTANT:
            # We do not automatically allow arbitrary operations.
            # The current SafetyCore is intentionally conservative.
            self._deny_count += 1

            return self._decision(
                SafetyDecision.DENY,
                SafetyReason.SAFETY_POLICY,
                operation_name,
                path,
            )

    # =========================================================
    # OPERATION-SPECIFIC HELPERS
    # =========================================================

    def can_execute(
        self,
        operation: str,
        *,
        path: str | Path | None = None,
    ) -> bool:
        decision = self.evaluate(
            operation,
            path=path,
        )

        return (
            decision["decision"]
            == SafetyDecision.ALLOW.value
        )

    def can_modify_path(
        self,
        path: str | Path,
    ) -> bool:
        """
        Current policy: modification is disabled.

        This method exists as a single gate for future
        recovery/quarantine/update components.
        """

        if self.is_protected_path(path):
            return False

        return False

    def authorize_lab_quarantine(
        self,
        scope: dict[str, Any],
    ) -> dict[str, Any]:
        """Authorize only the explicitly bounded Quarantine v2 lab canary.

        This is a separate lab capability boundary. It never changes the
        production ``evaluate`` contract and never grants production
        authorization.
        """
        try:
            from agent.quarantine.contracts import (
                CANARY_MARKER,
                CANARY_MARKER_FILENAME,
                LAB_CANARY_EXECUTION,
                canonical_scope_digest,
            )

            if not isinstance(scope, dict):
                raise ValueError("scope must be a dict")
            required = (
                "incident_id", "requested_action", "idempotency_key", "target", "approved_root",
                "target_sha256", "requester", "evidence_ref", "decision_digest",
                "mode", "canary_marker",
            )
            if any(not isinstance(scope.get(key), str) or not scope[key].strip() for key in required):
                raise ValueError("lab scope incomplete")
            if (scope["requested_action"] != "QUARANTINE" or scope["mode"] != LAB_CANARY_EXECUTION
                    or scope["canary_marker"] != CANARY_MARKER):
                raise ValueError("lab canary contract mismatch")
            for field in ("target_sha256", "decision_digest"):
                value = scope[field].lower()
                if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                    raise ValueError("lab digest invalid")

            with self._lock:
                if self.safe_mode:
                    raise PermissionError("SAFETY_CORE_SAFE_MODE")
                if self.shutdown_requested:
                    raise PermissionError("SAFETY_CORE_SHUTDOWN_REQUESTED")

            root = Path(scope["approved_root"]).expanduser().resolve(strict=True)
            target = Path(scope["target"]).expanduser().resolve(strict=True)
            marker = root / CANARY_MARKER_FILENAME
            target.relative_to(root)
            if self.is_protected_path(root) or self.is_protected_path(target):
                raise PermissionError("PROTECTED_PATH")
            if root.is_symlink() or target.is_symlink() or not root.is_dir() or not target.is_file():
                raise PermissionError("LAB_PATH_INVALID")
            if not marker.is_file() or marker.is_symlink() or marker.read_bytes() != CANARY_MARKER.encode("utf-8"):
                raise PermissionError("LAB_CANARY_MARKER_INVALID")

            return {
                "component": "SafetyCore",
                "version": self.VERSION,
                "allowed": True,
                "mode": LAB_CANARY_EXECUTION,
                "scope_digest": canonical_scope_digest(scope),
                "production_authorization": "NOT_GRANTED",
                "lab_authorization": "QUARANTINE_CAPABILITY_CONSUMED",
                "real_world_effect_scope": "ONE_LAB_FILE_ONLY",
                "fail_closed": True,
            }
        except Exception as exc:
            return {
                "component": "SafetyCore",
                "version": self.VERSION,
                "allowed": False,
                "mode": "LAB_CANARY_EXECUTION",
                "reason": type(exc).__name__,
                "fail_closed": True,
                "production_authorization": "NOT_GRANTED",
            }

    # =========================================================
    # PROTECTED PATH
    # =========================================================

    def is_protected_path(
        self,
        path: str | Path,
    ) -> bool:
        """
        Determine whether a path belongs to a protected
        operating-system area.

        Fail-closed:
        any path-resolution failure is treated as protected.
        """

        try:
            target = Path(path).expanduser().resolve(
                strict=False
            )

        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
        ):
            return True

        for protected in self.PROTECTED_PATHS:
            try:
                protected_path = (
                    protected.expanduser().resolve(
                        strict=False
                    )
                )

                target.relative_to(
                    protected_path
                )

                return True

            except ValueError:
                continue

            except (
                OSError,
                RuntimeError,
                TypeError,
            ):
                return True

        return False

    # =========================================================
    # DECISION RECORD
    # =========================================================

    def _decision(
        self,
        decision: SafetyDecision,
        reason: SafetyReason,
        operation: str,
        path: str | Path | None,
    ) -> dict[str, Any]:
        return {
            "decision": decision.value,
            "reason": reason.value,
            "operation": operation,
            "path": (
                str(path)
                if path is not None
                else None
            ),
            "safe_mode": self.safe_mode,
            "shutdown_requested": (
                self.shutdown_requested
            ),
            "version": self.VERSION,
        }

    @staticmethod
    def _reason_for_operation(
        operation: str,
    ) -> SafetyReason:
        mapping = {
            "SYSTEM_MODIFY":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "FIREWALL_MODIFY":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "REGISTRY_MODIFY":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "SERVICE_MODIFY":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "PROCESS_TERMINATE":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "PROCESS_SUSPEND":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "DRIVER_INSTALL":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "DRIVER_MODIFY":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "SECURITY_POLICY_MODIFY":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,

            "BOOT_MODIFY":
                SafetyReason.SYSTEM_MODIFICATION_DISABLED,
        }

        return mapping.get(
            operation,
            SafetyReason.UNKNOWN_OPERATION,
        )

    # =========================================================
    # HEALTH / DIAGNOSTICS
    # =========================================================

    def health_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": "SafetyCore",
                "version": self.VERSION,
                "status": "SAFE",
                "safe_mode": self.safe_mode,
                "shutdown_requested": (
                    self.shutdown_requested
                ),
                "safe_mode_reason": (
                    self._safe_mode_reason
                ),
                "decision_count": (
                    self._decision_count
                ),
                "deny_count": (
                    self._deny_count
                ),
                "fail_closed": True,
                "system_modification": False,
                "firewall_modification": False,
                "registry_modification": False,
                "service_modification": False,
                "process_termination": False,
            }
