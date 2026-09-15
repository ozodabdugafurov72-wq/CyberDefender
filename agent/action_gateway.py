from __future__ import annotations

"""CyberDefender Action Gateway v1 — dry-run only.

The gateway has no OS executor in v1. It consumes only a capability issued by
SafetyAuthorizationGate and returns a deterministic simulation result. No
subprocess, PowerShell, registry, firewall, service, driver, or network action
is invoked.
"""

from threading import RLock
from typing import Any

from agent.safety_authorization_gate import SafetyAuthorizationGate


class ActionGatewayError(Exception):
    pass


class ActionGateway:
    VERSION = "1.0"
    PRIVILEGED_ACTIONS = SafetyAuthorizationGate.PRIVILEGED_ACTIONS

    def __init__(self, authorization_gate: SafetyAuthorizationGate) -> None:
        if not isinstance(authorization_gate, SafetyAuthorizationGate):
            raise TypeError("authorization_gate must be SafetyAuthorizationGate")
        self.name = "ActionGateway"
        self.authorization_gate = authorization_gate
        self._lock = RLock()
        self.executions = 0
        self.simulations = 0
        self.rejected = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_result: dict[str, Any] | None = None

    def execute_dry_run(self, authorization: dict[str, Any], *, request: dict[str, Any]) -> dict[str, Any]:
        try:
            if not isinstance(authorization, dict) or not isinstance(request, dict):
                raise ActionGatewayError("authorization/request must be dict")
            if authorization.get("authorization") != "DRY_RUN_ONLY":
                raise ActionGatewayError("only DRY_RUN_ONLY authorization accepted")
            if authorization.get("execution_mode") != "DRY_RUN":
                raise ActionGatewayError("dry-run execution mode required")
            if authorization.get("real_world_effect") is not False:
                raise ActionGatewayError("authorization is not marked non-mutating")
            token_id = authorization.get("token_id")
            if not isinstance(token_id, str) or not token_id:
                raise ActionGatewayError("token_id missing")
            token_mac = authorization.get("token_mac")
            consumed = self.authorization_gate.consume(token_id, request=request, token_mac=token_mac)
            if consumed.get("accepted") is not True:
                with self._lock:
                    self.rejected += 1
                return {
                    "component": self.name, "version": self.VERSION,
                    "accepted": False, "executed": False,
                    "simulated": False, "real_world_effect": False,
                    "reason": consumed.get("reason", "AUTHORIZATION_REJECTED"),
                    "fail_closed": True,
                }
            scope = consumed["scope"]
            action = scope["requested_action"]
            if action not in self.PRIVILEGED_ACTIONS:
                raise ActionGatewayError("unsupported action")
            result = {
                "component": self.name, "version": self.VERSION,
                "accepted": True, "executed": False, "simulated": True,
                "execution_mode": "DRY_RUN", "real_world_effect": False,
                "action": action, "target": scope["target"],
                "incident_id": scope["incident_id"],
                "authorization_token_id": token_id,
                "executor": "NO_OP_DRY_RUN_EXECUTOR",
                "verification_required": True,
                "post_action_verification": False,
            }
            with self._lock:
                self.executions += 1
                self.simulations += 1
                self.last_result = result
            return result
        except ActionGatewayError as exc:
            with self._lock:
                self.rejected += 1
            return {
                "component": self.name, "version": self.VERSION,
                "accepted": False, "executed": False, "simulated": False,
                "real_world_effect": False, "reason": type(exc).__name__,
                "detail": str(exc), "fail_closed": True,
            }
        except Exception as exc:
            with self._lock:
                self.failed += 1
                self.last_error = str(exc)
            return {
                "component": self.name, "version": self.VERSION,
                "accepted": False, "executed": False, "simulated": False,
                "real_world_effect": False, "reason": "GATEWAY_ERROR",
                "error": type(exc).__name__, "fail_closed": True,
            }

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {
                "component": self.name, "version": self.VERSION,
                "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                "executions": self.executions,
                "simulations": self.simulations,
                "rejected": self.rejected,
                "failed": self.failed,
                "last_error": self.last_error,
                "fail_closed": True,
                "dry_run_only": True,
                "real_world_effect": False,
            }

    get_stats = health_check
