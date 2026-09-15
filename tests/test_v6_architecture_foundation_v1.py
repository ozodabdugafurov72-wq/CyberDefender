from __future__ import annotations

import ast
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.architecture.authority import AUTHORITY_MATRIX, authority_snapshot
from agent.architecture.boundaries import ALLOWED_TARGET_FLOW, FORBIDDEN_DIRECT_EDGES, TRUST_CROSSINGS, is_direct_edge_forbidden
from agent.architecture.constitution import SECURITY_CONSTITUTION, constitution_snapshot
from agent.architecture.status import V6_IMPLEMENTATION_STATUS, implementation_status_snapshot
from agent.action_gateway import ActionGateway
from agent.safety import SafetyCore
from agent.safety_authorization_gate import SafetyAuthorizationGate


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module)
    return found


def scan_tree_for_forbidden_imports(paths: list[Path], forbidden_prefixes: tuple[str, ...]) -> list[str]:
    violations: list[str] = []
    for base in paths:
        candidates = [base] if base.is_file() else sorted(base.rglob("*.py"))
        for path in candidates:
            if "__pycache__" in path.parts:
                continue
            for imported in imported_modules(path):
                if imported.startswith(forbidden_prefixes):
                    violations.append(f"{path.relative_to(ROOT)} -> {imported}")
    return violations


def main() -> None:
    constitution = constitution_snapshot()
    check(constitution["version"] == "6.0", "v6 Security Constitution version is canonical")
    check(len(SECURITY_CONSTITUTION) == 16, "Security Constitution has 16 explicit invariants")
    check(len({item.invariant_id for item in SECURITY_CONSTITUTION}) == 16, "constitution invariant IDs are unique")
    check(all(item.fail_closed for item in SECURITY_CONSTITUTION), "all constitution invariants default fail-closed")

    authority_before = copy.deepcopy(authority_snapshot())
    check(authority_before["real_world_executor_present"] is False, "current v6 authority matrix exposes no real-world executor")
    check(not any(profile.may_execute_real_world for profile in AUTHORITY_MATRIX.values()), "no current component has real-world execution authority")
    check(AUTHORITY_MATRIX["RiskEngine"].may_issue_dry_run_capability is False, "RiskEngine cannot issue capability")
    check(AUTHORITY_MATRIX["PolicyEngine"].may_issue_dry_run_capability is False, "PolicyEngine governs but cannot issue capability")
    check(AUTHORITY_MATRIX["AIGateway"].may_execute_real_world is False, "AI is advisory and has no execution authority")
    check(AUTHORITY_MATRIX["OwnerUI"].may_execute_dry_run is False and AUTHORITY_MATRIX["OwnerUI"].may_execute_real_world is False, "Owner UI is management plane, not execution authority")
    check(AUTHORITY_MATRIX["SafetyAuthorizationGate"].may_issue_dry_run_capability is True, "current capability issuer is explicitly DRY_RUN scoped")
    check(AUTHORITY_MATRIX["ActionGateway"].may_execute_dry_run is True, "current ActionGateway is modeled as dry-run executor only")

    check(is_direct_edge_forbidden("AI", "PRIVILEGED_EXECUTOR"), "AI -> privileged executor direct edge is forbidden")
    check(is_direct_edge_forbidden("OWNER_UI", "PRIVILEGED_EXECUTOR"), "Owner UI -> privileged executor direct edge is forbidden")
    check(is_direct_edge_forbidden("CLOUD_CONTROL", "PRIVILEGED_EXECUTOR"), "Cloud -> privileged executor direct edge is forbidden")
    check(is_direct_edge_forbidden("RECOVERY", "TRUST_RESTORATION"), "Recovery cannot directly declare trust restored")

    ordered = [
        "POLICY_ENGINE", "PRE_ACTION_INDEPENDENT_VERIFIER", "BLAST_RADIUS_GUARD",
        "LOCAL_SAFETY_CORE", "SHORT_LIVED_ACTION_CAPABILITY", "PRIVILEGE_SEPARATED_EXECUTOR",
        "POST_ACTION_INDEPENDENT_VERIFIER",
    ]
    positions = [ALLOWED_TARGET_FLOW.index(item) for item in ordered]
    check(positions == sorted(positions), "mandatory decision/response gates are ordered correctly")
    check("RE_ATTESTATION" in TRUST_CROSSINGS["RECOVERY_TO_TRUST"], "trust restoration requires re-attestation")
    check("SIGNED_PROMOTION" in TRUST_CROSSINGS["LEARNING_TO_PRODUCTION"], "learning cannot directly promote itself to production")

    safety = SafetyCore()
    safety_decision = safety.evaluate("PROCESS_TERMINATE")
    check(safety_decision.get("decision") == "DENY", "existing SafetyCore still denies privileged process termination")
    check(SafetyAuthorizationGate.PRIVILEGED_ACTIONS == ActionGateway.PRIVILEGED_ACTIONS, "dry-run authorization/gateway action vocabulary stays aligned")

    action_imports = imported_modules(ROOT / "agent" / "action_gateway.py")
    dangerous = {"subprocess", "winreg", "ctypes", "socket", "os"}
    check(not (action_imports & dangerous), "current ActionGateway has no direct OS mutation imports")

    boundary_violations = scan_tree_for_forbidden_imports(
        [ROOT / "dashboard_owner", ROOT / "agent" / "risk_engine.py", ROOT / "agent" / "attack_graph.py", ROOT / "agent" / "detection", ROOT / "agent" / "correlation"],
        ("agent.action_gateway", "agent.safety_authorization_gate"),
    )
    check(not boundary_violations, "management/intelligence code has no direct ActionGateway/authorization-gate import")

    status = implementation_status_snapshot()
    check(status["real_world_execution_available"] is False, "implementation reality map does not overclaim real execution")
    check(V6_IMPLEMENTATION_STATUS["device_attestation"] == "PLANNED", "device attestation is conservatively marked PLANNED")
    check(V6_IMPLEMENTATION_STATUS["production_family_mesh"] == "NOT_IMPLEMENTED", "Family Mesh is not falsely claimed as production")
    check(V6_IMPLEMENTATION_STATUS["distributed_ha_control_plane"] == "PLANNED", "distributed HA control plane is not falsely claimed current")

    authority_after = authority_snapshot()
    check(authority_before == authority_after, "architecture validation is side-effect free")
    check(len(FORBIDDEN_DIRECT_EDGES) >= 10, "explicit forbidden direct-edge set is non-trivial")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
