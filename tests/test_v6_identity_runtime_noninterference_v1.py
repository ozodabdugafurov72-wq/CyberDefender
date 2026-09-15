from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def main():
    runtime_files = [
        ROOT / "agent" / "main.py",
        ROOT / "agent" / "windows_service.py",
        ROOT / "agent" / "fleet" / "client.py",
        ROOT / "agent" / "action_gateway.py",
        ROOT / "agent" / "safety_authorization_gate.py",
        ROOT / "control_plane" / "windows_service.py",
        ROOT / "dashboard_owner" / "windows_service.py",
    ]
    check(all(path.is_file() for path in runtime_files), "runtime boundary files exist")
    leaked = []
    for path in runtime_files:
        for imported in imports(path):
            if imported == "agent.identity" or imported.startswith("agent.identity."):
                leaked.append(f"{path.relative_to(ROOT)} -> {imported}")
    check(not leaked, "Phase 1 identity is not silently integrated into running authority paths")

    identity_dir = ROOT / "agent" / "identity"
    dangerous = {"subprocess", "winreg", "ctypes", "socket", "urllib", "requests"}
    observed: set[str] = set()
    for path in identity_dir.glob("*.py"):
        observed.update(imports(path))
    check(not (observed & dangerous), "identity foundation has no OS/network execution imports")
    check("agent.action_gateway" not in observed, "identity foundation cannot call ActionGateway")
    check("agent.safety_authorization_gate" not in observed, "identity foundation cannot call authorization gate")

    windows_service = (ROOT / "agent" / "windows_service.py").read_text(encoding="utf-8-sig")
    fleet_client = (ROOT / "agent" / "fleet" / "client.py").read_text(encoding="utf-8-sig")
    check("identity\" / \"endpoint_id.txt" in windows_service, "legacy endpoint-id path remains explicit")
    check("CYBERDEFENDER_ENDPOINT_ID" in windows_service, "legacy endpoint-id environment bridge remains explicit")
    check("non-authoritative fleet telemetry client" in fleet_client.lower(), "fleet client remains explicitly non-authoritative")
    check("Device certificates/attestation replace the bootstrap" in fleet_client, "fleet client does not overclaim bearer-token identity as attestation")

    print("RESULT: PASS")


if __name__ == "__main__":
    main()
