from __future__ import annotations

import json
from pathlib import Path
import sys

from agent.identity import (
    TrustState,
    build_local_identity_set,
    identity_foundation_snapshot,
    privileged_identity_decision,
)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_v6_identity_machine_context_v1.py <endpoint_id_file>")
    endpoint_file = Path(sys.argv[1])
    endpoint_id = endpoint_file.read_text(encoding="ascii").strip()
    if not endpoint_id:
        raise RuntimeError("legacy endpoint id is empty")

    device, workloads = build_local_identity_set(endpoint_id)
    snapshot = identity_foundation_snapshot(device, workloads)

    if device.trust_state is not TrustState.RESTRICTED:
        raise AssertionError("local identity unexpectedly trusted")
    if snapshot["all_bindings_valid"] is not True:
        raise AssertionError("local workload binding failed")
    if snapshot["privileged_authorization_eligible"] is not False:
        raise AssertionError("identity unexpectedly grants privileged authorization")
    if snapshot["runtime_authority"] != "NONE":
        raise AssertionError("identity unexpectedly has runtime authority")
    for workload in workloads:
        decision = privileged_identity_decision(device, workload)
        if decision.privileged_authorization_eligible:
            raise AssertionError("workload identity unexpectedly grants authority")

    print(json.dumps({
        "component": snapshot["component"],
        "version": snapshot["version"],
        "endpoint_id": endpoint_id,
        "scope_kind": snapshot["scope_kind"],
        "device_trust_state": snapshot["device_trust_state"],
        "workload_count": len(workloads),
        "all_bindings_valid": snapshot["all_bindings_valid"],
        "identity_is_authorization": snapshot["identity_is_authorization"],
        "runtime_authority": snapshot["runtime_authority"],
        "ok": True,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
