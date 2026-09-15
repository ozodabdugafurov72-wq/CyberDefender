from __future__ import annotations

from pathlib import Path
import sys
import tempfile

from agent.sensors.native_process_supervisor import FramedSensorTransport, NativeSensorSupervisorError


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def fake() -> Path:
    return Path(__file__).resolve().parent / "support" / "fake_process_sensor_ipc_v1.py"


def main() -> int:
    target = fake()
    check(target.is_file(), "portable IPC fault sensor fixture exists")

    with FramedSensorTransport([sys.executable, str(target)], timeout=2.0, max_restarts=2) as sup:
        a = sup.snapshot(); b = sup.snapshot(); h = sup.health_check()
        check(a["ipc"]["sensor_epoch"] == b["ipc"]["sensor_epoch"], "persistent child keeps one sensor epoch")
        check(b["ipc"]["sequence"] > a["ipc"]["sequence"], "IPC sequence is strictly monotonic")
        check(h["status"] == "HEALTHY" and h["restart_count"] == 0, "happy path is persistent and restart-free")
        check(h["launch_binding_verified"] is True, "HELLO launch nonce is bound")

    wrong_nonce = FramedSensorTransport([sys.executable, str(target), "--fault", "wrong-nonce"], timeout=2.0, max_restarts=0)
    try:
        try: wrong_nonce.start()
        except NativeSensorSupervisorError: pass
        else: raise AssertionError("wrong launch nonce was accepted")
        check(wrong_nonce.health_check()["launch_binding_verified"] is False, "wrong launch nonce fails closed")
    finally:
        wrong_nonce.close()

    with tempfile.TemporaryDirectory(prefix="cd_ipc_restart_") as td:
        marker = Path(td) / "crashed.once"
        sup = FramedSensorTransport([sys.executable, str(target), "--crash-marker", str(marker)], timeout=2.0, max_restarts=2)
        try:
            sup.start(); before = sup.sensor_epoch
            try: sup.snapshot()
            except NativeSensorSupervisorError: pass
            after = sup.sensor_epoch
            check(before and after and before != after, "crash-only restart negotiates a new sensor epoch")
            check(sup.restart_count == 1, "controlled crash increments bounded restart counter")
            recovered = sup.snapshot()
            check(recovered["ipc"]["sensor_epoch"] == after, "post-crash snapshot is bound to new epoch")
            check(sup.health_check()["status"] == "HEALTHY", "supervisor recovers after controlled crash")
        finally:
            sup.close()

    for fault in ("wrong-sequence", "wrong-epoch", "oversize", "malformed"):
        sup = FramedSensorTransport([sys.executable, str(target), "--fault", fault], timeout=2.0, max_restarts=1)
        try:
            sup.start()
            try: sup.snapshot()
            except NativeSensorSupervisorError: pass
            else: raise AssertionError(f"{fault} response was accepted")
            check(sup.restart_count == 1, f"{fault} response triggers bounded restart")
        finally:
            sup.close()

    sup = FramedSensorTransport([sys.executable, str(target), "--fault", "malformed"], timeout=2.0, max_restarts=1)
    try:
        sup.start()
        for _ in range(2):
            try: sup.snapshot()
            except NativeSensorSupervisorError: pass
        h = sup.health_check()
        check(h["status"] == "DEGRADED", "restart budget exhaustion degrades only the supervisor")
        check(h["last_error"] == "RESTART_BUDGET_EXHAUSTED", "restart budget exhaustion is explicit")
    finally:
        sup.close()

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
