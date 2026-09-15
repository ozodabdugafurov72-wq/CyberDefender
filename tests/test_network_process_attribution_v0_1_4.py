from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import time

from agent.network.process_attribution import AsyncExecutableEnricher, ProcessAttributionResolver


failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"PASS | {message}")
    else:
        failures.append(message)
        print(f"FAIL | {message}")


def wait_until(predicate, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cd_proc_attr_") as td:
        exe = Path(td) / "fixture.exe"
        exe.write_bytes(b"CyberDefender process attribution fixture\n")
        expected = hashlib.sha256(exe.read_bytes()).hexdigest()

        def signature_reader(path: str):
            check(Path(path) == exe, "signature reader receives exact executable path")
            return {
                "status": "VALID",
                "signer_subject": "CN=CyberDefender Fixture",
                "raw_status": "Valid",
            }

        enricher = AsyncExecutableEnricher(signature_reader=signature_reader)

        def process_reader(pid: int):
            return {
                "pid": pid,
                "name": "fixture.exe",
                "exe": str(exe),
                "username": "LAB\\fixture",
                "create_time": 1234.5,
            }

        resolver = ProcessAttributionResolver(
            process_reader=process_reader,
            file_enricher=enricher,
        )

        first = resolver.resolve_pid(4242)
        check(first["attribution_status"] == "RESOLVED", "local PID attribution resolves without remote lookup")
        check(first["technical_name"] == "fixture.exe", "technical process name is retained")
        check(first["executable_path"] == str(exe), "full executable path is retained")
        check(first["create_time"] == 1234.5, "process create time binds PID instance")
        check(first["authority"] == "NONE" and first["authorization"] == "NOT_GRANTED", "process attribution cannot grant authority")
        check(first["file_identity"]["enrichment_status"] in {"PENDING", "COMPLETE"}, "file enrichment is asynchronous or already cached")

        check(wait_until(lambda: enricher.health_check()["completed"] >= 1), "bounded file enrichment worker completes")
        second = resolver.resolve_pid(4242)
        file_id = second["file_identity"]
        check(file_id["sha256_status"] == "VERIFIED", "SHA-256 is computed over the executable file")
        check(file_id["sha256"] == expected, "SHA-256 value matches independent fixture digest")
        check(file_id["signature"]["status"] == "VALID", "digital signature status is retained")
        check(file_id["signature"]["signer_subject"] == "CN=CyberDefender Fixture", "signer subject is retained")
        check(second["authorization"] == "NOT_GRANTED", "valid signature still does not authorize process or connection")

        pid_zero = resolver.resolve_pid(0)
        check(pid_zero["attribution_status"] == "PID_UNAVAILABLE", "PID 0/closed socket is not fabricated as a process")
        check(pid_zero["file_identity"]["sha256"] is None, "unavailable PID has no fabricated hash")

        health = resolver.health_check()
        check(health["authority"] == "NONE" and health["authorization"] == "NOT_GRANTED", "resolver health preserves non-authoritative boundary")
        check(health["file_enricher"]["external_network_io"] is False, "file enrichment performs no external network I/O")
        check(health["file_enricher"]["executes_target_binary"] is False, "file enrichment never executes target binary")

        resolver.close()
        check(enricher.health_check()["status"] == "STOPPED", "file enrichment worker closes deterministically")

    if failures:
        print(f"RESULT: FAIL={len(failures)}")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
