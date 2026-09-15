from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import sys
import time

MAGIC = b"CDRQ"
VERSION = 1
HELLO = 1
SNAPSHOT = 2
SHUTDOWN = 3
REQ = struct.Struct("<4sHHQ")
EPOCH_TICKS = 116_444_736_000_000_000
PROVENANCE = {
    "exe": {"source": "QueryFullProcessImageNameW", "confidence": "HIGH"},
    "cmdline": {"source": "NtQueryInformationProcess+CommandLineToArgvW", "confidence": "HIGH_WHEN_COLLECTED"},
    "username": {"source": "OpenProcessToken+LookupAccountSidW", "confidence": "HIGH_WHEN_COLLECTED"},
    "sid": {"source": "OpenProcessToken+ConvertSidToStringSidW", "confidence": "HIGH_WHEN_COLLECTED"},
    "session_id": {"source": "ProcessIdToSessionId", "confidence": "HIGH_WHEN_COLLECTED"},
    "integrity_level": {"source": "TokenIntegrityLevel", "confidence": "HIGH_WHEN_COLLECTED"},
    "cpu_percent": {"source": "DEFERRED_TO_PERSISTENT_METRICS_TIER", "confidence": "NOT_AVAILABLE_V05_CORE"},
    "memory_percent": {"source": "DEFERRED_TO_PERSISTENT_METRICS_TIER", "confidence": "NOT_AVAILABLE_V05_CORE"},
}


def read_exact(size: int) -> bytes:
    raw = bytearray()
    while len(raw) < size:
        chunk = sys.stdin.buffer.read(size - len(raw))
        if not chunk:
            raise EOFError
        raw.extend(chunk)
    return bytes(raw)


def frame(data: dict) -> None:
    payload = (json.dumps(data, separators=(",", ":")) + "\n").encode()
    sys.stdout.buffer.write(struct.pack("<I", len(payload)))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def snapshot(seq: int, epoch: str, *, supervisor_pid: int = 999, sensor_pid: int = 1000) -> dict:
    now = time.time()
    ticks = EPOCH_TICKS + int(now * 10_000_000)
    statuses = {
        "exe": {"status": "COLLECTED"},
        "username": {"status": "COLLECTED"},
        "sid": {"status": "COLLECTED"},
        "cmdline": {"status": "COLLECTED"},
        "session_id": {"status": "COLLECTED"},
        "integrity_level": {"status": "COLLECTED"},
        "cpu_percent": {"status": "NOT_COLLECTED_V05_CORE"},
        "memory_percent": {"status": "NOT_COLLECTED_V05_CORE"},
    }
    return {
        "schema": "cd.process.v5",
        "sensor": "RustProcessSensor",
        "version": "0.5.1",
        "timestamp": now,
        "partial": False,
        "skipped": 0,
        "process_count": 1,
        "ipc": {
            "protocol": "cd.sensor.ipc.v1",
            "version": 1,
            "sequence": seq,
            "sensor_epoch": epoch,
            "supervisor_pid": supervisor_pid,
            "sensor_pid": sensor_pid,
        },
        "enrichment_provenance": PROVENANCE,
        "processes": [{
            "pid": 100,
            "ppid": 1,
            "name": "fake.exe",
            "create_time": (ticks - EPOCH_TICKS) / 10_000_000.0,
            "creation_filetime": str(ticks),
            "exe": "C:\\fake.exe",
            "username": "DOMAIN\\user",
            "cmdline": ["C:\\fake.exe", "--test"],
            "sid": "S-1-5-21-1",
            "session_id": 1,
            "integrity_level": "MEDIUM",
            "cpu_percent": None,
            "memory_percent": None,
            "enrichment_status": statuses,
        }],
        "skipped_processes": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crash-marker")
    parser.add_argument("--fault", choices=["wrong-sequence", "wrong-epoch", "wrong-nonce", "oversize", "malformed"])
    args = parser.parse_args()

    launch_nonce = os.environ.get("CYBERDEFENDER_SENSOR_LAUNCH_NONCE", "")
    supervisor_pid_text = os.environ.get("CYBERDEFENDER_SENSOR_SUPERVISOR_PID", "")
    if len(launch_nonce) != 64 or any(c not in "0123456789abcdef" for c in launch_nonce):
        return 12
    try:
        supervisor_pid = int(supervisor_pid_text)
    except ValueError:
        return 13
    if supervisor_pid <= 0:
        return 14

    sensor_pid = os.getpid()
    epoch = f"{time.time_ns()}-{sensor_pid}"
    last_seq = 0
    crashed = False
    marker = Path(args.crash_marker) if args.crash_marker else None

    while True:
        raw = read_exact(REQ.size)
        magic, version, op, seq = REQ.unpack(raw)
        if magic != MAGIC or version != VERSION or seq <= last_seq:
            return 9
        last_seq = seq

        if op == HELLO:
            frame({
                "schema": "cd.sensor.hello.v1",
                "protocol": "cd.sensor.ipc.v1",
                "version": 1,
                "sequence": seq,
                "sensor": "RustProcessSensor",
                "sensor_version": "0.5.1",
                "sensor_epoch": epoch,
                "sensor_pid": sensor_pid,
                "supervisor_pid": supervisor_pid,
                "launch_nonce": (launch_nonce + "bad") if args.fault == "wrong-nonce" else launch_nonce,
            })
        elif op == SNAPSHOT:
            if marker is not None and not marker.exists() and not crashed:
                marker.write_text("crashed", encoding="utf-8")
                crashed = True
                return 23
            if args.fault == "oversize":
                sys.stdout.buffer.write(struct.pack("<I", 12 * 1024 * 1024 + 1))
                sys.stdout.buffer.flush()
                time.sleep(2)
                continue
            if args.fault == "malformed":
                payload = b"{malformed-json"
                sys.stdout.buffer.write(struct.pack("<I", len(payload)))
                sys.stdout.buffer.write(payload)
                sys.stdout.buffer.flush()
                continue
            data = snapshot(seq, epoch, supervisor_pid=supervisor_pid, sensor_pid=sensor_pid)
            if args.fault == "wrong-sequence":
                data["ipc"]["sequence"] = seq + 1
            elif args.fault == "wrong-epoch":
                data["ipc"]["sensor_epoch"] = epoch + "-wrong"
            frame(data)
        elif op == SHUTDOWN:
            frame({
                "schema": "cd.sensor.goodbye.v1",
                "protocol": "cd.sensor.ipc.v1",
                "version": 1,
                "sequence": seq,
                "sensor_epoch": epoch,
            })
            return 0
        else:
            return 10


if __name__ == "__main__":
    raise SystemExit(main())
