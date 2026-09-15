from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import secrets
import struct
import subprocess
import threading
import time
from typing import Any

from agent.sensors.rust_process_v05_contract import MAX_BYTES, RustProcessV05Error, validate_v05_snapshot

IPC_MAGIC = b"CDRQ"
IPC_VERSION = 1
IPC_OP_HELLO = 1
IPC_OP_SNAPSHOT = 2
IPC_OP_SHUTDOWN = 3
REQUEST_STRUCT = struct.Struct("<4sHHQ")


class NativeSensorSupervisorError(RuntimeError):
    pass


def _strict_json(raw: bytes) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise NativeSensorSupervisorError("duplicate IPC JSON key")
            out[key] = value
        return out

    try:
        data = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=hook)
    except NativeSensorSupervisorError:
        raise
    except Exception as exc:
        raise NativeSensorSupervisorError("invalid IPC JSON") from exc
    if not isinstance(data, dict):
        raise NativeSensorSupervisorError("IPC payload is not an object")
    return data


class FramedSensorTransport:
    """Bounded persistent child transport.

    Security properties:
      - shell=False;
      - no inherited stdin from operator;
      - stderr discarded;
      - fixed-size request frames;
      - length-prefixed bounded response frames;
      - one reader thread per child generation;
      - exact request/response sequence matching;
      - sensor epoch pinning within one generation;
      - bounded restart budget.
    """

    VERSION = "1.0"

    def __init__(
        self,
        command: list[str],
        *,
        timeout: float = 5.0,
        max_frame_bytes: int = MAX_BYTES,
        max_restarts: int = 3,
        restart_window_seconds: float = 60.0,
        require_direct_child_pid: bool = False,
    ) -> None:
        if not command or not all(isinstance(x, str) and x for x in command):
            raise ValueError("explicit command required")
        if not 0 < timeout <= 30:
            raise ValueError("invalid timeout")
        if not 0 < max_frame_bytes <= MAX_BYTES:
            raise ValueError("invalid frame bound")
        if not 0 <= max_restarts <= 10:
            raise ValueError("invalid restart bound")
        if not 1 <= restart_window_seconds <= 600:
            raise ValueError("invalid restart window")

        self.command = list(command)
        self.timeout = float(timeout)
        self.max_frame_bytes = int(max_frame_bytes)
        self.max_restarts = int(max_restarts)
        self.restart_window_seconds = float(restart_window_seconds)
        self.require_direct_child_pid = bool(require_direct_child_pid)

        self.child: subprocess.Popen[bytes] | None = None
        self.reader: threading.Thread | None = None
        self.responses: queue.Queue[tuple[int, bytes | Exception]] = queue.Queue(maxsize=4)
        self.stop_event = threading.Event()
        self.io_lock = threading.RLock()

        self.generation = 0
        self.sequence = 0
        self.sensor_epoch: str | None = None
        self.child_pid: int | None = None
        self.sensor_pid: int | None = None
        self.supervisor_pid = os.getpid()
        self._launch_nonce: str | None = None
        self._launch_binding_verified = False
        self._direct_pid_verified = False
        self.status = "NOT_STARTED"
        self.requests = 0
        self.failures = 0
        self.restart_count = 0
        self.last_error: str | None = None
        self.launch_attempts = 0
        self._retry_debits = 0
        self.exhausted = False
        self._closed = False
        self._healthy_since: float | None = None

    def _admit_launch(self) -> None:
        """One initial attempt; every subsequent attempt is debited before spawn.

        Exhaustion is terminal for this owner. Time alone cannot reset it.
        A still-running child may replenish retries only after validated useful
        snapshots span the stability window. Cumulative evidence never resets.
        """
        if self._closed:
            raise NativeSensorSupervisorError("SUPERVISOR_CLOSED")
        if self.exhausted or (self.launch_attempts and self._retry_debits >= self.max_restarts):
            self.exhausted = True
            self.status = "DEGRADED"
            self.last_error = "RESTART_BUDGET_EXHAUSTED"
            raise NativeSensorSupervisorError("native sensor restart budget exhausted")
        if self.launch_attempts:
            self._retry_debits += 1
            self.restart_count += 1
        self.launch_attempts += 1
        self._healthy_since = None

    @staticmethod
    def _read_exact(stream: Any, size: int) -> bytes:
        raw = bytearray()
        while len(raw) < size:
            chunk = stream.read(size - len(raw))
            if not chunk:
                raise EOFError("IPC EOF")
            raw.extend(chunk)
        return bytes(raw)

    def _reader_loop(self, generation: int, child: Any, stop_event: threading.Event,
                     responses: queue.Queue) -> None:
        try:
            if child.stdout is None:
                raise NativeSensorSupervisorError("child stdout unavailable")
            while not stop_event.is_set():
                header = self._read_exact(child.stdout, 4)
                size = struct.unpack("<I", header)[0]
                if not 0 < size <= self.max_frame_bytes:
                    raise NativeSensorSupervisorError("IPC frame length rejected")
                payload = self._read_exact(child.stdout, size)
                try:
                    responses.put((generation, payload), timeout=0.1)
                except queue.Full as exc:
                    raise NativeSensorSupervisorError("IPC response queue overflow") from exc
        except Exception as exc:
            try:
                responses.put((generation, exc), timeout=0.1)
            except queue.Full:
                pass

    def _spawn(self) -> None:
        self._terminate_child()
        self._admit_launch()
        self.stop_event = threading.Event()
        self.responses = queue.Queue(maxsize=4)
        launch_nonce = secrets.token_hex(32)
        from agent.sensors.windows_child_containment import sensor_environment
        child_env = sensor_environment(launch_nonce, self.supervisor_pid)
        try:
            child = self._create_child(child_env)
        except OSError as exc:
            self.failures += 1
            self.status = "DEGRADED"
            self.last_error = "SPAWN_FAILED"
            raise NativeSensorSupervisorError("native sensor could not start") from exc

        self.child = child
        self.child_pid = child.pid
        if child.stdin is None or child.stdout is None:
            self._terminate_child()
            raise NativeSensorSupervisorError("native sensor pipes unavailable")
        self.sensor_pid = None
        self._launch_nonce = launch_nonce
        self._launch_binding_verified = False
        self._direct_pid_verified = False
        self.generation += 1
        self.sequence = 0
        self.sensor_epoch = None
        self.status = "STARTING"
        self.reader = threading.Thread(
            target=self._reader_loop,
            args=(self.generation, child, self.stop_event, self.responses),
            daemon=True,
        )
        self.reader.start()

        try:
            hello = self._request(IPC_OP_HELLO, allow_restart=False)
            expected_hello_keys = {
                "schema",
                "protocol",
                "version",
                "sequence",
                "sensor",
                "sensor_version",
                "sensor_epoch",
                "sensor_pid",
                "supervisor_pid",
                "launch_nonce",
            }
            if set(hello) != expected_hello_keys:
                raise NativeSensorSupervisorError("HELLO schema expansion/missing field")
            if hello.get("schema") != "cd.sensor.hello.v1":
                raise NativeSensorSupervisorError("HELLO schema mismatch")
            if hello.get("protocol") != "cd.sensor.ipc.v1" or hello.get("version") != 1:
                raise NativeSensorSupervisorError("HELLO protocol mismatch")
            if hello.get("sequence") != self.sequence:
                raise NativeSensorSupervisorError("HELLO sequence mismatch")
            if hello.get("sensor") != "RustProcessSensor" or hello.get("sensor_version") != "0.5.1":
                raise NativeSensorSupervisorError("HELLO sensor mismatch")
            epoch = hello.get("sensor_epoch")
            if not isinstance(epoch, str) or not epoch or len(epoch) > 128:
                raise NativeSensorSupervisorError("HELLO epoch invalid")
            sensor_pid = hello.get("sensor_pid")
            if type(sensor_pid) is not int or sensor_pid <= 0:
                raise NativeSensorSupervisorError("HELLO sensor PID invalid")
            if hello.get("supervisor_pid") != self.supervisor_pid:
                raise NativeSensorSupervisorError("HELLO supervisor PID mismatch")
            if hello.get("launch_nonce") != self._launch_nonce:
                raise NativeSensorSupervisorError("HELLO launch nonce mismatch")
            self._launch_binding_verified = True
            self.sensor_pid = sensor_pid
            if self.require_direct_child_pid:
                if sensor_pid != self.child_pid:
                    raise NativeSensorSupervisorError("HELLO direct child PID mismatch")
                self._direct_pid_verified = True
            self.sensor_epoch = epoch
            self.status = "HEALTHY"
            self.last_error = None
        except Exception as exc:
            self.failures += 1
            self.status = "DEGRADED"
            self.last_error = f"HELLO:{type(exc).__name__}"
            self._terminate_child()
            raise

    def _create_child(self, env: dict[str, str]) -> Any:
        return subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, shell=False, bufsize=0, env=env)

    def start(self) -> None:
        with self.io_lock:
            if self._closed:
                raise NativeSensorSupervisorError("SUPERVISOR_CLOSED")
            if self.child is not None and self.child.poll() is None and self.status == "HEALTHY":
                return
            self._terminate_child()
            self._spawn()

    def _request(self, op: int, *, allow_restart: bool) -> dict[str, Any]:
        child = self.child
        if child is None or child.stdin is None or child.poll() is not None:
            if allow_restart:
                self._restart("CHILD_NOT_RUNNING")
                child = self.child
            else:
                raise NativeSensorSupervisorError("native sensor is not running")
        if child is None or child.stdin is None:
            raise NativeSensorSupervisorError("native sensor unavailable")

        self.sequence += 1
        sequence = self.sequence
        frame = REQUEST_STRUCT.pack(IPC_MAGIC, IPC_VERSION, op, sequence)
        try:
            child.stdin.write(frame)
            child.stdin.flush()
        except Exception as exc:
            if allow_restart:
                self._restart(f"WRITE:{type(exc).__name__}")
                return self._request(op, allow_restart=False)
            raise NativeSensorSupervisorError("IPC write failed") from exc

        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if allow_restart:
                    self._restart("TIMEOUT")
                raise NativeSensorSupervisorError("IPC response timeout")
            try:
                generation, item = self.responses.get(timeout=remaining)
            except queue.Empty as exc:
                if allow_restart:
                    self._restart("TIMEOUT")
                raise NativeSensorSupervisorError("IPC response timeout") from exc
            if generation != self.generation:
                continue
            if isinstance(item, Exception):
                if allow_restart:
                    self._restart(f"READER:{type(item).__name__}")
                raise NativeSensorSupervisorError("IPC reader failed") from item
            self.requests += 1
            try:
                payload = _strict_json(item)
            except Exception as exc:
                if allow_restart:
                    self._restart("INVALID_JSON")
                raise NativeSensorSupervisorError("IPC JSON validation failed") from exc
            if payload.get("schema") == "cd.process.v5":
                response_sequence = (
                    payload.get("ipc", {}).get("sequence")
                    if isinstance(payload.get("ipc"), dict)
                    else None
                )
            else:
                response_sequence = payload.get("sequence")
            if response_sequence != sequence:
                if allow_restart:
                    self._restart("SEQUENCE_MISMATCH")
                raise NativeSensorSupervisorError("IPC response sequence mismatch")
            return payload

    def snapshot(self) -> dict[str, Any]:
        with self.io_lock:
            if self._closed:
                raise NativeSensorSupervisorError("SUPERVISOR_CLOSED")
            if self.child is None:
                self._spawn()
            elif self.child.poll() is not None:
                self._restart("CHILD_EXITED")
            elif self.status != "HEALTHY":
                self._restart("SUPERVISOR_NOT_HEALTHY")
            payload = self._request(IPC_OP_SNAPSHOT, allow_restart=True)
            try:
                snapshot = validate_v05_snapshot(
                    payload,
                    require_ipc=True,
                    expected_sequence=self.sequence,
                    expected_epoch=self.sensor_epoch,
                    expected_supervisor_pid=self.supervisor_pid,
                    expected_sensor_pid=self.sensor_pid,
                )
            except RustProcessV05Error as exc:
                self.failures += 1
                self.last_error = "SNAPSHOT_VALIDATION_FAILED"
                self.status = "DEGRADED"
                self._restart("VALIDATION_FAILED")
                raise NativeSensorSupervisorError("validated snapshot rejected") from exc
            self.status = "HEALTHY"
            self.last_error = None
            now = time.monotonic()
            if self._healthy_since is None:
                self._healthy_since = now
            elif now - self._healthy_since >= self.restart_window_seconds:
                self._retry_debits = 0
            return snapshot

    def _restart(self, reason: str) -> None:
        previous_epoch = self.sensor_epoch
        self.failures += 1
        self._healthy_since = None
        self.last_error = reason[:256]
        self._terminate_child()
        self._spawn()
        if previous_epoch is not None and self.sensor_epoch == previous_epoch:
            self.status = "DEGRADED"
            self._terminate_child()
            raise NativeSensorSupervisorError("sensor epoch did not change after restart")

    def _terminate_child(self) -> None:
        child = self.child
        self.stop_event.set()
        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()
                except Exception:
                    pass
            try:
                child.wait(timeout=1)
            except Exception:
                pass
            if child.poll() is None:
                self.status = "DEGRADED"
                self.last_error = "CHILD_EXIT_NOT_VERIFIED"
                raise NativeSensorSupervisorError("CHILD_EXIT_NOT_VERIFIED")
            for stream in (child.stdin, child.stdout):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
        reader = self.reader
        if reader is not None and reader.is_alive():
            reader.join(timeout=1)
            if reader.is_alive():
                self.status = "DEGRADED"
                self.last_error = "READER_EXIT_NOT_VERIFIED"
                raise NativeSensorSupervisorError("READER_EXIT_NOT_VERIFIED")
        if child is not None and hasattr(child, "release"):
            child.release()
        self.child = None
        self.reader = None
        self.child_pid = None
        self.sensor_pid = None
        self._launch_nonce = None
        self._launch_binding_verified = False
        self._direct_pid_verified = False

    def close(self) -> None:
        with self.io_lock:
            self._closed = True
            child = self.child
            if child is not None and child.poll() is None and child.stdin is not None:
                try:
                    self._request(IPC_OP_SHUTDOWN, allow_restart=False)
                    child.wait(timeout=1)
                except Exception:
                    pass
            self._terminate_child()
            if self.status != "DEGRADED":
                self.status = "STOPPED"

    def health_check(self) -> dict[str, Any]:
        child_alive = self.child is not None and self.child.poll() is None
        return {
            "component": "NativeProcessSensorSupervisor",
            "version": self.VERSION,
            "status": self.status,
            "protocol": "cd.sensor.ipc.v1",
            "generation": self.generation,
            "sequence": self.sequence,
            "sensor_epoch": self.sensor_epoch,
            "child_pid": self.child_pid,
            "sensor_pid": self.sensor_pid,
            "supervisor_pid": self.supervisor_pid,
            "launch_binding_verified": self._launch_binding_verified,
            "direct_pid_required": self.require_direct_child_pid,
            "direct_pid_verified": self._direct_pid_verified,
            "child_alive": child_alive,
            "requests": self.requests,
            "failures": self.failures,
            "restart_count": self.restart_count,
            "launch_attempts": self.launch_attempts,
            "retry_debits": self._retry_debits,
            "exhausted": self.exhausted,
            "closed": self._closed,
            "max_restarts": self.max_restarts,
            "restart_window_seconds": self.restart_window_seconds,
            "last_error": self.last_error,
        }

    def __enter__(self) -> "FramedSensorTransport":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


class NativeProcessSensorSupervisor(FramedSensorTransport):
    """Production-shaped wrapper for one explicit Rust v0.5 executable."""

    def __init__(self, executable: str | Path, *, expected_sha256: str, **kwargs: Any) -> None:
        path = Path(executable).expanduser().resolve()
        if not path.is_absolute() or not path.is_file():
            raise ValueError("explicit existing absolute Rust executable required")
        self.executable = path
        if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
            raise ValueError("expected SHA-256 pin required")
        self.expected_sha256 = expected_sha256
        kwargs["require_direct_child_pid"] = True
        super().__init__([str(path), "--ipc"], **kwargs)

    def _create_child(self, env: dict[str, str]) -> Any:
        from agent.sensors.windows_child_containment import launch_contained, verified_binary
        with verified_binary(self.executable, self.expected_sha256):
            return launch_contained(self.command, env)
