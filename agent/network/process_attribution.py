from __future__ import annotations

import copy
import hashlib
import json
import os
import queue
import subprocess
import threading
import time
from collections import OrderedDict
from typing import Any, Callable

try:
    import psutil
except Exception:  # pragma: no cover - health surfaces dependency absence
    psutil = None


def _bounded_text(value: Any, limit: int = 256) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def _normalized_path(value: Any) -> str | None:
    text = _bounded_text(value, 4096)
    if not text:
        return None
    try:
        return os.path.normcase(os.path.abspath(text))
    except Exception:
        return text


class AsyncExecutableEnricher:
    """One-worker, bounded executable hash/signature enrichment cache.

    This worker is observability-only. It never grants process/network trust,
    never executes the target binary, and never performs external network I/O.
    Unknown/pending/failed enrichment is not interpreted as malicious or trusted.
    """

    VERSION = "0.1.4"
    AUTHORITY = "NONE"
    MAX_QUEUE = 16
    MAX_CACHE = 256
    MAX_HASH_FILE_BYTES = 512 * 1024 * 1024
    SIGNATURE_TIMEOUT_SECONDS = 3.0

    def __init__(
        self,
        *,
        signature_reader: Callable[[str], dict[str, Any]] | None = None,
        wall_clock: Callable[[], float] = time.time,
        close_join_seconds: float = 0.5,
    ) -> None:
        self.signature_reader = signature_reader or self._windows_signature
        self.wall_clock = wall_clock
        self.close_join_seconds = max(0.0, min(float(close_join_seconds), 5.0))

        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue(maxsize=self.MAX_QUEUE)
        self._queued: set[str] = set()
        self._closed = threading.Event()
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._thread = threading.Thread(
            target=self._run,
            name="CyberDefenderExecutableEnricher",
            daemon=True,
        )

        self.requests = 0
        self.scheduled = 0
        self.completed = 0
        self.failures = 0
        self.coalesced = 0
        self.queue_full = 0
        self.evictions = 0
        self.close_incomplete = False
        self.last_error: str | None = None
        self.last_failure_at: float | None = None

        self._thread.start()

    @staticmethod
    def _file_key(path: str) -> tuple[str | None, dict[str, Any]]:
        normalized = _normalized_path(path)
        if not normalized:
            return None, {
                "sha256": None,
                "sha256_status": "PATH_UNAVAILABLE",
                "signature": {"status": "UNVERIFIED", "signer_subject": None},
                "file_size": None,
                "file_mtime_ns": None,
            }
        try:
            stat = os.stat(normalized)
        except OSError:
            return None, {
                "sha256": None,
                "sha256_status": "FILE_UNAVAILABLE",
                "signature": {"status": "UNVERIFIED", "signer_subject": None},
                "file_size": None,
                "file_mtime_ns": None,
            }
        key_material = f"{normalized}|{int(stat.st_size)}|{int(stat.st_mtime_ns)}"
        key = hashlib.sha256(key_material.encode("utf-8", errors="surrogatepass")).hexdigest()
        return key, {
            "file_size": int(stat.st_size),
            "file_mtime_ns": int(stat.st_mtime_ns),
        }

    def lookup_or_schedule(self, path: str | None) -> dict[str, Any]:
        self.requests += 1
        if not path:
            return {
                "sha256": None,
                "sha256_status": "NO_EXECUTABLE_PATH",
                "signature": {"status": "UNVERIFIED", "signer_subject": None},
                "file_size": None,
                "file_mtime_ns": None,
                "enrichment_status": "UNAVAILABLE",
            }

        key, meta = self._file_key(path)
        if key is None:
            result = dict(meta)
            result["enrichment_status"] = "UNAVAILABLE"
            return result

        queue_token = _normalized_path(path) or path
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                return copy.deepcopy(cached)

            if queue_token in self._queued:
                self.coalesced += 1
                return {
                    **meta,
                    "sha256": None,
                    "sha256_status": "PENDING",
                    "signature": {"status": "PENDING", "signer_subject": None},
                    "enrichment_status": "PENDING",
                }

            if self._closed.is_set():
                return {
                    **meta,
                    "sha256": None,
                    "sha256_status": "UNAVAILABLE",
                    "signature": {"status": "UNVERIFIED", "signer_subject": None},
                    "enrichment_status": "STOPPED",
                }

            try:
                self._queue.put_nowait(path)
                self._queued.add(queue_token)
                self.scheduled += 1
            except queue.Full:
                self.queue_full += 1
                return {
                    **meta,
                    "sha256": None,
                    "sha256_status": "DEFERRED_QUEUE_FULL",
                    "signature": {"status": "DEFERRED", "signer_subject": None},
                    "enrichment_status": "DEFERRED",
                }

        return {
            **meta,
            "sha256": None,
            "sha256_status": "PENDING",
            "signature": {"status": "PENDING", "signer_subject": None},
            "enrichment_status": "PENDING",
        }

    def _sha256_file(self, path: str, size: int) -> tuple[str | None, str]:
        if size < 0:
            return None, "FILE_UNAVAILABLE"
        if size > self.MAX_HASH_FILE_BYTES:
            return None, "SKIPPED_TOO_LARGE"
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest(), "VERIFIED"

    def _windows_signature(self, path: str) -> dict[str, Any]:
        if os.name != "nt":
            return {
                "status": "UNVERIFIED_NON_WINDOWS",
                "signer_subject": None,
                "raw_status": None,
            }

        env = os.environ.copy()
        env["CYBERDEFENDER_AUTHENTICODE_PATH"] = path
        script = (
            "$ErrorActionPreference='Stop';"
            "$s=Get-AuthenticodeSignature -LiteralPath $env:CYBERDEFENDER_AUTHENTICODE_PATH;"
            "$subject=$null;if($s.SignerCertificate){$subject=$s.SignerCertificate.Subject};"
            "[pscustomobject]@{Status=$s.Status.ToString();SignerSubject=$subject} | ConvertTo-Json -Compress"
        )
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=False,
            timeout=self.SIGNATURE_TIMEOUT_SECONDS,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            env=env,
        )
        if completed.returncode != 0:
            return {
                "status": "ERROR",
                "signer_subject": None,
                "raw_status": "POWERSHELL_FAILED",
            }
        raw = bytes(completed.stdout or b"")
        if len(raw) > 64 * 1024:
            return {
                "status": "ERROR",
                "signer_subject": None,
                "raw_status": "OUTPUT_TOO_LARGE",
            }
        try:
            payload = json.loads(raw.decode("utf-8-sig", errors="strict").strip() or "{}")
        except Exception:
            payload = {}
        raw_status = _bounded_text(payload.get("Status"), 64) or "UNKNOWN"
        mapped = {
            "VALID": "VALID",
            "NOTSIGNED": "NOT_SIGNED",
            "HASHMISMATCH": "HASH_MISMATCH",
            "NOTTRUSTED": "NOT_TRUSTED",
            "UNKNOWNERROR": "UNKNOWN_ERROR",
        }.get(raw_status.upper(), "UNVERIFIED")
        return {
            "status": mapped,
            "signer_subject": _bounded_text(payload.get("SignerSubject"), 256) or None,
            "raw_status": raw_status,
        }

    def _enrich(self, path: str) -> tuple[str | None, dict[str, Any]]:
        key, meta = self._file_key(path)
        if key is None:
            result = dict(meta)
            result["enrichment_status"] = "UNAVAILABLE"
            result["completed_at"] = self.wall_clock()
            return None, result

        normalized = _normalized_path(path) or path
        size = int(meta.get("file_size") or 0)
        sha256_value: str | None = None
        sha_status = "ERROR"
        try:
            sha256_value, sha_status = self._sha256_file(normalized, size)
        except (OSError, PermissionError):
            sha_status = "ACCESS_ERROR"

        try:
            signature = self.signature_reader(normalized)
            if not isinstance(signature, dict):
                raise TypeError("SIGNATURE_READER_INVALID")
        except Exception as exc:
            signature = {
                "status": "ERROR",
                "signer_subject": None,
                "raw_status": type(exc).__name__,
            }

        result = {
            **meta,
            "sha256": sha256_value,
            "sha256_status": sha_status,
            "signature": {
                "status": _bounded_text(signature.get("status"), 64) or "UNVERIFIED",
                "signer_subject": _bounded_text(signature.get("signer_subject"), 256) or None,
                "raw_status": _bounded_text(signature.get("raw_status"), 64) or None,
            },
            "enrichment_status": "COMPLETE",
            "completed_at": self.wall_clock(),
        }
        return key, result

    def _run(self) -> None:
        while not self._closed.is_set():
            try:
                path = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue

            queue_token = _normalized_path(path) or path
            try:
                cache_key, result = self._enrich(path)
                if cache_key is not None:
                    with self._lock:
                        self._cache[cache_key] = result
                        self._cache.move_to_end(cache_key)
                        while len(self._cache) > self.MAX_CACHE:
                            self._cache.popitem(last=False)
                            self.evictions += 1
                    self.completed += 1
                    self.last_error = None
            except Exception as exc:  # isolated telemetry worker
                self.failures += 1
                self.last_error = type(exc).__name__
                self.last_failure_at = self.wall_clock()
            finally:
                with self._lock:
                    self._queued.discard(queue_token)
                self._queue.task_done()

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            cache_entries = len(self._cache)
            queued = len(self._queued)
        return {
            "component": "AsyncExecutableEnricher",
            "version": self.VERSION,
            "status": "STOPPED" if self._closed.is_set() else ("DEGRADED" if self.last_error else "HEALTHY"),
            "authority": self.AUTHORITY,
            "authoritative": False,
            "external_network_io": False,
            "executes_target_binary": False,
            "requests": self.requests,
            "scheduled": self.scheduled,
            "completed": self.completed,
            "failures": self.failures,
            "coalesced": self.coalesced,
            "queue_full": self.queue_full,
            "cache_entries": cache_entries,
            "queued": queued,
            "evictions": self.evictions,
            "last_error": self.last_error,
            "last_failure_at": self.last_failure_at,
            "close_incomplete": self.close_incomplete,
        }

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._thread.join(timeout=self.close_join_seconds)
        self.close_incomplete = self._thread.is_alive()


class ProcessAttributionResolver:
    """Resolve local PID identity and attach bounded async file evidence.

    Resolution is attribution, not authorization. A valid signature or hash never
    promotes a process, peer, user, or connection to AUTHORIZED.
    """

    VERSION = "0.1.4"
    AUTHORITY = "NONE"
    MAX_PIDS_PER_SAMPLE = 128

    def __init__(
        self,
        *,
        process_reader: Callable[[int], dict[str, Any]] | None = None,
        file_enricher: AsyncExecutableEnricher | None = None,
    ) -> None:
        self.process_reader = process_reader or self._psutil_process_reader
        self.file_enricher = file_enricher or AsyncExecutableEnricher()
        self.requests = 0
        self.resolved = 0
        self.unresolved = 0

    @staticmethod
    def _psutil_process_reader(pid: int) -> dict[str, Any]:
        if psutil is None:
            raise RuntimeError("PSUTIL_UNAVAILABLE")
        process = psutil.Process(pid)
        with process.oneshot():
            return {
                "pid": pid,
                "name": process.name(),
                "exe": process.exe(),
                "username": process.username(),
                "create_time": process.create_time(),
            }

    def resolve_pid(self, pid: int) -> dict[str, Any]:
        self.requests += 1
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = 0

        if pid <= 0:
            self.unresolved += 1
            return {
                "attribution_status": "PID_UNAVAILABLE",
                "pid": pid,
                "technical_name": None,
                "executable_path": None,
                "username": None,
                "create_time": None,
                "file_identity": {
                    "enrichment_status": "UNAVAILABLE",
                    "sha256": None,
                    "sha256_status": "UNAVAILABLE",
                    "signature": {"status": "UNVERIFIED", "signer_subject": None},
                },
                "authority": self.AUTHORITY,
                "authorization": "NOT_GRANTED",
            }

        try:
            raw = self.process_reader(pid)
            if not isinstance(raw, dict):
                raise TypeError("PROCESS_READER_INVALID")
            exe = _bounded_text(raw.get("exe"), 4096) or None
            name = _bounded_text(raw.get("name"), 256) or (os.path.basename(exe) if exe else None)
            username = _bounded_text(raw.get("username"), 256) or None
            try:
                create_time = float(raw.get("create_time")) if raw.get("create_time") is not None else None
            except (TypeError, ValueError):
                create_time = None
            file_identity = self.file_enricher.lookup_or_schedule(exe)
            self.resolved += 1
            return {
                "attribution_status": "RESOLVED",
                "pid": pid,
                "technical_name": name,
                "executable_path": exe,
                "username": username,
                "create_time": create_time,
                "file_identity": file_identity,
                "authority": self.AUTHORITY,
                "authorization": "NOT_GRANTED",
            }
        except Exception as exc:
            self.unresolved += 1
            error_type = type(exc).__name__
            if psutil is not None:
                if isinstance(exc, getattr(psutil, "NoSuchProcess", ())):
                    error_type = "PROCESS_EXITED"
                elif isinstance(exc, getattr(psutil, "AccessDenied", ())):
                    error_type = "ACCESS_DENIED"
                elif isinstance(exc, getattr(psutil, "ZombieProcess", ())):
                    error_type = "PROCESS_ZOMBIE"
            return {
                "attribution_status": error_type,
                "pid": pid,
                "technical_name": None,
                "executable_path": None,
                "username": None,
                "create_time": None,
                "file_identity": {
                    "enrichment_status": "UNAVAILABLE",
                    "sha256": None,
                    "sha256_status": "UNAVAILABLE",
                    "signature": {"status": "UNVERIFIED", "signer_subject": None},
                },
                "authority": self.AUTHORITY,
                "authorization": "NOT_GRANTED",
            }

    def resolve_many(self, pids: list[int]) -> dict[int, dict[str, Any]]:
        result: dict[int, dict[str, Any]] = {}
        for raw_pid in pids[: self.MAX_PIDS_PER_SAMPLE]:
            try:
                pid = int(raw_pid)
            except (TypeError, ValueError):
                pid = 0
            if pid in result:
                continue
            result[pid] = self.resolve_pid(pid)
        return result

    def health_check(self) -> dict[str, Any]:
        file_health = self.file_enricher.health_check()
        status = "DEGRADED" if file_health.get("status") == "DEGRADED" else ("STOPPED" if file_health.get("status") == "STOPPED" else "HEALTHY")
        return {
            "component": "ProcessAttributionResolver",
            "version": self.VERSION,
            "status": status,
            "authority": self.AUTHORITY,
            "authoritative": False,
            "authorization": "NOT_GRANTED",
            "requests": self.requests,
            "resolved": self.resolved,
            "unresolved": self.unresolved,
            "file_enricher": file_health,
        }

    def close(self) -> None:
        self.file_enricher.close()
