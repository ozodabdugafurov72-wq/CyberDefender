"""Authenticated bounded crash state under an installer-protected directory.

Two slots plus an authenticated commit anchor preserve the last complete
transaction across interrupted writes. A slot replay fails against the anchor.
Rollback of the entire protected directory by an administrator is outside the
boundary: HMAC is not a hardware monotonic counter. No startup auto-provisioning.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import stat
import threading

from agent.service_crash_guard import SERVICES, SCHEMA, fresh_record

MAX_BYTES = 32768


class CrashStoreError(RuntimeError):
    pass


def default_root():
    from win32com.shell import shell, shellcon
    return Path(shell.SHGetFolderPath(0, shellcon.CSIDL_COMMON_APPDATA, None, 0)) / "CyberDefenderCrashGuard"


def no_reparse(path: Path):
    # Check without resolve(), which would silently follow a substituted link.
    if not path.is_absolute(): raise CrashStoreError("STORE_PATH_NOT_ABSOLUTE")
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise CrashStoreError("STORE_REPARSE_REJECTED")


def protected_path(path: Path):
    no_reparse(path)
    if os.name != "nt": raise CrashStoreError("WINDOWS_ACL_REQUIRED")
    import win32security as security
    sd=security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
                                     security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
    allowed={"S-1-5-18", "S-1-5-32-544"}
    if security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner()) not in allowed:
        raise CrashStoreError("STORE_OWNER_REJECTED")
    acl=sd.GetSecurityDescriptorDacl()
    if acl is None: raise CrashStoreError("STORE_NULL_DACL")
    for i in range(acl.GetAceCount()):
        ace=acl.GetAce(i)
        # Reject unusual/object/callback ACEs rather than infer their meaning.
        if ace[0][0] not in (0, 1): raise CrashStoreError("STORE_ACE_REJECTED")
        if ace[0][0] == 0 and security.ConvertSidToStringSid(ace[2]) not in allowed:
            raise CrashStoreError("STORE_DACL_REJECTED")


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def strict_json(raw):
    if not 0 < len(raw) <= MAX_BYTES: raise CrashStoreError("STORE_SIZE_REJECTED")
    def pairs(items):
        out={}
        for key,value in items:
            if key in out: raise CrashStoreError("STORE_DUPLICATE_KEY")
            out[key]=value
        return out
    try: return json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except Exception: raise CrashStoreError("STORE_JSON_REJECTED") from None


def validate_record(r, service):
    expected=fresh_record(service)
    if type(r) is not dict or set(r) != set(expected) or r["schema"] != SCHEMA or r["service"] != service:
        raise CrashStoreError("STORE_SCHEMA_REJECTED")
    for key in ("revision", "generation", "cumulative_failures", "attempts_since_stable", "probes_used", "repair_count", "progress_count"):
        if type(r[key]) is not int or not 0 <= r[key] < 2**63: raise CrashStoreError("STORE_COUNTER_REJECTED")
    for key in ("boot", "session"):
        if type(r[key]) is not str or len(r[key]) > 128 or any(c not in "0123456789abcdef-" for c in r[key]):
            raise CrashStoreError("STORE_ID_REJECTED")
    if r["state"] not in {"READY", "STARTING", "RUNNING", "LATCHED", "PROBE", "UNAVAILABLE"}:
        raise CrashStoreError("STORE_STATE_REJECTED")
    for key in ("clean_stop", "active_attempt"):
        if type(r[key]) is not bool: raise CrashStoreError("STORE_FLAG_REJECTED")
    if type(r["last_progress"]) not in (int,float) or not math.isfinite(r["last_progress"]) or not 0 <= r["last_progress"] <= 10**12:
        raise CrashStoreError("STORE_TIME_REJECTED")
    if type(r["recent_failures"]) is not list or len(r["recent_failures"]) > 32: raise CrashStoreError("STORE_HISTORY_REJECTED")
    for item in r["recent_failures"]:
        if type(item) is not dict or set(item) != {"generation", "boot", "code", "tick"}:
            raise CrashStoreError("STORE_HISTORY_REJECTED")
        if item["code"] not in {"PREVIOUS_ATTEMPT_INTERRUPTED", "ATTEMPT_FAILED", "WORK_UNHEALTHY", "CLEANUP_UNVERIFIED"}:
            raise CrashStoreError("STORE_REASON_REJECTED")
        if type(item["generation"]) is not int or not 0 <= item["generation"] <= r["generation"]:
            raise CrashStoreError("STORE_GENERATION_REJECTED")
        if type(item["boot"]) is not str or len(item["boot"]) > 128 or any(c not in "0123456789abcdef-" for c in item["boot"]):
            raise CrashStoreError("STORE_BOOT_REJECTED")
        if type(item["tick"]) not in (int,float) or not math.isfinite(item["tick"]) or not 0 <= item["tick"] <= 10**12:
            raise CrashStoreError("STORE_TIME_REJECTED")
    if r["cumulative_failures"] < len(r["recent_failures"]): raise CrashStoreError("STORE_HISTORY_COUNT_REJECTED")


def atomic_write(path, data):
    if len(data) > MAX_BYTES: raise CrashStoreError("STORE_WRITE_SIZE_REJECTED")
    temporary=path.with_name(path.name + ".pending")
    # Exclusive ownership lock and protected directory make fixed pending paths
    # safe. Never follow an existing pending file/link after interrupted writes.
    if temporary.exists():
        no_reparse(temporary); temporary.unlink()
    try:
        with temporary.open("xb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        if os.name == "nt":
            import win32file
            win32file.MoveFileEx(str(temporary),str(path),0x1 | 0x8)  # replace + write through
        else:
            os.replace(temporary,path)
    except Exception:
        raise CrashStoreError("STORE_COMMIT_FAILED") from None


class FileCrashStore:
    def __init__(self, root: Path, service: str, *, path_validator=protected_path):
        if service not in SERVICES: raise CrashStoreError("SERVICE_ID_REJECTED")
        self.root=Path(root).absolute(); self.service=service; self.validate_path=path_validator
        self._lock=None; self._highwater=-1
        self._mutex=threading.RLock()
        try:
            path_validator(self.root)
            for name in ("guard.key", "provisioned", service+".lock"): path_validator(self.root/name)
            with (self.root/"provisioned").open("rb") as f:
                if f.read(64) != b"cd.crash-provision.v1\n": raise CrashStoreError("PROVISION_MARKER_REJECTED")
            # CreateFile share=0 enforces one writer/host across processes and threads.
            import win32file, win32con
            self._lock=win32file.CreateFile(str(self.root/(service+".lock")),win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                                          0,None,win32con.OPEN_EXISTING,0,None)
            with (self.root/"guard.key").open("rb") as f: self._key=f.read(33)
            if len(self._key) != 32: raise CrashStoreError("STORE_KEY_REJECTED")
            self.load()
        except Exception:
            self.close()
            raise CrashStoreError("STORE_OPEN_REJECTED") from None

    def _encode(self, payload):
        return canonical(dict(payload=payload, mac=hmac.new(self._key,canonical(payload),hashlib.sha256).hexdigest()))

    def _decode(self, path):
        self.validate_path(self.root); self.validate_path(path)
        with path.open("rb") as f: data=strict_json(f.read(MAX_BYTES+1))
        if type(data) is not dict or set(data) != {"payload", "mac"} or type(data["mac"]) is not str:
            raise CrashStoreError("STORE_ENVELOPE_REJECTED")
        if not hmac.compare_digest(data["mac"],hmac.new(self._key,canonical(data["payload"]),hashlib.sha256).hexdigest()):
            raise CrashStoreError("STORE_AUTH_REJECTED")
        return data["payload"]

    def load(self):
        with self._mutex: return self._load()

    def _load(self):
        if self._lock is None: raise CrashStoreError("STORE_CLOSED")
        try:
            anchor=self._decode(self.root/(self.service+".anchor"))
            if type(anchor) is not dict or set(anchor) != {"schema","service","revision","digest"} or anchor["schema"] != "cd.crash-anchor.v1" or anchor["service"] != self.service:
                raise CrashStoreError("STORE_ANCHOR_REJECTED")
            rev=anchor["revision"]
            if type(rev) is not int or not 0 <= rev < 2**63 or rev < self._highwater:
                raise CrashStoreError("STORE_REPLAY_REJECTED")
            r=self._decode(self.root/(self.service+f".{rev%2}.json"))
            validate_record(r,self.service)
            if r["revision"] != rev or hashlib.sha256(canonical(r)).hexdigest() != anchor["digest"]:
                raise CrashStoreError("STORE_REPLAY_REJECTED")
            self._highwater=rev
            return r
        except Exception:
            raise CrashStoreError("STORE_READ_REJECTED") from None

    def write(self, record):
        with self._mutex: return self._write(record)

    def _write(self, record):
        old=self.load()
        if record["revision"] != old["revision"]: raise CrashStoreError("STORE_STALE_WRITER")
        record=copy.deepcopy(record); record["revision"] += 1
        validate_record(record,self.service)
        self.validate_path(self.root)
        slot=self.root/(self.service+f'.{record["revision"]%2}.json')
        if slot.exists(): self.validate_path(slot)
        atomic_write(slot,self._encode(record))
        anchor=dict(schema="cd.crash-anchor.v1", service=self.service, revision=record["revision"],digest=hashlib.sha256(canonical(record)).hexdigest())
        atomic_write(self.root/(self.service+".anchor"),self._encode(anchor))
        self._highwater=record["revision"]
        return self.load()  # Independently authenticate the committed debit before use.

    def close(self):
        with self._mutex:
            if self._lock is not None: self._lock.Close(); self._lock=None

    def authorize_probe(self):
        """Authenticated administrator repair under exclusive stopped-host lock."""
        with self._mutex:
            r=self.load()
            if r["active_attempt"]:
                r["cumulative_failures"]+=1
                r["recent_failures"]=(r["recent_failures"]+[dict(generation=r["generation"],boot=r["boot"],
                    code="PREVIOUS_ATTEMPT_INTERRUPTED",tick=r["last_progress"])])[-32:]
            r["repair_count"]+=1; r["probes_used"]=0
            r["state"]="LATCHED"; r["active_attempt"]=False
            return self.write(r)


def provision(root: Path, *, path_validator=protected_path):
    """Installer-only first provisioning. Partial/missing established stores fail."""
    root=Path(root).absolute(); path_validator(root)
    if any(root.iterdir()):
        for service in SERVICES:
            store=FileCrashStore(root,service,path_validator=path_validator); store.close()
        return
    # The marker ensures interrupted first provisioning is not mistaken for new.
    (root/"provisioned").write_bytes(b"cd.crash-provision.v1\n")
    key=secrets.token_bytes(32)
    with (root/"guard.key").open("xb") as f: f.write(key); f.flush(); os.fsync(f.fileno())
    for service in SERVICES:
        (root/(service+".lock")).write_bytes(b"\0")
        record=fresh_record(service)
        def encode(payload): return canonical(dict(payload=payload,mac=hmac.new(key,canonical(payload),hashlib.sha256).hexdigest()))
        atomic_write(root/(service+".0.json"),encode(record))
        atomic_write(root/(service+".anchor"),encode(dict(schema="cd.crash-anchor.v1",service=service,revision=0,digest=hashlib.sha256(canonical(record)).hexdigest())))
    for service in SERVICES:
        verified=FileCrashStore(root,service,path_validator=path_validator)
        verified.close()


def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("operation", choices=("provision","status","authorize-probe"))
    parser.add_argument("--service",choices=SERVICES)
    args=parser.parse_args()
    if args.operation == "provision": provision(default_root()); return
    if args.service is None: parser.error("--service required")
    store=FileCrashStore(default_root(),args.service)
    try:
        r=store.load()
        if args.operation == "authorize-probe":
            # Requires protected-directory access and stopped service (lock).
            # Historical counts are not reset; grant only one extra probe.
            r=store.authorize_probe()
        print(json.dumps({k:r[k] for k in ("service","state","generation","cumulative_failures","repair_count","clean_stop")}))
    finally: store.close()


if __name__ == "__main__": main()
