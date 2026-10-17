"""SID-native, fail-closed ACL verification for privileged product paths.

The verifier never resolves account names.  Windows returns immutable SID
objects directly, so deleted/domain-unavailable principals cannot trigger the
old ``UNRESOLVED_ACL_PRINCIPAL`` path or be mistaken for a trusted account.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Iterable


BROAD_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
    "S-1-5-4",       # Interactive
    "S-1-5-2",       # Network
})
PRIVILEGED_OWNER_SIDS = frozenset({
    "S-1-5-18",      # LocalSystem
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
})

# Includes direct data/append rights, generic write/all, deletion, and ACL or
# ownership mutation.  Any one of these on a broad principal is unsafe.
WRITE_OR_CONTROL_MASK = (
    0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000100 |
    0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000
)
ALLOW_ACE_TYPES = frozenset({0})
DENY_ACE_TYPES = frozenset({1})


class AclVerificationError(RuntimeError):
    pass


def evaluate_acl(owner_sid: str, aces: Iterable[tuple[int, int, str]]) -> dict:
    if owner_sid not in PRIVILEGED_OWNER_SIDS:
        raise AclVerificationError("ACL_OWNER_NOT_PRIVILEGED")
    checked = 0
    unprivileged_write = []
    unsupported = []
    for ace_type, mask, sid in aces:
        checked += 1
        if not isinstance(sid, str) or not sid.startswith("S-"):
            raise AclVerificationError("ACL_SID_INVALID")
        if ace_type in ALLOW_ACE_TYPES:
            if sid not in PRIVILEGED_OWNER_SIDS and int(mask) & WRITE_OR_CONTROL_MASK:
                unprivileged_write.append(sid)
        elif ace_type not in DENY_ACE_TYPES:
            unsupported.append(int(ace_type))
    if unsupported:
        raise AclVerificationError("ACL_UNSUPPORTED_ACE_TYPE")
    if unprivileged_write:
        raise AclVerificationError("ACL_UNPRIVILEGED_WRITE_OR_CONTROL")
    return {
        "status": "PASS",
        "owner_sid": owner_sid,
        "aces_checked": checked,
        "broad_write_blocked": True,
        "principal_resolution": "SID_NATIVE",
    }


def audit_path(path: Path) -> dict:
    if os.name != "nt":
        raise AclVerificationError("WINDOWS_ACL_REQUIRED")
    if not path.is_absolute() or not path.exists():
        raise AclVerificationError("ACL_PATH_INVALID")
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if getattr(info, "st_file_attributes", 0) & 0x400:
                raise AclVerificationError("ACL_REPARSE_PATH")
    except OSError as exc:
        raise AclVerificationError("ACL_PATH_UNAVAILABLE") from exc
    import win32security as security

    try:
        descriptor = security.GetNamedSecurityInfo(
            str(path),
            security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION,
        )
    except Exception as exc:
        raise AclVerificationError("ACL_SECURITY_DESCRIPTOR_UNAVAILABLE") from exc
    owner = descriptor.GetSecurityDescriptorOwner()
    dacl = descriptor.GetSecurityDescriptorDacl()
    if owner is None or dacl is None:
        raise AclVerificationError("ACL_NULL_SECURITY_DESCRIPTOR")
    owner_sid = security.ConvertSidToStringSid(owner)
    aces: list[tuple[int, int, str]] = []
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        try:
            ace_type = int(ace[0][0])
            mask = int(ace[1])
            sid = security.ConvertSidToStringSid(ace[2])
        except Exception as exc:
            raise AclVerificationError("ACL_ACE_INVALID") from exc
        aces.append((ace_type, mask, sid))
    result = evaluate_acl(owner_sid, aces)
    result["path"] = str(path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    results = []
    try:
        for item in args.paths:
            results.append(audit_path(item.absolute()))
    except AclVerificationError as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, sort_keys=True))
        return 1
    except Exception:
        print(json.dumps({"status": "FAIL", "reason": "ACL_GATE_UNAVAILABLE"}, sort_keys=True))
        return 2
    print(json.dumps({"status": "PASS", "paths": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
