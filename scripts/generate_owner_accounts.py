"""Generate Railway-ready Owner/Admin credentials without committing secrets."""
from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from owner_cloud.security import hash_password


ALPHABET = string.ascii_letters + string.digits + "!@#%_-+="


def password(length: int = 24) -> str:
    while True:
        value = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if any(char.islower() for char in value) and any(char.isupper() for char in value) and any(char.isdigit() for char in value):
            return value


def generate() -> dict:
    credentials = []
    accounts = []
    for username, role in (("owner", "OWNER"), ("admin", "ADMIN")):
        raw_password = password()
        credentials.append({"username": username, "role": role, "password": raw_password})
        accounts.append(
            {
                "username": username,
                "role": role,
                "password_hash": hash_password(raw_password),
                "enabled": True,
            }
        )
    return {
        "credentials": credentials,
        "railway_variables": {
            "CYBERDEFENDER_OWNER_ACCOUNTS_JSON": json.dumps(accounts, separators=(",", ":")),
            "CYBERDEFENDER_DISTRIBUTION_READ_TOKEN": secrets.token_urlsafe(48),
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(generate(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote credentials to {output}")
