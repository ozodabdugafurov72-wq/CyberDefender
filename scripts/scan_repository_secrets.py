"""Fail when tracked repository files contain common credential signatures."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("openai-token", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
)


EXCLUDED_DIRS = {
    ".git", ".venv", ".test-tmp", "__pycache__", "dist", "output", "outputs",
    "state", "logs", "evidence", "quarantine", "_backup_before_process_authority_20260908_000948",
    "_backup_before_processgraph_coverage_20260907_233824", "_backup_before_rust_shadow_20260907_220651",
    "_v6_backups",
}


def repository_files(root: Path) -> list[Path]:
    result = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRS or part.startswith(".codex") for part in relative.parts):
            continue
        result.append(path)
    return result


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path in repository_files(root):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:8192] or len(raw) > 5 * 1024 * 1024:
            continue
        text = raw.decode("utf-8", "ignore")
        for label, pattern in PATTERNS:
            if pattern.search(text):
                findings.append(f"{path.relative_to(root).as_posix()}: {label}")
    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    matches = scan(args.root.resolve())
    if matches:
        for match in matches:
            print("FAIL | " + match)
        raise SystemExit(1)
    print("PASS | no common credential signatures in tracked files")
