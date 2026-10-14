"""Fail when tracked repository files contain common credential signatures."""
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path


PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("openai-token", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
)

SENSITIVE_NAME = re.compile(
    r"(?:^|_)(?:token|secret|password|passwd|credential|private_key|api_key|bearer)(?:_|$)",
    re.IGNORECASE,
)
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}


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


def _sensitive_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and SENSITIVE_NAME.search(child.id):
            names.add(child.id)
        elif isinstance(child, ast.Attribute) and SENSITIVE_NAME.search(child.attr):
            names.add(child.attr)
    return names


def _is_log_sink(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in {"print", "pprint"}
    return isinstance(call.func, ast.Attribute) and call.func.attr in LOG_METHODS


def scan_sensitive_log_sinks(path: Path, text: str) -> list[str]:
    if path.suffix.lower() != ".py":
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return []
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_log_sink(node):
            continue
        sensitive = set()
        for value in (*node.args, *(keyword.value for keyword in node.keywords)):
            sensitive.update(_sensitive_names(value))
        if sensitive:
            findings.append(
                f"{path.as_posix()}:{node.lineno}: sensitive-log-sink({','.join(sorted(sensitive))})"
            )
    return findings


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
        relative = path.relative_to(root)
        findings.extend(scan_sensitive_log_sinks(relative, text))
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
