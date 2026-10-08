"""Build and validate a dependency-closed Agent deployment manifest.

The manifest is derived from the actual source tree.  It follows local
``agent.*`` imports, including imports nested in functions, and records source
and installed-runtime hashes without copying file contents or secrets.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


SCHEMA = "cyberdefender.phase6-agent-dependency-manifest.v1"
DEFAULT_INSTALLED_ROOT = Path(r"C:\Program Files\CyberDefender\app")
ROOT_FILES = (
    "agent/main.py",
    "agent/windows_service.py",
    "agent/service_runner.py",
    "agent/service_lifecycle.py",
    "agent/service_crash_guard.py",
    "agent/service_diagnostics.py",
    "agent/service_crash_store.py",
    "agent/core/event_bridge.py",
    "agent/sensors/file_activity_collector.py",
    "agent/quarantine/coordinator.py",
    "agent/storage/durable_incident_outbox.py",
)
ROOT_DIRECTORIES = ("agent/correlation", "agent/detection")


class DependencyManifestError(RuntimeError):
    """Raised when the manifest cannot prove a closed local dependency set."""


def _read(path: Path) -> str:
    # Several existing source files carry a UTF-8 BOM.  It is valid source
    # material and must not be mistaken for a parse failure.
    return path.read_text(encoding="utf-8-sig")


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _module_for_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_module(root: Path, module: str) -> Path | None:
    candidate = root.joinpath(*module.split("."))
    if candidate.with_suffix(".py").is_file():
        return candidate.with_suffix(".py")
    package_init = candidate / "__init__.py"
    if package_init.is_file():
        return package_init
    return None


def _resolve_relative(root: Path, current: Path, level: int, name: str | None) -> Path | None:
    current_module = _module_for_path(root, current).split(".")
    if current.name != "__init__.py":
        current_module = current_module[:-1]
    if level > len(current_module) + 1:
        return None
    prefix = current_module[: len(current_module) - (level - 1)]
    module = ".".join(prefix + ([name] if name else []))
    return _resolve_module(root, module) if module else None


def _literal_module(call: ast.Call) -> str | None:
    if not call.args or not isinstance(call.args[0], ast.Constant):
        return None
    value = call.args[0].value
    return value if isinstance(value, str) else None


def _scan_file(root: Path, path: Path) -> tuple[set[Path], list[dict[str, Any]], set[str]]:
    text = _read(path)
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        raise DependencyManifestError(f"PARSE_FAILED:{_relative(root, path)}:{exc}") from None

    dependencies: set[Path] = set()
    unresolved: list[dict[str, Any]] = []
    external_imports: set[str] = set()

    def add_import(module: str, lineno: int) -> None:
        if module == "agent" or module.startswith("agent."):
            resolved = _resolve_module(root, module)
            if resolved is None:
                unresolved.append({
                    "file": _relative(root, path),
                    "line": lineno,
                    "import": module,
                    "kind": "local",
                })
            else:
                dependencies.add(resolved)
        elif module:
            external_imports.add(module.split(".", 1)[0])

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add_import(alias.name, node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                resolved = _resolve_relative(root, path, node.level, node.module)
                if resolved is None and node.module:
                    unresolved.append({
                        "file": _relative(root, path),
                        "line": node.lineno,
                        "import": "." * node.level + node.module,
                        "kind": "relative",
                    })
                elif resolved is not None:
                    dependencies.add(resolved)
            elif node.module:
                add_import(node.module, node.lineno)
        elif isinstance(node, ast.Call):
            function_name = ""
            if isinstance(node.func, ast.Name):
                function_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                function_name = node.func.attr
            if function_name in {"__import__", "import_module"}:
                literal = _literal_module(node)
                unresolved.append({
                    "file": _relative(root, path),
                    "line": node.lineno,
                    "import": literal,
                    "kind": "dynamic",
                    "local": bool(literal and (literal == "agent" or literal.startswith("agent."))),
                })
                if literal and not literal.startswith("agent"):
                    external_imports.add(literal.split(".", 1)[0])

    return dependencies, unresolved, external_imports


def _root_files(root: Path) -> set[Path]:
    files = {root / item for item in ROOT_FILES}
    for directory in ROOT_DIRECTORIES:
        files.update((root / directory).glob("*.py"))
    missing = [item for item in files if not item.is_file()]
    if missing:
        names = ",".join(sorted(_relative(root, item) for item in missing))
        raise DependencyManifestError(f"ROOT_FILE_MISSING:{names}")
    return files


def _package_inits(root: Path, path: Path) -> list[Path]:
    """Return package initializers implicitly executed for ``path``.

    Python executes each parent package's ``__init__.py`` before loading a
    submodule.  Those files are part of the runtime package boundary even
    when no source file contains an explicit import edge to them.
    """
    result: list[Path] = []
    current = path.parent
    while True:
        init = current / "__init__.py"
        if init.is_file():
            result.append(init)
        if current == root:
            break
        if root not in current.parents:
            break
        current = current.parent
    return result


def _git_metadata(root: Path) -> tuple[str | None, bool | None]:
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return commit or None, bool(status.strip())
    except (OSError, subprocess.SubprocessError):
        return None, None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(source_root: Path, installed_root: Path | None = None) -> dict[str, Any]:
    source_root = source_root.resolve()
    if installed_root is not None:
        installed_root = installed_root.resolve()

    roots = _root_files(source_root)
    graph: dict[Path, set[Path]] = {}
    unresolved: list[dict[str, Any]] = []
    external_imports: set[str] = set()
    seen: set[Path] = set()
    pending = list(roots)
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        pending.extend(
            package_init
            for package_init in _package_inits(source_root, path)
            if package_init not in seen
        )
        dependencies, file_unresolved, file_external = _scan_file(source_root, path)
        graph[path] = dependencies
        unresolved.extend(file_unresolved)
        external_imports.update(file_external)
        pending.extend(dependency for dependency in dependencies if dependency not in seen)

    relative_files = {_relative(source_root, path) for path in seen}
    direct_by_file = {
        _relative(source_root, path): sorted(_relative(source_root, dep) for dep in graph.get(path, set()))
        for path in seen
    }

    def transitive(path: Path) -> set[str]:
        result: set[str] = set()
        todo = list(graph.get(path, set()))
        while todo:
            child = todo.pop()
            relative = _relative(source_root, child)
            if relative in result:
                continue
            result.add(relative)
            todo.extend(graph.get(child, set()))
        return result

    source_commit, source_dirty = _git_metadata(source_root)
    entries: list[dict[str, Any]] = []
    for relative in sorted(relative_files):
        source_path = source_root / relative
        source_hash = sha256_file(source_path)
        installed_path = installed_root / relative if installed_root is not None else None
        installed_exists = bool(installed_path and installed_path.is_file())
        installed_hash = sha256_file(installed_path) if installed_exists and installed_path else None
        if installed_root is None:
            state = "SOURCE_ONLY"
        elif not installed_exists:
            state = "NEW"
        elif installed_hash != source_hash:
            state = "CHANGED"
        else:
            state = "ALREADY_MATCHING"
        entries.append({
            "relative_path": relative,
            "sha256": source_hash,
            "bytes": source_path.stat().st_size,
            "source_exists": True,
            "installed_exists": installed_exists,
            "installed_sha256": installed_hash,
            "status": state,
            "direct_local_dependencies": direct_by_file[relative],
            "transitive_local_dependencies": sorted(transitive(source_path)),
        })

    dynamic_local = [row for row in unresolved if row.get("kind") == "dynamic" and row.get("local")]
    # Dynamic imports are retained for audit, but only a dynamic local
    # ``agent.*`` import can make the local dependency closure incomplete.
    # A stdlib/third-party dynamic import (for example ``__import__("time")``)
    # is not a missing CyberDefender source file.
    static_unresolved = [row for row in unresolved if row.get("kind") != "dynamic"]
    return {
        "schema": SCHEMA,
        "source_root": str(source_root),
        "installed_root": str(installed_root) if installed_root is not None else None,
        "source_commit": source_commit,
        "source_dirty": source_dirty,
        "root_files": sorted(_relative(source_root, path) for path in roots),
        "required_file_count": len(entries),
        "closure_complete": not static_unresolved and not dynamic_local,
        "missing_local_imports": static_unresolved,
        "dynamic_imports": unresolved,
        "external_import_roots": sorted(external_imports),
        "files": entries,
    }


def validate_manifest(manifest: dict[str, Any], source_root: Path | None = None) -> None:
    if manifest.get("schema") != SCHEMA:
        raise DependencyManifestError("MANIFEST_SCHEMA_REJECTED")
    if not manifest.get("closure_complete"):
        raise DependencyManifestError("DEPENDENCY_CLOSURE_INCOMPLETE")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise DependencyManifestError("MANIFEST_FILES_MISSING")
    root = Path(source_root or manifest.get("source_root", "")).resolve()
    if not root.is_dir():
        raise DependencyManifestError("SOURCE_ROOT_MISSING")
    listed = {row.get("relative_path") for row in entries if isinstance(row, dict)}
    if len(listed) != len(entries) or None in listed:
        raise DependencyManifestError("MANIFEST_PATHS_INVALID")
    for relative in listed:
        candidate = (root / relative).resolve()
        if root not in candidate.parents and candidate != root:
            raise DependencyManifestError("MANIFEST_PATH_ESCAPE")
        if not candidate.is_file():
            raise DependencyManifestError(f"MANIFEST_SOURCE_MISSING:{relative}")
        row = next(item for item in entries if item.get("relative_path") == relative)
        if row.get("sha256") != sha256_file(candidate):
            raise DependencyManifestError(f"MANIFEST_HASH_MISMATCH:{relative}")
        for dependency in row.get("direct_local_dependencies", []):
            if dependency not in listed:
                raise DependencyManifestError(f"MANIFEST_DEPENDENCY_OMITTED:{relative}->{dependency}")
        for dependency in row.get("transitive_local_dependencies", []):
            if dependency not in listed:
                raise DependencyManifestError(f"MANIFEST_TRANSITIVE_DEPENDENCY_OMITTED:{relative}->{dependency}")

    regenerated = build_manifest(root, Path(manifest["installed_root"]) if manifest.get("installed_root") else None)
    expected = {row["relative_path"] for row in regenerated["files"]}
    if expected != listed:
        missing = sorted(expected - listed)
        extra = sorted(listed - expected)
        raise DependencyManifestError(f"MANIFEST_CLOSURE_MISMATCH:missing={missing}:extra={extra}")
    if regenerated.get("missing_local_imports") or not regenerated.get("closure_complete"):
        raise DependencyManifestError("SOURCE_DEPENDENCY_SCAN_INCOMPLETE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--installed-root", type=Path, default=DEFAULT_INSTALLED_ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path, help="Validate an existing manifest instead of generating one")
    args = parser.parse_args()
    try:
        if args.check:
            validate_manifest(json.loads(args.check.read_text(encoding="utf-8")), args.source_root)
            print("DEPENDENCY_MANIFEST_VALID=PASS")
            return 0
        if args.output is None:
            parser.error("--output is required when generating a manifest")
        manifest = build_manifest(args.source_root, args.installed_root)
        validate_manifest(manifest, args.source_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        print(f"DEPENDENCY_MANIFEST_VALID=PASS FILES={manifest['required_file_count']}")
        return 0
    except (DependencyManifestError, OSError, json.JSONDecodeError) as exc:
        print(f"DEPENDENCY_MANIFEST_VALID=FAIL REASON={exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
