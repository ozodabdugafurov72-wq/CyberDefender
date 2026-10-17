"""Exact-layout import closure probe for the Windows Agent service."""
from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import json
import os
from pathlib import Path
import site
import sys


THIRD_PARTY_MODULES = (
    "_cffi_backend",
    "cffi",
    "cryptography",
    "pycparser",
    "psutil",
    "pythoncom",
    "pywintypes",
    "servicemanager",
    "win32event",
    "win32service",
    "win32serviceutil",
)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _service_imports(source: Path) -> set[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=source.name)
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            result.add(node.module)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.release_root.resolve(strict=True)
    runtime_root = (root / "runtime").resolve(strict=True)
    dependency_root = (runtime_root / "Lib" / "site-packages").resolve(strict=True)
    if Path(sys.executable).resolve(strict=True).parent != runtime_root:
        raise RuntimeError("IMPORT_CLOSURE_INTERPRETER_MISMATCH")
    if os.environ.get("PYTHONPATH"):
        raise RuntimeError("IMPORT_CLOSURE_PYTHONPATH_PRESENT")

    sys.path.insert(0, str(root))
    bootstrap_path = (root / "agent_service_bootstrap.py").resolve(strict=True)
    spec = importlib.util.spec_from_file_location("cd_import_closure_bootstrap", bootstrap_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("IMPORT_CLOSURE_BOOTSTRAP_UNAVAILABLE")
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    bootstrap._verify_pinned_dependencies(root, required=True)

    legacy_fragment = str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CyberDefender" / "app").casefold()
    user_site = Path(site.getusersitepackages()).resolve()
    for entry in sys.path:
        if not entry:
            continue
        resolved = Path(entry).resolve()
        if legacy_fragment in str(resolved).casefold() or _inside(resolved, user_site):
            raise RuntimeError("IMPORT_CLOSURE_FORBIDDEN_SYS_PATH")

    source = root / "agent" / "windows_service.py"
    ast_imports = _service_imports(source)
    project_modules = sorted(name for name in ast_imports if name.split(".", 1)[0] in {"agent", "control_plane", "dashboard_owner"})
    imported_project: list[str] = []
    for name in project_modules:
        module = importlib.import_module(name)
        origin = getattr(module, "__file__", None)
        if origin is None or not _inside(Path(origin), root) or _inside(Path(origin), runtime_root):
            raise RuntimeError("IMPORT_CLOSURE_PROJECT_ORIGIN_REJECTED")
        imported_project.append(name)

    third_party: dict[str, str] = {}
    for name in THIRD_PARTY_MODULES:
        module = importlib.import_module(name)
        origin = getattr(module, "__file__", None)
        if origin is None or not _inside(Path(origin), dependency_root):
            raise RuntimeError("IMPORT_CLOSURE_DEPENDENCY_ORIGIN_REJECTED")
        third_party[name] = Path(origin).resolve().relative_to(dependency_root).as_posix()

    print(
        json.dumps(
            {
                "status": "IMPORT_CLOSURE_PASS",
                "dependency_root": str(dependency_root),
                "interpreter": str(Path(sys.executable).resolve()),
                "project_modules": len(imported_project),
                "third_party": third_party,
                "pythonpath_present": False,
                "legacy_origin": False,
                "user_site_origin": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
