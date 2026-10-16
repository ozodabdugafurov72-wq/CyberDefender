import ast
import json
import os
from pathlib import Path
import sys
import tempfile
import types
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
diagnostic_path = root / 'agent/service_diagnostics.py'
tree = ast.parse(diagnostic_path.read_text())
tree.body = [n for n in tree.body if not (isinstance(n, ast.ImportFrom) and (n.module or '').startswith('agent.'))]
scope = {
    '__file__': str(diagnostic_path),
    'SERVICES': {'CyberDefenderAgent'},
    'normalize_gate_code': lambda value: value if value == 'KEY_NOT_ACTIVE' else 'BOOTSTRAP_UNCLASSIFIED',
    'failing_component': lambda code: 'key_manager' if code.startswith('KEY_') else None,
}
exec(compile(tree, str(diagnostic_path), 'exec'), scope)
service_path = root / 'agent/windows_service.py'
tree = ast.parse(service_path.read_text())
method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_run_attempt')
captured = []
class RuntimeBootstrapError(RuntimeError):
    gate_code = 'KEY_NOT_ACTIVE'
class Runner:
    exit_reason = 'UNHANDLED_EXCEPTION'
    def __init__(self, *args, **kwargs): pass
    def run(self):
        raise RuntimeBootstrapError('SECRET_TEST_TOKEN_DO_NOT_RECORD')
class Handle:
    def Close(self): pass
modules = {
    'agent': types.ModuleType('agent'),
    'agent.main': types.SimpleNamespace(build_managed_runtime=lambda **kw: None),
    'agent.service_runner': types.SimpleNamespace(ServiceRunner=Runner),
    'agent.service_diagnostics': types.SimpleNamespace(write_service_log=scope['write_service_log']),
    'win32file': types.SimpleNamespace(CreateFile=lambda *a: Handle()),
    'win32con': types.SimpleNamespace(GENERIC_READ=1, GENERIC_WRITE=2, OPEN_ALWAYS=4),
}
with tempfile.TemporaryDirectory() as raw, patch.dict(sys.modules, modules):
    temp = Path(raw)
    scope['_log_dir'] = lambda: temp
    scope['protected_path'] = lambda p: None
    env = {'SERVICE_NAME': 'CyberDefenderAgent', 'Path': Path, 'os': os,
           'configure_machine_environment': lambda: {'endpoint_id': temp/'absent'},
           'servicemanager': types.SimpleNamespace(LogInfoMsg=lambda *a: None, LogErrorMsg=lambda *a: None)}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(service_path), 'exec'), env)
    def rejected_failure_record(code):
        captured.append(code)
        raise RuntimeError('synthetic authenticated-store rejection')
    guard = types.SimpleNamespace(allow_optional=False, failed=rejected_failure_record)
    host = types.SimpleNamespace(_stop_event=object(), _runner=None)
    assert env['_run_attempt'](host, guard) is False
    raw_log = (temp/'CyberDefenderAgent.jsonl').read_bytes()
    rows = [json.loads(line) for line in raw_log.splitlines()]
    fatal = next(r for r in rows if r['event'] == 'FATAL')
    assert fatal['exception_class'] == 'RuntimeBootstrapError'
    assert fatal['stage'] == 'RUNTIME_RUN'
    assert fatal['gate_code'] == 'KEY_NOT_ACTIVE'
    assert fatal['failing_component'] == 'key_manager'
    assert fatal['source']['file'] == 'windows_service.py'
    assert fatal['source']['function'] == '_run_attempt'
    expected_line = next(n.lineno for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'run')
    assert fatal['source']['line'] == expected_line
    assert fatal['time'].endswith('+00:00')
    assert all(len(line)+1 <= 512 for line in raw_log.splitlines())
    assert b'SECRET_TEST_TOKEN' not in raw_log and str(root).encode() not in raw_log
    assert captured == ['UNHANDLED_EXCEPTION']
    print('PASS injected boundary only; bounded sanitized evidence survives CrashStore rejection')
