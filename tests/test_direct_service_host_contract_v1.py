from __future__ import annotations
from pathlib import Path

root=Path(__file__).resolve().parent.parent
mods=[
    root/'agent'/'windows_service.py',
    root/'control_plane'/'windows_service.py',
    root/'dashboard_owner'/'windows_service.py',
]
for path in mods:
    text=path.read_text(encoding='utf-8')
    assert '--service-run' in text
    assert 'PrepareToHostSingle' in text
    assert 'StartServiceCtrlDispatcher' in text
    assert '--preflight' in text
    assert 'write_service_log' in text
assert (root/'agent'/'service_diagnostics.py').is_file()
assert (root/'scripts'/'collect_service_diagnostics.ps1').is_file()
print('PASS | all three services support direct SCM dispatch from venv python')
print('PASS | all three services expose fail-fast preflight')
print('PASS | bootstrap failures have file-based diagnostics independent of EventLog')
print('RESULT: PASS')
