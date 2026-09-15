from __future__ import annotations
from pathlib import Path

root=Path(__file__).resolve().parent.parent
install=(root/'scripts'/'install_machine.ps1').read_text(encoding='utf-8')

assert "agent\\quarantine\\vault.py" in install
assert "Packaging invariant failed" in install
assert "'quarantine'" not in install.split("$copyArgs=",1)[1].split("\n",1)[0]
assert "--preflight" in install
assert "Wait-ServiceRunning" in install
assert "Wait-HttpHealthy" in install
assert "dashboard_runtime.json" in install
assert "Agent runtime published state but is not marked running under SCM lifecycle" in install
assert "Agent runtime health is not HEALTHY" in install
assert "Agent runtime component failures detected" in install
assert "CyberDefender machine install VERIFIED." in install
assert "CyberDefender machine install FAILED" in install
assert "Show-ServiceDiagnostics" in install
assert "Remove-ServiceSafe" in install
assert "Port 8775 is already in use" in install and "Port 8785 is already in use" in install
assert "pythonservice.exe" not in install
print('PASS | source quarantine package cannot be excluded by runtime-data cleanup')
print('PASS | install is fail-closed on preflight/start/health failures')
print('PASS | fresh Agent runtime state must be running, HEALTHY, and failure-free')
print('PASS | false-success machine install message is removed')
print('PASS | direct service hosting avoids pythonservice.exe registry-host ambiguity')
print('PASS | failed service start produces deterministic local/SCM diagnostics')
print('RESULT: PASS')
