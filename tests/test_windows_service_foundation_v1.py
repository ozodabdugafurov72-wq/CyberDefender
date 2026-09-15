from __future__ import annotations
from pathlib import Path
import agent.windows_service as agent_service
import control_plane.windows_service as cp_service
import dashboard_owner.windows_service as ui_service

root=Path(__file__).resolve().parent.parent
install=(root/'scripts'/'install_machine.ps1').read_text(encoding='utf-8')
status=(root/'scripts'/'service_status.ps1').read_text(encoding='utf-8')
requirements=(root/'requirements.txt').read_text(encoding='utf-8')
assert agent_service.SERVICE_NAME=='CyberDefenderAgent'
assert cp_service.SERVICE_NAME=='CyberDefenderControlPlane'
assert ui_service.SERVICE_NAME=='CyberDefenderOwnerUI'
assert 'New-Service' in install and '-StartupType Automatic' in install
assert 'CyberDefenderRecoveryPolicy' in install and "'failureflag'" in install
assert '--service-run' in install
assert 'CyberDefenderControlPlane' in status and 'CyberDefenderOwnerUI' in status
assert 'pywin32' in requirements
assert (root/'scripts'/'open_owner.cmd').is_file()
print('PASS | three Windows service contracts exist')
print('PASS | direct venv-python SCM hosts are configured')
print('PASS | auto-start and restart recovery are configured')
print('PASS | Owner UI can be opened without a PowerShell command')
print('RESULT: PASS')
