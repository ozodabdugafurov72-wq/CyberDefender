# CyberDefender P0.8.5.1 — Machine Installer & Service Startup Hotfix

This hotfix is based on real Windows installation evidence from P0.8.5.

## Fixed

- Root runtime `quarantine/` exclusion no longer removes the source package `agent/quarantine/`.
- Machine preflight is fail-closed; missing source/runtime dependencies stop installation before service registration.
- Services are hosted directly by the machine venv Python SCM dispatcher rather than the ambiguous `pythonservice.exe`/PythonClass registry host path.
- Existing CyberDefender services are stopped/removed before application files are replaced.
- Ports 8775 and 8785 are checked before service registration.
- Every service must reach `RUNNING`; Control Plane and Owner UI must pass HTTP health checks.
- Agent must publish a fresh `dashboard_runtime.json` before installation is declared successful.
- False `machine install tayyor` success output after service failure is removed.
- Bootstrap exceptions are written to bounded `C:\ProgramData\CyberDefender\logs\service_bootstrap.log` and SCM diagnostics are surfaced on installer failure.
- `pywin32_postinstall -install` global Python/System32 mutation is no longer used by the machine installer.
- Existing state, device identity, and secrets remain preserved across the hotfix install.

## Security boundary

The Windows Service foundation does not grant real response authorization. Policy, Independent Verification, Safety Core, Authorization Gate and Action Gateway boundaries remain unchanged; privileged execution remains protected / dry-run only.
