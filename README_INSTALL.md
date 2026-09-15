# CyberDefender P0.8.5.2 install guide

## A. Development/release verification
From the extracted project directory:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\install.ps1
.\scripts\verify.ps1
```

This keeps development state under `%LOCALAPPDATA%\CyberDefender`.

## B. Machine 24/7 service install / repair
After release verification PASS, open Windows Terminal / PowerShell with **Run as administrator**, change into the extracted **P0.8.5.2** project directory and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\install_machine.ps1
```

The installer is idempotent for the P0.8.5 failed-service state: it stops/removes existing CyberDefender service registrations before replacing the application tree. Existing `%ProgramData%\CyberDefender` state, endpoint identity and secrets are preserved.

The machine install creates:
- `%ProgramFiles%\CyberDefender\app`
- `%ProgramFiles%\CyberDefender\app.previous` (one previous application snapshot when available)
- `%ProgramData%\CyberDefender\state`
- `%ProgramData%\CyberDefender\secrets`
- `%ProgramData%\CyberDefender\identity`
- `%ProgramData%\CyberDefender\control-plane\distribution.db`
- `%ProgramData%\CyberDefender\logs\service_bootstrap.log`

and registers three direct venv-Python Windows Service hosts:
- `CyberDefenderAgent`
- `CyberDefenderControlPlane`
- `CyberDefenderOwnerUI`

The install is successful only after all required preflights pass, all services reach `Running`, Control Plane and Owner UI pass HTTP health checks, and the Agent publishes fresh runtime state.

Check:

```powershell
.\scripts\service_status.ps1
```

Expected: all three services `Running`, start type `Automatic`.

If machine install fails, collect deterministic diagnostics with:

```powershell
.\scripts\collect_service_diagnostics.ps1
```

After services are healthy, open Owner UI without starting the agent from PowerShell:

`./scripts/open_owner.cmd`

or browse to `http://127.0.0.1:8775/owner`.

## C. Real local download telemetry test
After machine services are running, open:

`http://127.0.0.1:8785/download/cyberdefender`

A completed transfer increments **DOWNLOAD EVENTS** by exactly one. The Fleet & Distribution dashboard does not infer unique people from IP addresses.

## Uninstall machine services
Run elevated:

```powershell
.\scripts\uninstall_machine.ps1
```

By default ProgramData state is preserved. Use `-RemoveState` only when intentional permanent state deletion is desired.
