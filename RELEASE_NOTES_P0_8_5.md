# CyberDefender P0.8.5 — Application & 24/7 Service Foundation

P0.8.5 moves CyberDefender from a developer-launched runtime toward a machine-installed Windows security application while preserving the P0.8.1 security boundaries.

## Windows Service foundation
- `CyberDefenderAgent`: automatic endpoint runtime service.
- `CyberDefenderControlPlane`: loopback distribution/fleet telemetry service.
- `CyberDefenderOwnerUI`: loopback Owner Master Control service.
- Services are configured for automatic startup and Windows restart recovery by `scripts/install_machine.ps1`.
- Runtime lifecycle is owned by `ServiceRunner 1.0`: graceful stop, deterministic repository close, fail-safe cycle handling.
- Machine state/secrets use `%PROGRAMDATA%\CyberDefender`; application code uses `%ProgramFiles%\CyberDefender\app`.
- Local machine identity and fleet bootstrap token are generated once and ACL-restricted to SYSTEM/Administrators.

## Real Fleet & Distribution telemetry
- Owner Master Control schema upgraded to v3.5.
- New Fleet & Distribution panel shows:
  - exact completed download transfer events,
  - registered/installed endpoints,
  - online/offline/degraded/critical status,
  - service state,
  - runtime version,
  - last heartbeat.
- Download counts come from the distribution endpoint itself, not estimates.
- A successful HTTP file transfer increments the completed-download count; failed/incomplete transfers do not count as completed.
- Endpoint enrollment and heartbeat APIs require the local bootstrap bearer token.
- Raw IP addresses and guessed user identities are not stored.
- `downloads_completed` is an exact transfer-event count, not a claim about unique people. Unique-user analytics requires a future authenticated website/account layer.

## Distribution artifact
- Machine install builds `%PROGRAMDATA%\CyberDefender\distribution\CyberDefenderPackage.zip`.
- Local real download endpoint: `http://127.0.0.1:8785/download/cyberdefender`.
- This proves the real telemetry path locally. A public website/control-plane deployment later exposes the same contract over TLS.

## Security boundaries preserved
- Policy and Independent Verification remain active.
- Safety Core remains the final local trust boundary.
- AI has no privileged authority.
- Real privileged OS action remains blocked / DRY-RUN only.
- Fleet/distribution data is non-authoritative and cannot grant endpoint response authorization.
- Owner UI remains loopback-only by default.

## Installer status
P0.8.5 contains the real Windows-service machine-install foundation, but the final signed `CyberDefenderSetup.exe/MSI` is NOT yet shipped. The one-time service bootstrap still uses an elevated PowerShell installer script. After installation, the three services auto-start at boot and daily operation no longer requires PowerShell. Code signing, native Setup.exe/MSI packaging, repair/upgrade UI and secure update signing remain the next packaging hardening step.
