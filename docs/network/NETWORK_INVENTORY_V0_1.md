# CyberDefender Network Inventory v0.1

## Scope

Network Inventory v0.1 is a passive, non-authoritative observability plane for the local Windows endpoint.

It reads existing local operating-system telemetry only:

- adapter/address state through `psutil`;
- Windows neighbor-cache state through `Get-NetNeighbor`;
- existing local connection state through `psutil.net_connections`.

It does **not** perform ping, port scanning, packet injection, DNS discovery, firewall mutation, quarantine, or active host probing.

## Security invariants

- `UNKNOWN != UNAUTHORIZED`.
- Device identity is not user identity.
- A user identifier is exposed only when an explicit trusted binding marks it verified.
- Network inventory has `authority=NONE` and is not an authorization input in v0.1.
- Dashboard remains loopback-only/read-only and receives runtime-published state; browser JavaScript has no direct OS access.
- Active scanning remains disabled in v0.1.
- Collection failure does not grant authority or silently fabricate a healthy sample.
- Device/connection storage is bounded.

## Trust registry

Optional runtime registry path:

`<CYBERDEFENDER_STATE_DIR>/network_trust.json`

If absent, observed non-local devices remain `UNKNOWN`.

Use `config/network_trust.example.json` as the shape reference. The trust registry is configuration evidence only; it does not grant network or OS execution authority.

## Performance posture

Default sampling is once every 5 runtime cycles and can be changed with:

`CYBERDEFENDER_NETWORK_SAMPLE_EVERY_CYCLES`

Bounds:

- `CYBERDEFENDER_NETWORK_MAX_DEVICES` (default 256, hard cap 2048)
- `CYBERDEFENDER_NETWORK_MAX_CONNECTIONS` (default 256, hard cap 4096)

## Promotion boundary

v0.1 is passive inventory only. Governed active scanning belongs to a later version and requires separate Policy/Safety/authorization scope, rate limits, lab validation, and independent evidence.
