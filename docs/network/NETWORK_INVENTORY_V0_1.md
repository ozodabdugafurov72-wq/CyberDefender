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


## v0.1.2 semantics correction

- Neighbor-cache rows are not hotspot/AP connected-client counts.
- Current peer observation is restricted to active default-route interfaces.
- IPv4/IPv6 multicast and L2 broadcast/multicast control identities are excluded.
- The local endpoint is counted separately from observed peers.
- Default gateway evidence is labelled `GATEWAY`.
- `hotspot_client_count` remains `null` / non-authoritative unless an AP/controller source exists.
- Connection count is local socket/flow telemetry, never a device count.

## v0.1.3 integration hardening

Network collection is moved off the core runtime cycle into one bounded daemon
worker. Runtime cycles only request a refresh and consume the latest completed
good snapshot. Requests are coalesced to one pending refresh; no unbounded queue
is created.

A slow, failed, or stuck optional collector cannot block Detection, EventBus,
Correlation, Policy, Safety Core, Independent Verification, or dashboard
publication. Deadline overruns are observable in `runtime_integration` telemetry.
The worker never grants authority and does not add active scanning, packet
injection, DNS probing, firewall mutation, or response actions.

Shutdown waits for the optional worker only for a bounded interval. If the worker
has not exited, `close_incomplete` remains observable and process shutdown is not
held indefinitely.
