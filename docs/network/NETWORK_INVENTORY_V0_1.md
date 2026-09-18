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

## v0.1.4 — Process Attribution + Failure Forensics

Network Inventory v0.1.4 extends the passive/non-authoritative model without
changing authorization or action semantics.

### Connection → local process attribution

Each bounded local socket observation may carry local process evidence:

- PID and process create time;
- technical process name;
- executable path;
- local username observation;
- SHA-256 executable digest when bounded background enrichment completes;
- Windows Authenticode status and signer subject when available.

This is attribution evidence only. `SIGNED`, `HASHED`, `KNOWN`, and `RESOLVED`
never mean `AUTHORIZED`. The enrichment worker performs no external network I/O
and never executes the observed executable.

Executable hash/signature work is moved to one bounded daemon worker with a
small deduplicated queue/cache. Network collection can return `PENDING` or
`DEFERRED` enrichment rather than blocking the XDR security runtime.

### Async failure forensics

The network integration now retains recovery-safe diagnostics:

- `failures_total`;
- `consecutive_failures`;
- `last_failure_at`;
- `last_failure_type`;
- `last_failure_reason` (bounded);
- `last_failure_duration_ms`;
- `last_success_at` and `last_success_age_seconds`;
- explicit `stale` / `stale_after_seconds`.

A successful recovery clears the current `last_error` and resets consecutive
failures, but historical `last_failure_*` evidence remains available for the
current runtime session.

Security invariants remain unchanged: passive-only, no ping, no port scan, no
packet injection, no firewall mutation, no automatic authorization, and no
vendor inference from remote IP addresses.


## v0.1.5 — Explicit Trust Registry Foundation

The optional local `network_trust.json` registry is reloadable at runtime without
restarting the Agent. It remains evidence only: it cannot grant OS/network action
authority and the Admin surface remains read-only. There is no auto-whitelist.

Registry changes are detected by bounded file metadata checks. Missing or malformed
registry evidence fails safe to `UNKNOWN`; stale `AUTHORIZED` labels are not retained
when current evidence is invalid. Runtime telemetry exposes loaded-rule count, reloads,
failures and the last registry error.

Each matched peer exposes bounded trust evidence (`evidence_type`, optional
`evidence_ref`) with `authoritative=false` and `authorization=NOT_GRANTED`.


## v0.1.6 — Passive DNS Cache Correlation Foundation

v0.1.6 adds bounded, local-only DNS cache evidence to connection telemetry.

Security contract:

- reads the existing Windows DNS client cache with `Get-DnsClientCache`;
- does not issue DNS queries or reverse lookups;
- does not use DNS names as authorization or trust evidence;
- correlates cached A/AAAA records to already-observed remote connection IPs;
- publishes at most four cached names per connection;
- cache-reader failure degrades only optional DNS telemetry;
- active scanning, packet injection, firewall mutation, auto-whitelist, and remote enrichment remain disabled;
- `DNS cache match != trusted destination` and `DNS name != authorization`.

The network inventory schema is `cyberdefender.network-inventory.v0.1.6`.
