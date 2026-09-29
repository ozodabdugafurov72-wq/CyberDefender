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

## v0.1.6.1 — Windows DNS Cache Schema Compatibility Hotfix

The passive DNS reader accepts both current Windows `Name` / `Type` properties
and legacy/alternate `RecordName` / `RecordType` properties. Runtime telemetry
exposes `raw_rows_observed` so a successful PowerShell read cannot silently look
like an empty parsed cache. The hotfix changes no authority or active-network
behavior.

## v0.1.7 — Passive Interface Flow Telemetry Foundation

v0.1.7 adds local interface counter telemetry and bounded rate derivation.

Security and semantics contract:

- reads only local OS interface counters (`psutil.net_io_counters(pernic=True)`);
- performs no packet capture, pcap/sniffing, socket hook, active probe, DNS query,
  remote enrichment, packet injection, or firewall mutation;
- cumulative byte/packet counters are converted to deltas/rates only after a
  second valid sample;
- counter rollback/reset produces no negative or wrapped rate;
- aggregate RX/TX rates are scoped to active default-route interfaces;
- interface rates are NOT per-connection byte attribution;
- flow telemetry is non-authoritative and cannot grant trust or authorization;
- `flow rate != anomaly`, `high bandwidth != malicious`, and `traffic evidence != authorization`.

The network inventory outer schema becomes
`cyberdefender.network-inventory.v0.1.8` while DNS cache evidence remains on the
v0.1.6.1 compatibility reader.

## v0.1.8 — Flow Continuity & Accuracy Hardening

v0.1.8 decouples lightweight interface-rate sampling from the heavier passive
network inventory snapshot. A dedicated bounded daemon sampler reads only local
cumulative interface counters at a default 1 second cadence. The full
neighbor/DNS/connection inventory remains asynchronous and coalesced.

Accuracy/continuity contract:

- raw instantaneous rates come from the latest valid counter delta;
- 5 second and 30 second rolling mean/peak windows are published separately;
- sequence numbers, sample age, cadence, late samples, gap events, estimated
  missed slots, counter resets and sampling coverage are explicit;
- stale or post-suspend evidence is never silently presented as fresh;
- counter rollback starts a new baseline and cannot produce wrapped/negative rates;
- the runtime may refresh flow telemetry from bounded in-memory sampler state
  between full inventory collections; this fast path performs no PowerShell,
  DNS, socket enumeration, packet capture, or remote I/O;
- packet capture and per-connection byte attribution remain disabled;
- continuity percentage is a sampling-continuity estimate, not a packet-delivery
  guarantee and not an authorization signal;
- `high traffic != malicious`, `flow continuity != trust`, and
  `flow evidence != authorization`.

The network inventory outer schema is
`cyberdefender.network-inventory.v0.1.8` and the continuous flow schema is
`cyberdefender.interface-flow-continuity.v0.1.8`.

## v0.1.9 — Robust Flow Baseline / Anomaly Confidence Foundation

v0.1.9 adds an observation-only robust rolling baseline on top of the bounded
1-second passive interface counter sampler. The baseline uses median/MAD based
statistics, excludes the newest sample from its own training set, and exposes
an evidence-quality confidence score that is bounded by sample count,
continuity, and staleness.

The analyzer is deliberately non-authoritative. `anomaly_candidate=true` means
only that a local aggregate interface-flow deviation is worth downstream
correlation. It does **not** mean malware, does not create an incident, does not
change Risk Engine state, and never grants authorization. High traffic is not
itself treated as malicious.

Schemas:

- outer inventory: `cyberdefender.network-inventory.v0.1.9`
- continuous flow: `cyberdefender.interface-flow-continuity.v0.1.9`
- baseline analysis: `cyberdefender.flow-baseline.v0.1.9`

Safety remains unchanged: packet capture, active scan, packet injection,
firewall mutation, external enrichment, per-connection byte fabrication and
auto-whitelisting remain disabled.

## v0.2 — Policy-Gated Identity Verification Foundation

`agent/network/active_verification.py` provides an optional enrichment plane for
already observed peers. It is not enabled by the default runtime bootstrap.
Activation requires an explicit `cyberdefender.network-verification-policy.v0.1`
policy with a private allowlisted CIDR, bounded target/probe limits, internal
resolver addresses, and an operator approval reference.

The safest discovery order is passive observation first, followed by bounded
reverse-DNS and ICMP verification only for peers already present in the local
observation set. Broad subnet sweeps, arbitrary TCP port scans, external DNS,
mDNS/LLMNR, firewall changes, quarantine and response actions are outside this
foundation.

Verification results are evidence only. A DNS name or reachable ICMP response
does not change trust, enrollment, user identity or authorization. Explicit
`DENIED`/`REVOKED` registry evidence is surfaced as
`SUSPICIOUS_UNAUTHORIZED`; an unregistered peer remains
`OBSERVED_UNVERIFIED`/`UNKNOWN`. Out-of-scope or ambiguous targets fail closed
to `REVIEW_REQUIRED`. Cooldown, target, query, probe, timeout and resolver
limits are enforced before any optional network I/O.

## v0.3 — Identity, Segment and Attribution Semantics

Network rows keep separate `identity_state`, `trust_state`, `presence_state`,
and `user_binding` values. `endpoint_id` is the canonical enrollment identity;
hostnames, IP addresses, MAC addresses, and observed DNS names are provenance
evidence only. Duplicate hostnames therefore remain separate endpoint rows.

The passive collector may emit bounded evidence candidates such as
`NEW_MAC_FIRST_SEEN`, `UNENROLLED_ACTIVE_DEVICE`, `IP_MAC_CONFLICT`,
`GATEWAY_IDENTITY_CHANGED`, `RAPID_IP_CHURN`, `RAPID_MAC_CHURN`, and
`DNS_IDENTITY_MISMATCH`. These remain `OBSERVED_UNVERIFIED`, `SUSPICIOUS`, or
`REVIEW_REQUIRED`; they never authorize or execute a response. Gateway baselines
are keyed by interface, network segment, and gateway IP, so Ethernet and Wi-Fi
identities cannot be conflated.

The optional verifier role is `CENTRAL_ONLY`, with a finite operation budget and
single-worker concurrency. Passive refreshes are isolated behind the bounded
async worker; timeout and stale evidence are explicit and do not weaken local
protection. Process attribution exposes confidence and provenance while keeping
`VALID` separate from trust and authorization.

## Cross-plane freshness semantics

Fleet heartbeat liveness uses a 90-second `last_seen` threshold. Passive network
inventory uses a separate 120-second sample freshness threshold because it is a
local observation plane with a bounded collector timeout, not proof of Agent
heartbeat liveness. An endpoint may therefore be Fleet `OFFLINE` while a recent
passive network sample remains `fresh` during the 90-to-120-second interval.
The Owner UI keeps these planes separate: fleet rows show `OFFLINE`/`STALE`,
while the network panel labels observations as `ACTIVE`/`STALE` and remains
explicitly non-authoritative. No plane fabricates the other plane's liveness.

## Event family and lifecycle state

Owner event grouping uses endpoint-scoped family identity (normalized event
family code and explicit subject). Human-readable wording, source, severity,
and lifecycle state remain evidence attributes. An active warning and its
`_RECOVERED` observation therefore share one family with a historical count,
while `current_state` and `active_now` expose the current lifecycle state.
