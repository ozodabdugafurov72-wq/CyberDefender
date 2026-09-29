# Active Verification Activation Plan (Not Executed)

This plan is an operator-reviewed preparation document. It does not enable DNS
resolution, ICMP, or any active verification path by itself.

## Required operator inputs

- central observer node: `<operator-selected-central-endpoint-id>`
- approved lab CIDR: `<operator-approved-private-cidr>`
- approved internal DNS resolver: `<operator-approved-resolver-ip>`
- approval reference: `<operator-change-ticket-or-runbook-ref>`

The observer must be the single `CENTRAL_ONLY` verifier. Other endpoints remain
passive. Hostname, IP, MAC, DNS name, and ICMP reachability are evidence only;
none of them grants trust or authorization.

## Initial bounded policy

- `enabled`: `true` only after the operator approval gate succeeds
- `role`: `CENTRAL_ONLY`
- `allowed_cidrs`: exactly the approved private lab segment
- `resolver_addresses`: exactly the approved internal resolver, inside that segment
- `probe_methods`: `ICMP` only
- `max_targets`: 32 (lower if the segment policy requires it)
- `max_dns_queries`: 32
- `max_probes`: 32
- `timeout_seconds`: 1.0, never above the source-enforced bound
- `cooldown_seconds`: 30.0 or greater
- `operation_budget_seconds`: 5.0 or lower
- concurrency: 1

No public resolver, external DNS, mDNS, LLMNR, TCP port scan, packet capture,
packet injection, firewall mutation, or automatic blocking is permitted.

## Evidence and review

Each operation must retain policy/version, passive observation source, target IP,
interface/segment, method, bounded start/duration, result class, and timeout or
failure reason. Results remain `OBSERVED_UNVERIFIED`, `SUSPICIOUS`, or
`REVIEW_REQUIRED` unless explicit local trust evidence is `DENIED` or `REVOKED`.

## Rollback

1. Disable the policy and remove its operator approval reference.
2. Keep the passive inventory and historical evidence files.
3. Verify `active_scan_enabled=false`, `dns_resolution=false`, authority `NONE`,
   and authorization `NOT_GRANTED` in the read-only Owner/Admin view.
4. If verification telemetry is degraded, leave the central observer disabled and
   preserve the last-good passive snapshot for review.

Activation requires a separate operator approval and disposable/lab validation.
This document records no credentials, tokens, keys, endpoint secrets, or runtime
state.
