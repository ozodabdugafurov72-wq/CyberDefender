# CyberDefender Cloud SOC architecture gate

Evidence time: 2026-10-16T14:09:37Z  
Review branch: `codex/cloud-soc-security`  
Production mutation: none

## Decision and verified inventory

`https://app.cyberdefender-sec.uz/` is the canonical production Owner Dashboard. The local OwnerUI service on port 8775 is a compatibility component and is outside the production Owner Dashboard acceptance path. The Agent-only installer does not query, start, stop, reconfigure, or uninstall it.

| Area | Verified current state | Decision |
|---|---|---|
| Railway topology | Separate Distribution and Owner Dashboard services exist in staging and production; each has a persistent volume | PASS for separation; durability gate remains open |
| Production Owner | Custom domain `app.cyberdefender-sec.uz`, one Railway replica | PASS for canonical routing; NO-GO for HA |
| Production source | Active deployment message maps to commit `a33676c7e89e37c3d75918e7878186b023584897`, an ancestor of the review baseline | Ancestry verified; deployed artifact digest still needs attestation |
| Staging source | Active Distribution deployment message maps to commit `e0933a7897d4f5d7a50f5926b59cb9a5404d6e90`, an ancestor of the review baseline | Ancestry verified; staging must receive reviewed changes before production |
| Owner web security | Server-side OWNER/ADMIN RBAC, default-deny routes, CSRF, persistent hashed sessions, idle/absolute expiry, logout revocation, Secure/HttpOnly/SameSite=Strict cookies, brute-force lock, audit events, production HTTPS/Host checks and security headers | Focused tests PASS |
| Owner-to-Distribution | Authenticated read token over Railway private networking; redirects are rejected and credentials are not forwarded | PASS for current read-only link |
| Endpoint ingest | HMAC-SHA256 binds method/path/body/timestamp/nonce; nonce persistence rejects replay; payload and clock skew are bounded | Cryptographic request integrity PASS |
| Endpoint identity | A shared bootstrap secret authenticates all endpoints while `endpoint_id` is client supplied | **NO-GO: cross-endpoint impersonation is possible for any token holder** |
| Tenant isolation | Distribution tables, endpoint credentials, sessions, and read model have no authoritative tenant binding | **NO-GO** |
| MFA | No TOTP, WebAuthn, or external IdP MFA assertion is implemented | **NO-GO for production owner access** |
| Fleet freshness | Server computes online status from persisted `last_seen` with a 90-second window; signed request timestamps and nonces block simple replay | PASS for simple staleness; tenant-bound sequence/ACK is missing |
| Dashboard refresh | Authenticated bounded polling every 30 seconds | Acceptable initial design; SSE is optional after authorization tests |
| Privileged response | Cloud route is read-only and returns 403 for response actions | PASS; keep disabled |
| Database operations | SQLite on one persistent volume; no independently verified backup/restore, PITR, RPO/RTO, or replica failover | **NO-GO** |
| Monitoring/rollback | Railway health checks and restart policy exist; alert routing, SLOs, release attestation, and rehearsed rollback are unverified | **NO-GO** |

## Patch delivered on the review branch

The Owner Dashboard now validates every endpoint object returned by Distribution. Unknown fields, invalid identifiers, unsupported telemetry contracts, invalid lifecycle/resource states, and malformed or misordered timestamps make the upstream state unavailable. This prevents malformed or future unscoped fields from entering the SOC read model silently. The regression first failed against the previous implementation and then passed with the patch. This does not create tenant isolation; it provides a fail-closed boundary for the current schema.

## Target architecture

1. **Enrollment authority:** accept a single-use, short-lived enrollment code and issue a unique endpoint credential bound server-side to `tenant_id`, `endpoint_id`, credential generation, and revocation state. Never accept tenant membership from endpoint payloads.
2. **Telemetry ingress:** authenticate with the endpoint credential, validate the tenant/endpoint binding before parsing operational content, enforce body/count/time budgets, persist nonce and monotonic sequence state transactionally, and ACK only committed records.
3. **Endpoint outbox:** connect the existing durable local spool to a separate bounded priority fleet outbox. Preserve all admitted HIGH/CRITICAL evidence, use count and byte batch caps, capped exponential backoff with jitter and `Retry-After`, and never reset endpoint identity on network failure.
4. **Durable cloud store:** use managed PostgreSQL for enrollment, credentials, sessions, audit, ingest journal, and projections. Partition every security-relevant key and query by authoritative `tenant_id`. Keep raw ingest append-only and build fleet health as a replayable projection.
5. **Owner identity:** use an OIDC provider with mandatory MFA for OWNER/ADMIN. Bind the local session to issuer, subject, tenant, role, MFA/authentication-context, issued time, and revocation generation. Keep CSRF and strict cookies.
6. **Fleet read model:** derive ONLINE only from the latest committed tenant-bound heartbeat within its freshness window. A stale, replayed, revoked, or out-of-order record can only move the endpoint toward stale/offline, never toward healthy.
7. **Dashboard updates:** start with 15–30 second bounded polling. Add authenticated SSE only after connection limits, tenant-filtered queries, `Last-Event-ID`, revocation, proxy buffering, and reconnect backoff tests pass.
8. **Response boundary:** remote privileged actions remain disabled. Future response commands require Safety Core authorization, independent verification, per-endpoint command credentials, expiry, nonce, idempotency, audit, and a separate operator approval gate.

## Patch sequence and focused tests

| Phase | Change | Required focused tests |
|---|---|---|
| A | Server-issued tenant/endpoint enrollment and credential rotation/revocation | cross-tenant substitution denied; endpoint impersonation denied; revoked/expired generation denied; bootstrap replay denied |
| B | Transactional bounded ingest journal and sequence/ACK | duplicate idempotent; conflicting reuse denied; nonce replay 409; out-of-order cannot improve health; crash before commit yields no ACK |
| C | Durable priority endpoint outbox and adaptive delivery | restart/outage loses zero admitted events; HIGH/CRITICAL reserve; saturation fail-closed; 429/Retry-After; CPU/memory/disk/network budgets |
| D | Tenant-scoped projection and Owner queries | every query includes authoritative tenant scope; cross-tenant ID probing denied; stale endpoint cannot report ONLINE; malformed endpoint state denied |
| E | OIDC MFA and distributed session/rate-limit controls | MFA claim required; role downgrade/revocation invalidates session; CSRF; logout; distributed brute-force limit across replicas |
| F | Backup, restore, monitoring, and rollback | encrypted backup restore drill; RPO/RTO measurement; alert delivery; migration rollback/forward recovery; release digest attestation |

Existing focused Owner security tests and endpoint-response contract tests remain mandatory. The new malformed-endpoint regression is part of phase D.

## Deployment and rollback plan

1. Create a staging PostgreSQL instance and apply expand-only migrations. Take an encrypted backup before each migration and verify restore into an isolated database.
2. Deploy enrollment and ingest changes to staging with production response actions still disabled. Enroll one disposable endpoint with a staging-only credential.
3. Shadow-write the ingest journal and projection, then compare old and new read models without exposing synthetic ONLINE state.
4. Pass security, durability, resource, backup/restore, and cross-tenant tests. Record image digest, source commit, migration version, and configuration schema.
5. Deploy production database migrations first, then services by immutable image digest. Canary read-only Owner access and a single endpoint before widening enrollment.
6. Roll back application images to the last attested digest if health or authorization gates fail. Database changes use expand/contract migrations; rollback must not require destructive down-migration. Revoke only the affected endpoint credential generation.
7. Keep local protection and the local ControlPlane available during any cloud outage. Pending endpoint telemetry remains durable until acknowledged by cloud storage.

## Exact GO / NO-GO gates

Production Cloud SOC is GO only when all conditions below have recorded evidence:

- canonical HTTPS domain, HSTS, secure sessions, server-side RBAC, CSRF, mandatory MFA, logout/session revocation, and audit persistence pass;
- per-endpoint, tenant-bound credentials are issued, rotated, and revoked server-side; shared-secret cross-endpoint impersonation is denied;
- replay, stale, out-of-order, oversized, malformed, and cross-tenant telemetry cannot create or improve endpoint health;
- admitted endpoint events survive network loss, agent restart, server restart, 429 responses, and database failover without silent loss;
- fleet read queries and live updates are tenant scoped and cross-tenant probes are denied;
- production response actions remain disabled;
- encrypted backups restore successfully within approved RPO/RTO, alerts reach the operator, and deployment rollback is rehearsed;
- one staging endpoint shows matching signed local evidence, committed cloud ingest, and read-model state without synthetic claims;
- the Windows Agent independently reaches RUNNING, 3× HEALTHY, and the full STABLE window.

Current decision: **NO-GO**. The current cloud dashboard is suitable only for read-only staged validation until MFA, tenant-bound endpoint identity, durable cloud operations, and the local Agent health gates pass.
