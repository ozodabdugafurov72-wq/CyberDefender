# TENQORVA Owner and Admin Control Panel Audit

## Scope and invariants

This audit covers the cloud read-only control surface. TENQORVA is presentation-only; Python service names, Railway private hostnames, CyberDefender protocol schemas, endpoint identity, signed-ingest rules, and action-authority boundaries are unchanged. The loopback dashboard in `dashboard_owner/` remains the reference implementation and is not exposed by the cloud image.

## Audited source

| Component | Existing responsibility | Data dependency |
| --- | --- | --- |
| `dashboard_owner/server.py` | Loopback Owner/Admin views, local runtime health, incidents, quarantine read model, Process Sensor Plane, fleet snapshot | Local state files, SQLite distribution DB, logs and quarantine vaults |
| `dashboard_owner/static/` | Existing feature organization and responsive local dashboard presentation | `/owner/api/*` and `/admin/api/state` |
| `owner_cloud/app.py` | Cloud authentication, sessions, RBAC, CSRF, audit, read-only dashboard | Owner SQLite DB and `DistributionClient` |
| `owner_cloud/distribution_client.py` | Fail-closed validation of private fleet APIs | Railway-private distribution service |
| `control_plane/cloud_soc_v2.py` | Signed tenant enrollment, heartbeat/event ingest, tenant fleet read model | Distribution SQLite DB |
| `docs/OWNER_CLOUD_SECURITY.md` | Cloud boundary and Railway variables | Deployment configuration |
| `Dockerfile.owner-dashboard` | Security-gated owner image | Secret scan and owner security tests |
| `RELEASE_NOTES_RUST_CANARY_ADMIN_OWNER_v1.md` | Local Owner/Admin and ProcessSensor provenance | Frozen runtime release line |

## Existing features and visual organization

The local reference provides fleet and endpoint lifecycle visibility, health and runtime components, incidents and classifications, quarantine evidence, Process Sensor Plane status, freshness and degraded states, plus distinct Owner/Admin routes. The original cloud surface provided a shared `/owner` page for both roles, aggregate fleet cards, endpoint evidence, event totals, XDR gates, signed response evidence, Owner audit, and a single `/api/v1/state` API.

The completed cloud surface retains the established overview → fleet → events → diagnostics → security organization, adds a dedicated `/admin` surface, and preserves explicit read-only/XDR security evidence.

## Cloud API contracts

### Browser-facing

| Route | Method | Role | Contract |
| --- | --- | --- | --- |
| `/owner` | GET | OWNER only | Owner dashboard with Owner-only audit panel |
| `/admin` | GET | ADMIN only | Admin monitoring and session dashboard; no audit panel |
| `/api/v1/owner/state` | GET | OWNER only | Tenant fleet, security gates, integration availability |
| `/api/v1/admin/state` | GET | ADMIN only | Same read-only operational evidence without Owner audit |
| `/api/v1/state` | GET | OWNER or ADMIN | Backward-compatible role-scoped state alias |
| `/api/v1/session` | GET | OWNER or ADMIN | Username, role, read-only flag and expiry |
| `/api/v1/audit` | GET | OWNER only | Bounded recent authentication/authorization audit |
| `/logout` | POST | OWNER or ADMIN + CSRF | Revokes the current session |
| `/api/v1/actions/*` | POST | Authenticated + CSRF | Always `403 READ_ONLY_MODE`; no action is executed |

Every protected route performs server-side authorization. UI hiding is not an authorization control.

### Private service-facing

The tenant-scoped dashboard calls `GET /api/v2/owner/tenants/{tenant_id}/fleet` with the dedicated read token over Railway private networking. The response schema remains `cyberdefender.fleet-read-model.v2` and now exposes only already-persisted trusted values:

- verified endpoint presence, health, service/resource state and installed runtime version;
- last verified heartbeat and freshness window;
- CPU/RAM only for fresh online endpoints;
- durable spool pending count, byte count and state from signed heartbeats;
- `accepted_through`, the server-persisted ingest sequence used as ACK progress;
- aggregate event counts and bounded recent event metadata (identifier, endpoint, type, priority and timestamps); no event payload is returned.

The Owner client accepts the prior v2 response shape for rolling deployment. Missing diagnostic fields become explicit `UNAVAILABLE` states rather than zero/healthy values.

## Roles

| Capability | OWNER | ADMIN |
| --- | --- | --- |
| Fleet, endpoint, health, runtime and version visibility | Yes | Yes |
| Detection/correlation summaries and recent event metadata | Yes | Yes |
| Spool and ACK diagnostics when exposed | Yes | Yes |
| Session information | Yes | Yes |
| Security access audit | Yes | No |
| Privileged endpoint operations | No | No |

## Data availability and non-fabrication

Sensor Plane, ProcessGraph, persistence-detail and quarantine-detail data exist in the local product but do not have authenticated tenant-scoped cloud read contracts. The cloud panels therefore show `UNAVAILABLE` with a concrete missing-contract reason. Quarantine event metadata may be shown when signed events exist, but it is never represented as vault/item status. Legacy signed response evidence is rendered only when the upstream contract declares that capability.

Fleet freshness uses the upstream `generated_at` and `online_after_seconds` values. The browser does not substitute its own fetch time as telemetry freshness.

## Security controls

- scrypt password verification; hashes and TOTP secrets are supplied only through secret variables;
- unique per-account TOTP with replay-resistant counters;
- host-only Secure, HttpOnly, SameSite=Strict session and pre-auth cookies;
- absolute and idle session expiry;
- pre-auth and session CSRF tokens;
- login rate limiting and persistent failure lockout;
- authentication failures, rate limits, lockouts, authorization denials, logout and denied actions are audited without credential material;
- strict Host/HTTPS validation, CSP, HSTS, clickjacking and MIME protections;
- tenant-bound private API token and fail-closed response validation;
- no cloud action authority.

## Frozen runtime boundary

No endpoint agent, sensor, ProcessGraph authority, quarantine executor, cryptographic admission rule, service name, or frozen runtime recovery branch is changed. The only control-plane change is the bounded, tenant-scoped read model projection of fields already authenticated and persisted by the existing cloud ingest path.
