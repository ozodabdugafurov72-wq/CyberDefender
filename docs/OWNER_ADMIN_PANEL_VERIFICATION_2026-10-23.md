# TENQORVA Owner/Admin Panel Verification — 2026-10-23

## Result

Code gate: **GO for staging after Railway reauthentication**. Production gate: **NO-GO** until a staging deployment is independently exercised with real tenant telemetry and the Owner records approval.

No production deployment or promotion was performed.

## Provenance

- Branch: `codex/tenqorva-owner-admin-panel`
- Base: `c8f58f448021ebf579cf1f7ee16ce0b17bc35f80` (`origin/codex/cloud-soc-security`)
- Frozen runtime recovery branch: unchanged
- Runtime/agent authority: unchanged
- Deployment image: `Dockerfile.owner-dashboard`
- Commit: recorded after the final verification pass

## Verification evidence

| Gate | Result | Evidence |
| --- | --- | --- |
| Owner authentication | PASS | scrypt + TOTP login, secure session creation, Owner landing route tested |
| Admin authentication | PASS | Admin login lands on `/admin` |
| Role separation | PASS | ADMIN denied Owner page/state/audit; OWNER denied Admin page/state |
| Direct API restrictions | PASS | protected state APIs return 401/403 server-side; action routes always deny |
| CSRF | PASS | login, logout and denied action CSRF regressions |
| Session controls | PASS | absolute expiry, idle expiry, revocation and cookie attributes |
| Login rate/lock | PASS | sliding rate limit and persistent per-subject/client lock regressions |
| Authentication/authorization audit | PASS | denied anonymous API access, lock/rate outcomes, RBAC denial, logout and denied actions recorded |
| Tenant isolation | PASS | cross-tenant fleet read and endpoint binding rejected |
| Fleet accuracy | PASS | online state requires fresh verified heartbeat; summary is recomputed against endpoint evidence |
| Trusted diagnostics | PASS | signed spool counters/state and server-persisted accepted sequence preserved |
| Event investigation | PASS | bounded tenant-scoped event metadata; payload is not exposed |
| Unavailable behavior | PASS | absent upstream/API capabilities render `UNAVAILABLE`, never healthy/zero telemetry |
| Responsive UI | PASS | real-browser desktop and 390×844 mobile breakpoint inspection |
| Owner-only audit visual | PASS | present on Owner page, absent on Admin page |
| Privileged actions | PASS | no action implementation; `/api/v1/actions/*` returns `READ_ONLY_MODE` |
| Secret scan | PASS | `scripts/scan_repository_secrets.py` |
| Python syntax | PASS | `py_compile` on changed Python modules |
| Diff hygiene | PASS | `git diff --check` |
| Container build | NOT RUN | Docker executable is unavailable on the verification host |
| Staging deployment | BLOCKED | Railway connector requires reauthentication; Railway CLI is unavailable |

Automated runs:

- 29 targeted Owner cloud, distribution-client and Cloud SOC v2 security/HTTP tests: PASS.
- 20-test `test_owner*.py` discovery suite: PASS.

## Security review

The cloud service keeps scrypt password verification, TOTP replay prevention, host-only Secure/HttpOnly/SameSite=Strict cookies, session idle/absolute expiry, CSRF, login throttling/lockout, strict Host and forwarded-HTTPS checks, CSP/HSTS and server-side RBAC. Credentials, TOTP seeds and service tokens remain environment secrets; no replacement credential was generated or committed.

The browser receives only tenant-scoped read models. Event payloads, local vault contents, ProcessGraph detail and sensor internals are not exposed. Risk and detection data cannot authorize actions. The only new upstream read projection consists of values already authenticated and persisted by the signed v2 ingest boundary.

## Railway staging requirements (names only)

Owner dashboard service:

- `CYBERDEFENDER_ENVIRONMENT=staging`
- `CYBERDEFENDER_OWNER_ACCOUNTS_JSON` (sealed secret; replacement accounts only)
- `CYBERDEFENDER_OWNER_TOTP_SECRETS_JSON` (sealed secret; unique per enabled account)
- `CYBERDEFENDER_OWNER_TENANT_ID`
- `CYBERDEFENDER_DISTRIBUTION_PRIVATE_URL=http://cyberdefender.railway.internal:8080`
- `CYBERDEFENDER_DISTRIBUTION_READ_TOKEN` (sealed secret)
- `CYBERDEFENDER_OWNER_DB=/data/owner.db`
- `CYBERDEFENDER_OWNER_ALLOWED_HOSTS`
- `RAILWAY_PUBLIC_DOMAIN`
- persistent volume mounted at `/data`
- Dockerfile path `Dockerfile.owner-dashboard`
- health check `/health`

Distribution service:

- `CYBERDEFENDER_CLOUD_SOC_V2_ENABLED=1`
- tenant read-token mapping required by the existing v2 distribution configuration
- `CYBERDEFENDER_DISTRIBUTION_READ_TOKEN` for legacy compatibility if retained
- existing distribution DB persistence and private-network endpoint unchanged

No secret value belongs in Git, build arguments, logs, deployment notes or browser bundles. Previously shared temporary credentials must not be reused.

## Staging deployment procedure

1. Reauthenticate the Railway connector.
2. Push the reviewed commit and pin the staging Owner service source to that immutable SHA.
3. Stage configuration changes in the staging environment only; inspect the staged diff.
4. Confirm required sealed variables and `/data` persistence exist without reading or recreating secret values.
5. Commit the staged Railway changes and wait for the deployment to reach `SUCCESS`.
6. Record deployment ID, image/source SHA, build logs, domain and health evidence.
7. Verify Owner/Admin login with newly provisioned secrets, role/API separation, CSRF/rate/session controls, tenant isolation and real telemetry freshness.
8. Verify `/api/v1/actions/*` remains denied and inspect the Owner audit.
9. Run desktop/mobile browser checks against the staging URL.

Staging URL: **not available — deployment blocked by Railway reauthentication**.

## Production promotion plan

Production remains blocked until the staging checklist passes and the Owner explicitly approves the immutable staging SHA. Promotion must reuse that exact SHA and reviewed configuration, rotate any staging-only credentials, preserve the existing custom domain, and perform post-promotion authentication/RBAC/telemetry smoke tests. No database schema downgrade is required.

Rollback is to redeploy the immediately preceding successful Railway Owner/dashboard deployment and distribution deployment pair by recorded deployment IDs. The v2 read-model additions are backward-compatible: the Owner client accepts the prior response shape and renders missing diagnostics as unavailable. Do not roll back or modify the frozen runtime recovery branch.

## Known blockers

- Railway connector reauthentication is required before project/environment inspection or staging deployment.
- Docker is not installed on this verification host, so the multi-stage container build gate was not repeated locally; its component security tests and secret scan passed directly.
- Sensor Plane, ProcessGraph, persistence detail and quarantine detail still lack authenticated tenant-scoped cloud APIs and therefore remain intentionally `UNAVAILABLE`.
