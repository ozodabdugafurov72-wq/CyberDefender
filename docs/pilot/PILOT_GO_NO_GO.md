# Pilot Go / No-Go

Date: 2026-10-12

## GO

- Commit and push the reviewed branch.
- Deploy this revision to the separate Railway staging Distribution and Owner services.
- Run unauthenticated denial, login/logout, RBAC, session expiry, rate limit, CSRF, health, download/manifest, persistent database, signed response ingest, private Owner read, and secret-scan gates.
- Demonstrate the read-only Owner evidence panel with a harmless, signed staging evidence record.

## NO-GO

- Production autonomous quarantine or restore.
- Starting or changing the installed local Agent, ControlPlane, or OwnerUI before the controlled integration plan is approved.
- Production promotion if staging response evidence, Distribution regression, persistence, or security gates fail.
- Claims of universal sub-second response based on one lab host.

Current decision: **GO for staging validation; NO-GO for production autonomous response.**
