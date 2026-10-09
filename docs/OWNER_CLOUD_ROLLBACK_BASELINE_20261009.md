# Owner Cloud Rollback Baseline — 2026-10-09

This record freezes the last known production state before the secure cloud
Owner Dashboard work. It contains identifiers only and no credentials.

## Git baseline

- Commit: `306a28681f24ed295df18476671199815997c4f9`
- Branch at capture: `main`
- Tag: `rollback-owner-cloud-baseline-20261009`
- GitHub repository: `ozodabdugafurov72-wq/CyberDefender`

## Railway production baseline

- Project: `CyberDefender`
- Project ID: `b4cadbbc-3e29-4e88-b69c-b599d2a31a27`
- Environment: `production`
- Environment ID: `185f9365-8209-4e53-ae53-447466e2aaef`
- Distribution service ID: `e994f7da-466a-4e23-a3f7-ffe59a95b7a0`
- Active deployment ID: `5a761e06-0133-4546-b08b-63dfb4bfa1e5`
- Public domain: `cyberdefender-production.up.railway.app`
- Private domain: `cyberdefender.railway.internal`
- Region/replicas: US East / 1
- Healthcheck: `/health`, 60 seconds
- Restart policy: `ON_FAILURE`, maximum 10 retries
- Volume: `cyberdefender-volume`
- Volume ID: `a9fb66b4-a26d-4bca-b389-98ce61e9be49`
- Mount/size: `/data` / 500 MB

## Rollback

1. Do not wipe or detach the production volume.
2. Select deployment `5a761e06-0133-4546-b08b-63dfb4bfa1e5` in Railway and
   use Railway's redeploy/rollback action.
3. If source rollback is required, deploy tag
   `rollback-owner-cloud-baseline-20261009` or commit `306a286...`.
4. Confirm `/health`, package download, package SHA-256, and persistent
   distribution counters before declaring rollback complete.

The new Owner Dashboard uses a separate service and a separate volume. Its
rollback must never delete or replace this distribution volume.
