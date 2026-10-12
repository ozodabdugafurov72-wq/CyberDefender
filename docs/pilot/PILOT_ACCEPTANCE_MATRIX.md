# Pilot Acceptance Matrix

Date: 2026-10-12

| Gate | Result | Evidence |
|---|---|---|
| Real detector-to-response chain | PASS | Acceptance JSON contains the full pipeline trace and `HIGH_MEMORY_USAGE` detection |
| Millisecond measurement | PASS | 117.278 ms detection-to-response on this host |
| Exact-scope quarantine | PASS | Single-use capability, marker root, one bounded non-executable file |
| Independent post-action verification | PASS | `QUARANTINED_VERIFIED` |
| Verified recovery | PASS | `RESTORED_VERIFIED`, same SHA-256, restore receipt valid |
| Fail-closed collision/tamper behavior | PASS | Destination collision preserves quarantine; receipt tamper becomes integrity failure |
| Signed cloud evidence ingest | PASS | HMAC-bound method/path/body/time, nonce replay denial, strict contract |
| Private Owner transport | PASS | Private host plus distinct read credential required |
| Cloud Owner reason/evidence display | PASS | Read-only panel renders verified DB evidence with DOM `textContent` |
| Login, RBAC, secure session, logout | PASS | Owner Cloud security suite |
| CSRF and rate limiting | PASS | Login/logout/action CSRF and brute-force/API limiter tests |
| Secret exclusion | PASS | Capability MAC absent from records, APIs, UI, and acceptance evidence |
| Production autonomous action | BLOCKED BY DESIGN | `production_authorization=NOT_GRANTED` |
| Installed local endpoint integration | PENDING OWNER GATE | Controlled plan required before starting local services |
| Staging deployment of this revision | PENDING | Deploy only after commit/push |
