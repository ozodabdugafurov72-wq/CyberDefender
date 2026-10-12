# Pilot Test Evidence

Date: 2026-10-12

## Measured restricted-lab result

The acceptance runner used one harmless file in a newly created temporary marker-protected root. It did not start or modify the installed CyberDefender services.

| Measurement | Observed | Gate |
|---|---:|---:|
| Detection to verified response | 117.278 ms | ≤ 1000 ms |
| Policy/verifier/executor pipeline | 116.740 ms | ≤ 1000 ms |
| Filesystem quarantine executor | 98.094 ms | measured |
| Verified restore | 51.486 ms | ≤ 1000 ms |

Verified facts: source removed after quarantine; quarantine object, evidence, and receipt integrity passed; restored content matched the original SHA-256; restore receipt passed; Owner projection reported `RESTORED_VERIFIED`; cloud response contract validation passed; no capability MAC was exported; production authorization stayed `NOT_GRANTED`.

Machine-readable evidence: [restricted_lab_response_acceptance.json](evidence/restricted_lab_response_acceptance.json)

## Regression evidence

- 29 signed-ingest, response-evidence, private Distribution API, Owner authentication/RBAC/CSRF/session/rate-limit tests passed.
- 50 quarantine, restore, lifecycle, data-fidelity, multivault, and Owner evidence tests passed except two host-capability skips.
- 3 runtime file-activity wiring tests passed.
- 88 response safety foundation checks passed.
- 70 adversarial response safety checks passed.
- JavaScript syntax checks passed for both cloud and local Owner surfaces.

Host-capability skips: Windows symlink creation was unavailable; the isolated test runtime did not expose the pywin32 service host. Neither skip was counted as a product PASS.
