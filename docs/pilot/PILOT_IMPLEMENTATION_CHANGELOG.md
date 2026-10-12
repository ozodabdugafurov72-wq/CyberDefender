# Pilot Implementation Changelog

Date: 2026-10-12

- Added lab-only restore request and restore capability contracts with exact scope, TTL, HMAC integrity, replay denial, operator approval, independent eligibility verification, and SafetyCore attestation.
- Added exclusive-create restore, SHA-256 verification, signed restore receipt, post-restore verification, and truthful pre/post-effect failure states.
- Added measured detection-to-response, gate-pipeline, filesystem-executor, and restore latency evidence.
- Added Owner read-model projection for quarantine, verified restore, receipt integrity, recovery state, reasons, attribution, and latency.
- Added a reproducible temporary-lab acceptance runner and committed JSON evidence.
- Added the bounded `cyberdefender.response-evidence.v1` fleet contract.
- Added signed response-evidence publishing to the endpoint fleet client.
- Added Distribution schema v3 with immutable response evidence storage and read-only summary projection.
- Added private Owner API response evidence and fail-closed Owner Cloud revalidation.
- Added a read-only cloud Owner panel for response counts, reasons, risk, verification, SHA-256, and latency.
- Added tamper, replay/scope, collision, migration, private transport, forged authorization, and UI contract tests.
