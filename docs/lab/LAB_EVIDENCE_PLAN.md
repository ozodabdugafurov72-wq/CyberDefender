# Evidence preservation

READY_LOCALLY: preserved artifact is H1D9-c0ebb51fbeb17266ebe3a5a8.zip. SHA-256: `071ec3ff2b1c0bf07c84c84879a250a75f11ace127c25047bcc35c64c170be0d`. Source location: evidence/h1d9-prelab. Follow-on sprint evidence lives separately in evidence/post-h1d9-sprint; historical artifacts are not rewritten.

EXTERNAL_PREREQUISITE: staff provide a restricted evidence destination outside guest snapshots and a separately trusted hash/receipt channel. Hashes detect changes relative to a trusted receipt; replacing both evidence and receipt is outside an unanchored SHA boundary. Assign custody and access rights before collecting results.

UNVERIFIED_UNTIL_LAB: capture package identity, staff authorization reference, machine hash, checkpoint IDs, UTC timestamps, phase transition history, exit codes, sanitized service/PID relationships, selected event IDs, resource observations and verification results. Verify every evidence/report hash before import and after transfer. Export latest state before restore and retain earlier evidence append-only externally.

READY_LOCALLY: prohibit passwords, private/guard/storage keys, authorization MACs/tokens, raw command lines, full environments and unnecessary sensitive telemetry in exported reports. Response journal stores validated IDs, hashes, scoped decisions and synthetic observations, not gate capability MACs. Fixture events must be synthetic; the journal is not a general telemetry archive.

UNVERIFIED_UNTIL_LAB: missing, partial, corrupt or stale evidence cannot become PASS. Preserve FAIL and unexecuted variants explicitly. All-case completion requires the complete existing case checklist and independent recovery verification.
