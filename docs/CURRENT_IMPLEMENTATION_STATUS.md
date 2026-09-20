# Current implementation status — ACK integrity, 2026-09-20

Scope: source-only consumer success / ACK propagation. No deployment or response
authority changes. The EventBus admission-binding issue remains a separate task.

The starting Git tree was clean at `fb1e563a4ab5b6a1d81e2018a8e270e7f4876015`.
History attributes the newer main runtime to passive network changes, including
`18d7df4`, `db38cbb`, `3a52b73`, and `f9dd70f`. These changes are preserved.
Original files are backed up under `evidence/ack-integrity-20260920/backup`.

## Implemented change

The canonical consumer requires explicit adapter success before calling durable
ACK. Adapter and ACK errors remain contained and increment observable counters.
The engine retains its legacy `ingest(event)` behavior; the adapter opts into
strict failure propagation and enqueue-before-commit publication. Rejected
publication does not commit duplicate suppression. Existing duplicates can be
ACKed without republishing an incident within the engine's existing bounded window.

The durable pipeline, spool format, ACK atomicity, recovery schedule, EventBus,
Policy, Safety, verifier and privileged-action boundaries are unchanged.
The ownership diagnostic probe now delegates to the actual correlation engine;
all original assertions are retained.

## Evidence and limits

Focused tests exercise the real runtime consumer without starting the runtime,
services or sensors. They cover downstream failures, queue pressure, duplicate
delivery, ACK failure, and reopening a temporary durable spool after failed
publication. See `evidence/ack-integrity-20260920/REPORT.md` for final counts,
exact commands, initial failures and regression results.

The historical 86-script and 92-script closures remain historical evidence, not
certification of all subsequent source additions. This patch does not update the
frozen H1D9 package or claim production readiness.

LIVE DEPLOY: NOT PERFORMED.
