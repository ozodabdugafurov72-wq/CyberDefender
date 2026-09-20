# Integration gaps — ACK integrity scope, 2026-09-20

1. **Separate next boundary task: trusted consumption admission binding.** A
   directly published, integrity-valid SecurityEvent can still reach the runtime
   consumer without cryptographic admission. This patch deliberately does not
   repair that boundary or claim that ACK success proves admission.
2. **Durability scope:** the existing transport is at-least-once. Incident
   publication is an in-memory queue acceptance, not a new durable incident sink.
   Duplicate suppression remains bounded and in-memory. A process crash after
   successful publication but before durable ACK does not gain a new cross-process
   exactly-once guarantee from this patch. No new recovery loop is introduced.
3. **H1D9 lab evidence:** actual disposable-machine fault/restore verification
   remains separate. Historical frozen snapshots are not regenerated here.
4. **Other capability work:** NDR, response, Go/Rust integration, AI and other
   roadmap features are outside this task. No live mitigation is enabled.

The ACK failure-propagation defect is addressed by this patch; final source test
results and any unresolved test failures are recorded in
`evidence/ack-integrity-20260920/REPORT.md`.
