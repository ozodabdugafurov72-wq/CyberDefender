# Recovery prerequisites and stop rules

READY_LOCALLY: the frozen [H1D9 checkpoint procedure](../H1D9_CHECKPOINTS.md) defines explicit restore/export/receipt verification. Preserve that procedure and its bounded counters.

EXTERNAL_PREREQUISITE: staff prove C0 clean-image restoration before installation; record image/checkpoint identity, machine identity, timestamp and successful verification. Create C1 after clean installation and C2 after validated canary setup. Ensure enough storage for all images plus evidence. Evidence storage must survive guest rollback.

UNVERIFIED_UNTIL_LAB: after a fault branch leaves ROLLBACK_PENDING, use PrepareCheckpointRestore, export and hash the latest results outside the checkpoint, then staff restore the exact approved C2. Reintroduce the latest verified results with protected ACLs, not stale checkpoint state. ResumeCheckpoint requires the bound staff receipt and independent baseline observations. It never repeats an actuator or marks the full case PASS. Interrupted/ambiguous recovery stops in REVIEW_REQUIRED / DEGRADED_SAFE.

EXTERNAL_PREREQUISITE: assign emergency-stop authority to both operator and supervising staff; assign checkpoint restoration to the machine owner. At unexpected target identity, missing evidence, exhaustion of a fault budget, failed verification, resource tripwire or lost isolation, stop issuing commands. Preserve sanitized evidence and request staff recovery; never delete counters or continually retry.

UNVERIFIED_UNTIL_LAB: final C0 restore must prove service/app/state/native-child/port absence plus staff comparison of Registry, scheduled-task and firewall baselines. No current-host rollback is authorized. Response v0.1 has no real rollback actuator: it retains unchanged fixture state and requires review on ambiguity.
