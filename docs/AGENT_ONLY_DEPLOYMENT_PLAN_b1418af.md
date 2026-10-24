# CyberDefender Agent-only deployment plan

Status: REVIEW-ONLY. No PLAN, APPLY, probe, restart, or service mutation has been executed for this package.

## Candidate and pins

| Item | Value |
|---|---|
| Source commit | `bda8126b517a6c46c6078996c148d5d32164c4d0` |
| Candidate ZIP | `106398453f5c0d7d4056e58838c3c847b1d75b02473e199cb5511fe6cea7bd7d` |
| Runtime ZIP | `7368ccfc91f605b3f3aa96de804a950d1797699021a5236b66a607e643878bb2` |
| Installer | `6917043b433cc4eac884300ee301f230d54d436c4b4f500fcb9864c2b6a49d86` |
| Agent-only wrapper | `a329287270b32c53d05ef7404475733901c78c10f0cc99e851f2dc94adac818f` |
| Baseline commit | `c5030219ba3a996013b8ab0dda48f60743e5c665` |
| Baseline ZIP | `6240488d506d1fb7ebac264fa0a1dbc7c05e1a74c65d5a2667fc98603af346bf` |
| Transactional bundle A/B | `4c3d15b50dd23f94f59889fc36b4b6c391884e076b13fa3145d4df226dda16c6` |

The candidate archive contains `release/scripts/agent_release/agent_service_bootstrap.py`, `release/native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe`, and `PINNED_MANIFEST.json`. Git-to-ZIP byte provenance and A/B reproducibility passed. The Rust binary SHA-256 is `a8a8a4add316fd061901e7a8094daf0262dddd2fed1ebb948ce871d935746b44`.

## Installed baseline contract

The read-only service snapshot at 2026-10-24T09:50:06Z reported the Agent as `Stopped`, PID `0`, `Auto`, `LocalSystem`, with the pinned c503021 runtime and `--service-run` bootstrap command. The plan preserves this StartMode, service account, recovery configuration, and original binPath. ControlPlane and OwnerUI are read-only companions; their state, PID, account, StartMode, recovery configuration, and path must be identical before and after the operation.

The wrapper refuses any candidate, runtime, installer, or baseline hash that differs from the pins above. It never passes `-AuthorizeRecoveryProbe`, never calls `Start-Service`, `Stop-Service`, or `sc.exe`, and its default path is PLAN. It snapshots the spool tree by relative path, length, and SHA-256 and fails closed if the digest changes.

## Execution sequence

1. Operator opens an elevated PowerShell 5.1 session and verifies the wrapper, installer, candidate ZIP, runtime ZIP, and baseline ZIP hashes.
2. Run the wrapper without `-Apply`. It performs read-only service/companion/spool snapshots and invokes the reviewed installer in PLAN mode. Expected terminal output is `AGENT_ONLY_DEPLOY status=PASS code=PLAN_PASS apply=False exit=0`.
3. Review the PLAN output, current authenticated CrashGuard state, and the operator approval card. No probe is authorized by this wrapper.
4. Only after a separate exact Agent-only authorization, rerun the same wrapper with `-Apply -HostAcknowledgement AGENT_ONLY_AUTHORIZED`. The underlying installer is the only component allowed to change the Agent service and owns its transactional candidate/rollback sequence.
5. The wrapper requires unchanged companion snapshots and unchanged spool digest after the child exits. It records a bounded result and removes only its temporary stdout/stderr directory.
6. If APPLY passes, observe the normal release gate: `RUNNING`, three `HEALTHY` snapshots at least 60 seconds apart, then 15 minutes `STABLE`, with zero component and consumer failures. EICAR and staging heartbeat remain separate later gates.

## Rollback and abort contract

Abort before the child starts on any pin mismatch, missing/reparse input, unreadable spool, missing service, missing Agent-only acknowledgement, or existing result path. Abort after the child on a nonzero installer exit, missing health/pass marker, changed companion field, changed spool digest, changed Agent identity, or rollback read-back mismatch. The reviewed installer restores the prior Agent binPath, StartMode, account, recovery configuration, and starting state on its failure path; the wrapper verifies those values and reports `ROLLBACK_READBACK` if verification fails. The isolated rollback fixture passed. Live rollback has not been exercised and remains UNVERIFIED.

Expected Agent downtime is limited to the installer stop/switch/health transaction; the installer’s existing stop timeout is 45 seconds and its candidate health wait is bounded. ControlPlane, OwnerUI, ProgramData, and spool are not deployment targets.

## Evidence and blockers

Package-level wrapper checks passed 3/3, PowerShell parse returned zero errors, release-manager verification passed, Git-to-ZIP provenance passed, and the isolated rollback fixture passed. No live mutation occurred. Remaining prerequisites are an independent review of the new wrapper, a pushed commit and fresh read-only PLAN using the exact pins, a separate Agent-only authorization for APPLY, and live health evidence. The current cloud/MFA/PostgreSQL/backup/HA/tenant-monitoring gates are outside this laptop package and remain unverified.
