# H1D9 university operator runbook

**Disposable lab only. No commands in this document authorize changes to the protected production HP host or a personal Acer.** No machine fault was executed during source preparation. Read the final prelab report and independently verify the package SHA before execution. Staff approval for the actual machine, checkpoint restore and each destructive branch is still required.

## Before installation

1. Staff designate a disposable VM (preferred) or university physical lab machine. Obtain permission, confirm no unrelated data, isolate networking and prove full C0 image recovery. Do not enable features, alter boot settings or create VMs without machine-owner approval.
2. Complete H1D9_LAB_DEPENDENCIES.md. Capture exact trusted Python/dependency versions and hashes. No offline dependencies are supplied by this package. Record time zone, UTC and pending reboot conditions.
3. On that target only, open an approved elevated Windows PowerShell shell. Copy the ZIP to C:\H1D9\input using staff-approved media. Set `$Archive` to its absolute path and `$Sha` to the separately delivered SHA-256. Compare `(Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()` with `$Sha`; stop on mismatch.
4. Extract into a new empty C:\H1D9\package. Never overlay another version or follow a junction. Keep the original ZIP. The package must contain manifest.json and payload. Staff may need approved script signing/execution-policy arrangements; do not bypass policy.
5. Set working directory and run read-only discovery:

```powershell
Set-Location C:\H1D9\package\payload
$Python='C:\Path\To\Approved\python.exe' # actual verified interpreter, not a placeholder
& .\scripts\h1d9\lab_preflight.ps1
```

6. Review all WARN/BLOCK findings, including explicit Python version checks from the dependency document. BLOCK stops the session. Record the actual machine UUID SHA and staff C0 checkpoint/image ID; never copy the production UUID or fabricate a VM identity.
7. Only after staff have actually confirmed every acknowledgement, create the bound 12-hour session:

```powershell
& .\scripts\h1d9\new_lab_session.ps1 -Archive $Archive -PackageSha256 $Sha -TargetUuidHash $TargetUuidHash -Checkpoint $C0 -StaffReference $StaffReference -EnvironmentType VM -StaffPermits -RecoveryVerified -NoUnrelatedData -DependenciesReady -NetworkIsolated -WarningsReviewed
$Runner='C:\H1D9\package\payload\scripts\h1d9\run_lab.ps1'
$Common=@{GuestAuthorization='C:\H1D9\authorization.json';Archive=$Archive;PackageSha256=$Sha;Python=$Python}
```

For an approved university physical lab use EnvironmentType UNIVERSITY_PHYSICAL_LAB, with an independently verified recovery image. The marker is an operator attestation, not machine attestation. Renew only with explicit `-Renew`, matching package/UUID and preserving the existing nonce. Never create a new nonce to hide a failed session.

## Baselines

8. `& $Runner @Common -Phase Preflight` must succeed with a new protected session root. The result root is C:\H1D9\results\ followed by authorization.lab_nonce. Record that as `$Results`.
9. `& $Runner @Common -Phase ConfirmC0 -Checkpoint $C0` acknowledges the already verified staff checkpoint.
10. `& $Runner @Common -Phase Install` installs only on the admitted disposable target. Stop on nonzero status; never repeatedly rerun a partly completed installation.
11. `& $Runner @Common -Phase C1Validate` independently checks installed hashes, services, HTTP, protected stores, progress and PYTHON_ONLY baseline.
12. Staff create and label C1 externally; `& $Runner @Common -Phase ConfirmC1 -Checkpoint $C1`.
13. `& $Runner @Common -Phase EnableRustCanary`; then `& $Runner @Common -Phase C2Validate`.
14. Staff create the immutable C2 checkpoint externally; `& $Runner @Common -Phase ConfirmC2 -Checkpoint $C2`. ConfirmC2 records a fresh independent observation tied to this ID. The final acknowledgement may not be inside the hypervisor snapshot; preserve current results externally whenever restoring.

## Controlled branches

15. Read the exact 26-case checklist in H1D9_CASE_CHECKLIST.md and test_catalog.json. Run one phase at a time. Examples, only after staff authorization:

```powershell
& $Runner @Common -Phase FixtureTests
& $Runner @Common -Phase Resources -Samples 30
& $Runner @Common -Phase Crash -Service CyberDefenderControlPlane
& $Runner @Common -Phase CleanRestart -Service CyberDefenderControlPlane
# Choose a separately authorized branch, not all commands blindly:
& $Runner @Common -Phase SCMStorm -Service CyberDefenderAgent
```

Each SCM storm consumes four lifetime debits for the named service, waits through finite configured recovery and observes 180 seconds without a fifth restart. It leaves ROLLBACK_PENDING. NativeHang targets only the identified canary child; it does not hang Python core work. StoreFault supports exactly one of truncate, corrupt, oversized, wrong-schema, wrong-service, delete-slot, delete-anchor and always requires restoration afterward. Standard-user ACL checks, stale/replay/wrong-owner/disk-full cases need separate staff-controlled fixtures or reviewed manual procedures; they are not certified by one StoreFault result.

16. For a C2 continuation:

```powershell
& $Runner @Common -Phase PrepareCheckpointRestore
```

Record the emitted state_sha256, export_sha256, export filename and nonce **outside the checkpoint**. Follow H1D9_CHECKPOINTS.md to copy and verify the entire latest results directory. Keep an untouched external copy. Staff restore the exact C2 image, reintroduce the verified package/authorization with the same session, and restore the current exported results with protected SYSTEM/Admin ACLs. Do not use the older ledger contained in C2. If any step is ambiguous, stop for review.

17. Staff create a restore receipt outside `$Results` (for example C:\H1D9\restore-receipt.json) from receipt_templates.json. Set package/machine/session/checkpoint/nonce/hash bindings to the externally preserved values. Read the current boot identity with the package's read-only `agent.service_lifecycle.boot_identity()` from the approved Python interpreter. Staff must explicitly confirm `restored: true` and `preserved_evidence: true`. Then:

```powershell
& $Runner @Common -Phase ResumeCheckpoint -Receipt C:\H1D9\restore-receipt.json -PreservedStateSha256 $PreservedStateSha256 -ExportSha256 $ExportSha256
```

This performs admission and read-only verification, not snapshot restoration or a fault. Successful continuation returns C2_BASELINE_PASS without completing any case. It preserves lifetime debits/evidence and opens only the bounded next branch. A duplicate resume is rejected without a second action. An interrupted resume or failed verification requires REVIEW_REQUIRED / DEGRADED_SAFE and staff review; it cannot be automatically retried. An operator can select final C0 recovery with PrepareRollback after review; never delete state to get another chance.

## Reboot, sleep and interruption

18. For clean reboot coverage, return to validated C2 with C2Validate, invoke PrepareReboot, preserve results externally, then staff explicitly reboot the disposable target. Re-establish shell variables/authorization and invoke PostReboot. The harness never reboots or schedules itself. Test interrupted/latched variants separately; a clean reboot does not complete the whole POWER-01 case.
19. PrepareSleep/PostSleep use the same explicit operator pattern. Record actual supported `powercfg /a` states and matching Windows sleep/wake events using selected timestamps/event IDs only. If unsupported, POWER-02 may be NOT APPLICABLE with evidence. Missing evidence is BLOCKED, not unsupported. No current-host sleep/wake action is authorized.
20. Hard power loss is HIGH RISK, operator-only and requires a verified disposable VM plus separate staff permission. PreparePowerLoss only flushes observations/state. Preserve/export evidence, then the operator may power off that VM through its manager; never power off the host or physical disk. PostPowerLoss compares fresh state after recovery. Without evidence of interruption during the targeted write window, record only a reboot/interruption observation, not atomic-write coverage. Prefer deterministic interrupted-write source fixtures; no unsafe storage failure simulation is automated.

## Evidence, decisions and final rollback

21. Supporting phase observations never imply a full mixed-case PASS. Create an operator-case receipt from receipt_templates.json outside `$Results`; store only sanitized supporting evidence files inside `$Results`. Required checks cover preconditions, expected results, absent fail conditions, complete evidence, verified recovery and **all variants**. Use `RecordOperatorCase -Receipt <absolute-receipt-path>` only after reviewing every catalog obligation. Missing tests stay BLOCKED. FAIL is sticky. Do not collect raw command lines, environment values, tokens, storage keys or full sensitive event logs; redact before import. FixtureTests exports exit/count summaries, not raw stdout/stderr. AUTH cases also require adversarial authority tests and cross-fault evidence.
22. Invoke `Report`, inspect LAB_REPORT.md, its SHA receipt and state evidence hashes. Export sanitized evidence before final `PrepareRollback`; staff restore C0 and restore the latest results as described above. `RollbackValidate` checks named service/app/state/Rust/port absence; staff additionally compare scheduled tasks, Registry and firewall baselines. Record the complete ROLLBACK-01 receipt only after those checks. Do not uninstall/erase production files or manually reconstruct C0 by deleting counters. The report stays INCOMPLETE unless all mandatory cases are genuinely complete; no report authorizes production deployment.

Resource bounds are stop conditions, not performance certification: one Resources phase samples 2–600 times with a 1,200-second deadline, free RAM/disk and growth tripwires. Run observation before/after selected fault branches and review matched windows; short baseline samples do not prove fault-loop resource safety. Arbitrary hung Python work is detectable but not safely auto-recoverable in H1D; worker isolation is outside this task.
