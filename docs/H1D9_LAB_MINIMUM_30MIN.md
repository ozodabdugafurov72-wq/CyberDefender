# H1D9 30-minute minimum session

Prerequisite: staff-approved disposable target, dependencies and tested C0 already available. Preparation/OS provisioning time is not included. If these prerequisites are missing, do not compress them into the test slot.

0–5 min: verify archive SHA against the independently delivered value; read-only preflight; confirm target identity, isolation, staff authorization and recovery image.

5–15 min: create session, Preflight, ConfirmC0, Install and C1Validate. Preserve independent service/ACL evidence. If installation exceeds the slot, stop and retain INCOMPLETE.

15–22 min: ConfirmC1, EnableRustCanary, C2Validate, ConfirmC2 and a short Resources observation. Verify Python authority, Rust non-authority, pin, one child and progress.

22–30 min: export sanitized evidence and report, perform staff-controlled final C0 restoration if there is enough time, run RollbackValidate and staff residue checks. If not, retain the isolated lab under staff ownership pending cleanup.

Do not attempt SCM storms, store tampering, power loss or all 26 cases in this mode. Missing cases remain BLOCKED; baseline authority observations do not complete cross-fault AUTH cases. This session cannot establish full H1D9 integration PASS.
