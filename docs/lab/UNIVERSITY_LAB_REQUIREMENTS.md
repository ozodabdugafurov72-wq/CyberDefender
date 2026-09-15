# Disposable university lab requirements

This is preparation, not authorization to change any machine. H1D9 software pre-lab readiness does not establish lab validation.

| Requirement | Status | Acceptance evidence |
|---|---|---|
| Preserved H1D9 source package and separately delivered SHA | READY_LOCALLY | See LAB_EVIDENCE_PLAN.md; verify again on receipt |
| 2–5 disposable Windows 11 x64 machines/VMs, build 26100+ | EXTERNAL_PREREQUISITE | Staff inventory, owner permission, UUID binding; no production assets |
| Each target: 8 GiB RAM, 3 GiB available, 20 GiB NTFS disk free | EXTERNAL_PREREQUISITE | Guest preflight; reserve additional checkpoint/evidence storage |
| Hypervisor checkpoint or complete physical recovery image | EXTERNAL_PREREQUISITE | Full restore demonstration before installation |
| Isolated network and approved transfer media | EXTERNAL_PREREQUISITE | Staff-reviewed topology and reachability checks |
| Python and complete trusted offline dependencies | EXTERNAL_PREREQUISITE | UNRESOLVED; see LAB_DEPENDENCIES.md |
| Named operator, staff approver, emergency-stop and rollback owners | EXTERNAL_PREREQUISITE | Signed scope, time window, target IDs and allowed branches |
| Actual installation, services, SCM recovery, containment and rollback | UNVERIFIED_UNTIL_LAB | Complete H1D9 case evidence; no inference from unit tests |

Prefer disposable VMs managed by staff. Do not create a VM, enable Windows features, change boot settings, or alter the current production host under this document. A physical target requires an equally proven recovery image and explicit permission to erase its disposable state.
