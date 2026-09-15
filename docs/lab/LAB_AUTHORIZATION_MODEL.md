# Staff and software authorization

EXTERNAL_PREREQUISITE: obtain named staff approval binding the disposable target UUID, package SHA, approved actions, time window, maximum fault counts, evidence destination and rollback owner. Approval for target A does not authorize target B. Staff separately authorize reboot, sleep, power interruption and each destructive branch. No current-production-host action is permitted.

READY_LOCALLY: the existing new_lab_session.ps1/run_lab.ps1 admission path binds package, target, session and acknowledgements. Preserve its immutable deny rules. The marker is an operator attestation, not cryptographic proof of a hypervisor. Do not fabricate staff acknowledgements or reuse an expired session.

READY_LOCALLY: response_control is an opt-in synthetic library with trusted caller-supplied Principal and FixtureContext. It installs no API endpoint or runtime subscription. Principal is not a user login or remote authentication implementation. Production authentication and ingress integration remain outside this sprint.

READY_LOCALLY: ActionIntent and AI advice grant no authority. The simulation path requires tenant/identity/evidence admission, RiskEngine, PolicyEngine, IndependentVerifier, SafetyCore/SafetyAuthorizationGate, BlastRadiusGuard, the existing no-op ActionGateway, independent fixture observation and RecoveryPlanner. OBSERVE and SIMULATE cannot become EXECUTE. A simulation ticket cannot authorize an OS action.

UNVERIFIED_UNTIL_LAB: verify admission rejection on the actual designated lab host before faults. Source tests are not staff approval. Real quarantine and its rollback remain unimplemented and unauthorized.
