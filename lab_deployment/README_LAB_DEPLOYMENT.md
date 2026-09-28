# CyberDefender Agent-only university lab kit

This kit prepares sequential enrollment for lab labels `PC-JDU3` through `PC-JDU9`. A lab label is separate from the Windows hostname and endpoint identity. It is source-only and does not deploy, start services, change the current machine, or provide a central service package.

Do not rename university PCs unless separately authorized by university IT.

The package builder includes only the `agent/` source tree, `requirements.txt`, and the pinned release native process sensor. It rejects control-plane and Owner UI paths, credentials, key material, identities, databases, logs, runtime state, caches, and sensitive file extensions. The package contains no enrollment credential. The builder emits a versioned ZIP, a JSON manifest, and a SHA-256 sidecar.

## Required operator inputs

For each endpoint, provide:

- exact hostname `PC-JDU3` … `PC-JDU9`;
- the current central Control Plane URL, for example `http://<central-lab-ip>:8785`;
- the package ZIP and its SHA-256 sidecar;
- a temporary enrollment/fleet credential through a separate protected path.

Credential values are never command-line echoed or printed by the scripts. The installer copies the separately supplied credential to the endpoint’s protected secrets directory; it is not inside the ZIP.

## Build and sequential workflow

The builder requires an explicit, clean Git source checkout. It never defaults to the current working tree. For a release baseline, create or select an isolated checkout and pass its path:

```powershell
.\lab_deployment\BUILD_AGENT_ONLY_PACKAGE.ps1 `
  -SourceRoot C:\path\to\isolated\stable-agent-source `
  -OutputDirectory .\artifacts\lab-agent
```

The builder records the source commit and tree hash in the manifest and refuses a dirty checkout unless `-AllowDirtySource` is explicitly used for development-only work.

For `PC-JDU3`, verify or set the hostname first, then run the installer locally as Administrator with the explicit package path, package SHA-256, Control Plane URL, and separate credential path:

```powershell
.\lab_deployment\INSTALL_LAB_ENDPOINT.ps1 `
  -LabLabel PC-JDU3 `
  -ControlPlaneUrl http://<central-lab-ip>:8785 `
  -PackagePath .\artifacts\lab-agent\<package>.zip `
  -PackageSha256 <64-hex-sha256> `
  -EnrollmentCredentialPath <protected-temporary-file>
```

Run the verifier and require every local gate to pass. Leave `-SkipCentral` absent for the two heartbeat samples. Only after the central registration and heartbeat progression are confirmed should the operator proceed to `PC-JDU4`, then `PC-JDU5` through `PC-JDU9`, one endpoint at a time:

```powershell
.\lab_deployment\VERIFY_LAB_ENDPOINT.ps1 `
  -LabLabel PC-JDU3 `
  -ControlPlaneUrl http://<central-lab-ip>:8785
```

If any endpoint fails a security, integrity, service, health, or heartbeat gate, stop fleet expansion and investigate that endpoint. The scripts do not perform uncontrolled parallel enrollment.

Use `lab_endpoint_map.csv` for operator-side label, hostname, endpoint ID, and status tracking. It contains no credentials. The current fleet schema stores `endpoint_id` and `hostname`; it has no supported lab-label/display-name field, so the label is recorded locally in the Agent state and in this operator mapping until a future schema/UI change is approved.

For baseline proof, run the read-only capture on the existing successful endpoints:

```powershell
.\lab_deployment\CAPTURE_AGENT_BASELINE.ps1 -LabLabel PC-JDU -OutputPath .\PC-JDU_baseline_evidence.json
.\lab_deployment\CAPTURE_AGENT_BASELINE.ps1 -LabLabel PC-JDU2 -OutputPath .\PC-JDU2_baseline_evidence.json
```

Compare the two records, optionally against an explicit candidate checkout:

```powershell
.\lab_deployment\COMPARE_AGENT_BASELINE.ps1 `
  -EvidenceA .\PC-JDU_baseline_evidence.json `
  -EvidenceB .\PC-JDU2_baseline_evidence.json `
  -CandidateSourceRoot C:\path\to\candidate-checkout `
  -OutputPath .\agent_baseline_comparison.json
```

`PROVEN` requires complete matching evidence and an explicit candidate checkout. Any missing, conflicting, or uncertain evidence remains `NOT_PROVEN` or `MISMATCH`.

## Endpoint boundary

Each target receives only `CyberDefenderAgent`. The installer refuses to proceed if `CyberDefenderControlPlane` or `CyberDefenderOwnerUI` already exists. It preserves an existing endpoint identity and storage key, creates them locally when absent, restricts secrets and identity ACLs to SYSTEM and Administrators, provisions CrashGuard through the canonical module, installs one Automatic Agent service, and persists the supplied Control Plane URL in the Agent service environment.

Local protection remains independent of central telemetry. Registration and heartbeat are observational management telemetry and do not grant policy, safety, authorization, or response authority.

## Rollback

Run `UNINSTALL_LAB_ENDPOINT.ps1` on the target as Administrator to remove only the Agent service and application runtime. It refuses to operate when central services are present. Identity, storage key, fleet credential, state, logs, and CrashGuard evidence are preserved unless the explicit `-RemoveIdentityAndStorage` switch is supplied.

No firewall rule, port proxy, registry setting outside the Agent service environment, or central service is changed automatically by this kit. Any required narrow inbound Control Plane rule must be reviewed and applied separately by the lab operator.

## Output semantics

`PASS` means the stated gate was actually checked. `FAIL` stops the script immediately. `WAIT` means a deliberately skipped central check or an explicit operator follow-up; it is never reported as success.
