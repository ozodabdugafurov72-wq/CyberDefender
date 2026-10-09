# Fleet and XDR Compatibility v1

## Scope

This release normalizes CyberDefender fleet identity and health telemetry for
read-only XDR consumption. It does not enable remote response actions. Local
protection remains authoritative and telemetry failure cannot grant authority or
stop the endpoint protection loop.

The mapping is pinned to the published OCSF 1.9.0 schema. Fleet inventory maps to
Discovery / Device Inventory Info (`category_uid=5`, `class_uid=5001`) with the
Collect activity (`activity_id=2`, `type_uid=500102`). The private export is:

`GET /api/v1/owner/xdr/ocsf/device-inventory`

It requires the Railway private hostname and the separate distribution read
credential. The public domain returns `404` for this path.

## Verified security properties

| Property | Implementation and verification |
| --- | --- |
| Payload integrity | SHA-256 body digest is included in the HMAC-SHA256 canonical request. Tampering is rejected before persistence. |
| Request authenticity | Fleet writes require both the bearer secret and a `cyberdefender.fleet.v1` signature. Tokens shorter than 32 bytes are rejected. |
| Replay resistance | Signed timestamp has a five-minute window. A 128-bit nonce is persisted in SQLite and duplicate use returns `409 REPLAY_DETECTED`. |
| Redirect safety | The endpoint client does not follow HTTP redirects, preventing credential forwarding to another origin. |
| Transport | Remote fleet origins must use HTTPS. Plain HTTP is accepted only for loopback integration tests and local control-plane use. |
| Identity integrity | Empty, traversal-like, control-character, and oversized endpoint identifiers are rejected. Hostnames and versions are bounded. |
| State integrity | Install, health, service, and resource states use explicit allowlists. Unknown supplied values are rejected instead of silently becoming healthy or unknown. |
| Input bounds | JSON only, 64 KiB maximum body, bounded strings and bounded capability lists. Errors return fixed codes without exception details. |
| Read separation | Fleet write token and Owner read token remain distinct. OCSF export is read-only and private-network gated. |
| Durable migration | Schema v1 databases migrate in place to v2 with telemetry metadata and replay nonces. Existing download and endpoint rows remain. |
| Dependency floor | Windows runtime dependencies are pinned to `psutil 7.2.2`, `cryptography 50.0.2`, and `pywin32 312`; the former `cryptography 46.x` range included versions affected by 2026 advisories. |

Automated coverage includes signature binding, stale timestamp, changed body,
duplicate nonce, missing signature, invalid identity/state, oversized request,
private/public export separation, real HTTP client/server exchange, and OCSF core
classification fields.

## Current interoperability boundary

| Capability | Current state | Required next work |
| --- | --- | --- |
| OCSF device inventory | Implemented and tested | Validate release artifacts against the compiled OCSF 1.9.0 schema in CI. |
| Runtime OCSF contract validation | Implemented for exported Device Inventory records | Add the official compiled-schema validator as a release-build cross-check. |
| Detection Finding (`class_uid=2004`) | Internal detections feed correlated incidents | Keep atomic detections local until their evidence/redaction policy is defined. |
| Incident Finding (`class_uid=2005`) | Mapper implemented and tested for create/update/close lifecycle, evidence IDs, tenant ID, severity, risk, and causal timestamps | Connect the durable local incident outbox only after the controlled local integration approval. |
| STIX 2.1 / TAXII 2.1 | Not implemented | Add only for threat-intelligence exchange; TAXII is not the fleet heartbeat transport. |
| Per-device identity | Shared bootstrap fleet secret | Replace with device-scoped credentials or certificates plus rotation and revocation. |
| Tenant isolation | No cloud tenant model | Add tenant identity at admission, storage, queries, audit, and export before multi-tenant use. |
| Active XDR response | Deliberately unavailable | Requires separate authorization, capability, verification, rollback, and lab gates. |

These boundaries are reported as unfinished capabilities, not successful gates.
Owner Dashboard must show only the implemented OCSF inventory status and must not
label the product as a complete XDR platform.

## Rollout

1. Deploy the server and Owner Dashboard to staging.
2. Use a staging-only fleet credential and a synthetic endpoint identity.
3. Verify signed register and heartbeat, tamper/replay/stale rejection, private
   OCSF export, dashboard rendering, persistence, and the existing download path.
4. Rebuild the endpoint package so client and server share the same protocol.
5. Promote distribution first, then Owner Dashboard. Existing unsigned fleet
   clients will fail closed and must upgrade before telemetry resumes.
6. Keep response actions disabled.
