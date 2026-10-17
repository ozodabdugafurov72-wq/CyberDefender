# CyberDefender Cloud SOC v2 contract

Status: review branch only; default disabled; no production deployment.
Protocol: `cyberdefender.cloud.v2`

## Trust and enrollment

The server creates a short-lived, single-use enrollment code bound to an authoritative tenant. An endpoint creates its Ed25519 key locally and sends only the public key to `POST /api/v2/enrollment`. The server assigns `tenant_id`, `endpoint_id`, `credential_id`, and credential generation. A consumed or expired code fails closed. The endpoint private key never crosses this API.

Enrollment requires exactly: `schema`, `one_time_code`, `agent_instance_id`, `device_public_key`, `hostname`, `runtime_version`, and `capabilities`. Body size is at most 64 KiB. The schema is `cyberdefender.enrollment.v2`.

## Signed ingest

- `POST /api/v2/endpoints/{endpoint_id}/heartbeat`
- `POST /api/v2/endpoints/{endpoint_id}/event-batches`

Each request includes protocol, credential ID, Unix timestamp, random nonce, monotonic sequence, body SHA-256, and Ed25519 signature headers. The signature covers protocol, method, exact path, credential ID, timestamp, nonce, sequence, and body digest. The server checks the credential's authoritative tenant/endpoint binding before accepting content. The durable nonce window is pruned by request age and capped at 2,048 entries per endpoint.

Heartbeat schema `cyberdefender.heartbeat.v2` is strictly typed and reports health, service, resource, runtime, component failure, cycle, CPU/RAM, and spool state. Event schema `cyberdefender.event-batch.v2` accepts 1–128 ordered events and at most 8 KiB of bounded JSON per event. Supported event types are `DETECTION`, `INCIDENT`, `ATTACK_GRAPH`, `RISK`, `QUARANTINE`, and `AUDIT`. Event payload keys use a closed telemetry allowlist; arbitrary credential, token, password, secret, and private-key fields cannot be admitted or stored. Only normalized validated structures are persisted.

Clock skew is at most 300 seconds. Nonces are durable and exact replay returns HTTP 409. Sequence gaps and conflicting idempotency keys return HTTP 409. A committed request returns `ACK`; a byte-identical request ID with a new nonce returns `DUPLICATE_ACK`. ACK is emitted only after the nonce, ingest record, event rows, and endpoint sequence commit together.

## Owner read model

`GET /api/v2/owner/tenants/{tenant_id}/fleet` is available only over the authenticated Railway private service boundary. Its bearer credential comes from the tenant-specific `CYBERDEFENDER_CLOUD_SOC_READ_TOKENS_JSON` map; all configured token values must be unique or the whole map fails closed. It returns at most 100 endpoints and aggregated event counts. ONLINE is derived from server receipt time inside a 30–300 second freshness window. Stale endpoints become OFFLINE and CPU/RAM values are withheld. Every response states `privileged_actions: DISABLED`.

The Owner Dashboard polls its own authenticated state route every 30 seconds. It validates the exact tenant ID, schema, counts, endpoint fields, freshness bounds, and event summary before rendering. Malformed or cross-tenant data makes the upstream state unavailable.

## Rotation and failure behavior

The repository supports a new public key generation with a bounded 0–900 second overlap, followed by revocation of old credentials or the whole endpoint. Rotation/revocation administration is deliberately not exposed as a public HTTP route in this release.

The v2 HTTP surface is hidden with 404 unless `CYBERDEFENDER_CLOUD_SOC_V2=1`. Remote response actions remain disabled. Local ControlPlane and the existing v1 protocol remain unchanged.

## Remaining production gates

Production still requires managed PostgreSQL, backup/restore evidence, HA and alerting, distributed rate limits, mandatory MFA through a reviewed IdP, staging deployment, one real endpoint integration, and Agent RUNNING/3x HEALTHY/STABLE evidence.
