# Cross-language Evidence Envelope v1

Purpose: a minimal **non-authoritative** envelope that Rust, Go, C#, C++ and Python producers can implement consistently. C implementations should sit behind a narrow wrapper rather than parse arbitrary JSON directly.

Required semantics:

- `schema_version = cd.evidence-envelope.v1`
- stable `event_id`, `tenant_id`, `producer_id`
- explicit `producer_language`
- finite positive timestamp
- explicit trust level (`SYNTHETIC`, `AUTHENTICATED`, `UNTRUSTED`)
- SHA-256 payload digest
- bounded unique evidence references
- `authorization = NOT_GRANTED` always
- current modes limited to `OBSERVE` or `SYNTHETIC`
- unknown fields/trailing payload rejected by strict decoders
- message acceptance never implies response authorization

Future transport/IDL selection (e.g. Protobuf) must preserve these semantics and be proven with golden fixtures before migration.
