# Pilot Security Limitations

Date: 2026-10-12

- Real filesystem quarantine and restore are authorized only for one harmless file under an explicit marker-protected lab root. Production autonomous response remains disabled.
- The response evidence channel uses the existing strong fleet bootstrap HMAC secret. Per-device certificates, hardware attestation, and independent device revocation remain enterprise follow-up work.
- The general incident outbox is not connected to cloud ingest. This change carries only a strict, verified response-evidence record.
- The cloud Owner Dashboard is read-only. It cannot trigger quarantine, restore, policy, verification, or SafetyCore.
- The acceptance result measures this host and this harmless canary. It is not a universal endpoint latency guarantee.
- No live malware was used. Safe simulations and harmless canaries remain the pilot validation method.
- Byte-reproducible package output remains a separate task; semantic package parity is the current accepted baseline.
- The installed local Agent/ControlPlane/OwnerUI were not started or changed during this work. Controlled local integration still requires the previously requested owner approval.
