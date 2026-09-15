# NDR v0.0: synthetic observation foundation

This opt-in Python package runs only supplied synthetic metadata. It captures no packets, opens no sockets, scans no hosts, installs no adapter and changes no production runtime. The integration tests exercise existing components with synthetic data; they establish no LAB_VERIFIED or PRODUCTION_VALIDATED capability.

## Data path and admission

Trusted fixture assembly supplies a SensorBinding (tenant, collector sensor/host, unique epoch/start time). FlowObservation validates that binding, strict bounded fields, IP/port/protocol/state/direction, timestamps and SYNTHETIC provenance. Unknown live/authenticated labels are rejected: they cannot manufacture authenticated ingress. A future live adapter must pass the existing Crypto/Replay admission path; a SHA-valid SecurityEvent alone is not authentication.

FlowObservation converts to the existing SecurityEvent NETWORK_FLOW contract. Reconnaissance analysis emits a separate NDR_RECON SecurityEvent, then the existing EventBus → SecurityEventBridge → CorrelationEngine → AttackGraph → RiskEngine path. Only the exact pending internally admitted detection digest may cross the bus callback; forged externally published bus events are rejected. Tenant+source+epoch identity is derived after integrity verification because the existing CorrelationEngine prioritizes entity_id and does not automatically tenant-prefix it. No CorrelationEngine changes were made.

Many destinations from one source share one incident within the existing correlator's window. Same target/many ports and same port/many targets have separate tested statistics. This is cross-target correlation from a bound collector, not a deployed multi-sensor enrollment or Family Mesh system. CorrelationEngine and AttackGraph retain their own existing clocks/limits; the new analysis window uses its fixture clock. Production replay persistence is not claimed.

Graph integration uses existing IP and INCIDENT nodes and CONNECTS_TO / OBSERVED_IN edges. Scan-like context is an attribute; no unsupported SCANNED or SERVICE node type was invented. Graph capacity failure degrades analysis; no ProcessGraph or sensor authority changes.

## Detector families and limits of inference

All families first require at least 75% refused/timed-out/SYN_SENT observations in the retained source group. UNKNOWN outcomes do not count as probes. Established browsing-like connections do not satisfy this predicate.

| Family | Synthetic threshold |
|---|---|
| PORT_SCAN / VERTICAL_PORT_SCAN | Four distinct ports on one target |
| HORIZONTAL_HOST_SCAN | Four targets on one port |
| MULTI_HOST_RECON | Four targets and at least two ports |
| BURST_RECON | A scan-like family plus eight probes within ten seconds |
| LOW_AND_SLOW_RECON | A scan-like family spanning at least 120 seconds |

Thresholds are initial fixtures, not calibrated production detections. Output says “scan-like reconnaissance behavior”; it does not identify Nmap or another tool. Approved scanners and known admin/security sources remain observable with evidence and LOW priority, while unknown sources default MEDIUM. Approved context comes from trusted configuration, never a self-asserted flow field. DNS, packet content, banners and fingerprinting are not collected or inferred.

The verified Catalog contains 2,000 DEFINED records. All remain DEFINED. The first 100 mappings preserve telemetry, context, independent evidence requirements and benign context. Only broad PORT_SCAN, HOST_DISCOVERY and SUBNET_SWEEP definitions are related to synthetic scan-like signals; the other selectors remain NOT_IMPLEMENTED. Generic family tests do not justify promoting every linked scenario. The sole observed evidence class is SYNTHETIC_FLOW, so Catalog's two independent evidence classes for future high-impact actions are not satisfied.

## Response boundary

NDR can produce an ActionIntent **proposal** in SIMULATE mode. It creates no ticket and grants no authority. Complete retained evidence, a current untampered detection, a valid clock and non-degraded state are required. More than eight contributing references, more than sixteen targets, capacity eviction, stale data or errors prevent a response proposal. Ordinary later traffic cannot refresh an older detection's age.

The proposal recomputes incident-only risk using the existing RiskEngine, matching the current ResponseControlPlane fixture contract. Graph-enriched analysis remains separately available; neither is authorization. An authorized fixture caller must assemble trusted evidence/target context and pass normal Response admission, Policy, SafetyAuthorizationGate/SafetyCore, no-op ActionGateway and independent fixture verification. Direct execution with no ticket and an AI principal both fail in integration tests. There is no real NETWORK_LIMITED executor or privileged rollback.

## Resource and restart policy

| Resource | Default / hard maximum | Cleanup/restart |
|---|---|---|
| Retained flows | 256 / 1,024; 2 KiB input each | 300s window, configurable 1–600s; explicit oldest eviction marks incomplete evidence |
| Active source entities | 32 / 128 | Expire when no retained flow; oldest entity eviction degrades evidence |
| Replay IDs | 4,096 / 8,192 per epoch | Never evicted to silently accept replay; full set rejects input and reports DEGRADED |
| Sensor epoch | 3,600s; 32 unique epochs per instance | Only explicit trusted new-epoch restart; old epoch reuse rejected |
| Approved context | 64 sources | Trusted fixture configuration |
| Output evidence / targets | 8 / 16 | Omitted count/completeness explicit; incomplete proposal denied |
| Registry / cached network definitions | 2,000 / 100 | Exact pinned bytes; defensive copies; no executable dispatch from Catalog |
| EventBus | 32 entries; 32 dispatches per observation | Existing bounded queue |
| CorrelationEngine | Existing 5,000 recent events, 1,000 incidents, 50 evidence entries per incident | Existing 60s correlation/compaction behavior |
| AttackGraph | 128 nodes, 256 edges, 300s TTL | Existing capacity rejection/expiry |
| Last detection/incident/risk/pending digest | One each | Replaced, never an unbounded history |

Window statistics use bounded work (including per-window cardinality comparisons); this is not a throughput benchmark. The 500-source synthetic fixture measured memory allocation under a 4 MiB test ceiling, with eight retained events/four active entities. Exact output is in the final test log. Capacity losses remain in lifetime eviction counts. Explicit new epoch clears current window/degradation/replay state and preserves epoch history and lifetime evictions. Process restart persistence requires future authenticated ingress; this opt-in module has no autonomous resume or background task.
