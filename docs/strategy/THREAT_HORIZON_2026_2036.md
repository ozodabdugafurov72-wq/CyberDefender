# CyberDefender Threat Horizon 2026–2036

**Scope:** defensive planning scenarios, not predictions of specific attacks. The horizon is derived from 2025–2026 observed trends and then extrapolated conservatively for architecture planning.

## Current evidence baseline (observed, not forecast)

- Verizon DBIR 2026 reports that **31% of breaches start with software vulnerabilities**, **48% involve ransomware**, and **15% of attack techniques are being bolstered by generative AI**. These measurements justify prioritizing exposure/vulnerability context, ransomware/recovery, and AI-assisted adversary speed without assuming AI creates entirely new physics of attack.
- ENISA Threat Landscape 2025 reports **DDoS as 77% of reported incidents**, **phishing around 60%** of observed initial-intrusion methods and **vulnerability exploitation 21.3%**, while ransomware remains the most impactful EU threat. ENISA also highlights abuse of dependencies/supply chains and living-off-trusted-sites/land techniques.
- NIST AI RMF and the Generative AI Profile emphasize lifecycle governance, measurement and risk management; CISA/NCSC guidance applies Secure-by-Design principles to AI systems.
- OWASP explicitly notes prompt injection cannot currently be assumed perfectly preventable; it recommends constraining model behavior, validating outputs, least privilege and human approval for high-risk actions. CyberDefender therefore designs for **compromised-model containment** rather than perfect prompt filtering.
- MITRE ATLAS tracks agent-specific attacks including tool invocation, context/tool-data poisoning, RAG poisoning, prompt self-replication and agent configuration manipulation.
- NIST standardized ML-KEM/ML-DSA/SLH-DSA in FIPS 203/204/205 and recommends beginning migration; NIST transition planning targets deprecation/removal of quantum-vulnerable algorithms by **2035**, with high-risk systems earlier.

## Priority threat families

### P0 — design for now (2026–2028)

1. **Rapid vulnerability exploitation / edge appliances** — AI-assisted recon shrinks patch windows. Detect asset exposure, vulnerable edge/VPN/device context and exploit-like follow-on behavior.
2. **Identity/session theft** — credentials, tokens, cookies, OAuth/app consent, MFA fatigue/bypass and infostealers. Build identity-device-process-network correlation.
3. **Ransomware/extortion** — process/file velocity, privilege escalation, backup tampering, lateral movement and exfiltration correlation; recovery must be first-class.
4. **Third-party/supply-chain compromise** — signed-but-compromised dependencies, malicious packages/extensions, service-provider compromise, update-chain abuse.
5. **Stealth reconnaissance** — vertical/horizontal/distributed/low-and-slow scans, service discovery, route/topology discovery and scan behavior hidden in trusted services.
6. **Living-off-the-land / living-off-trusted-sites** — legitimate admin tools, cloud SaaS and trusted channels used for C2/exfiltration.
7. **AI-augmented social engineering** — spear phishing, smishing, vishing, synthetic identities/deepfakes and highly personalized fraud.
8. **Shadow AI / data leakage** — sensitive data submitted to unapproved AI systems, local model/tool leakage, unsanctioned agents.
9. **Agentic AI manipulation** — direct/indirect prompt injection, tool poisoning, context/RAG poisoning, memory poisoning, excessive agency and system-prompt leakage.
10. **Cloud/IAM/control-plane abuse** — workload identity, API token misuse, misconfiguration, privilege graph and cross-cloud lateral movement.

### P1 — build foundations now, mature 2028–2031

11. **Autonomous multi-stage adversary agents** — recon -> exploit selection -> credential use -> lateral movement at machine speed. Counter with bounded telemetry, attack graphs, deterministic admission and rate limits.
12. **Software-development AI supply-chain attacks** — poisoned rules/configuration for coding agents, slopsquatting/hallucinated packages, malicious build dependencies and generated insecure code.
13. **USB/removable-media attacks** — sensitive-copy anomalies, removable-media staging, executable launch chains, HID injection-like behavior, rogue USB NICs and driver/device anomalies.
14. **Firmware/boot/signed-driver abuse** — signed vulnerable drivers, boot persistence, firmware integrity and telemetry suppression.
15. **Container/Kubernetes/serverless compromise** — identity-heavy cloud-native attacks, image provenance, secrets and short-lived workload telemetry.
16. **OT/IoT/edge/cyber-physical** — device identity, firmware/config integrity, protocol baselines and segmentation. Safety impact matters more than raw malware count.
17. **Security-tool/evidence-plane attacks** — tamper with sensors, logs, AI context, risk inputs or verification. CyberDefender must detect attacks against itself.
18. **Data integrity/manipulation** — attackers alter evidence, business data or model context rather than merely stealing/encrypting it.

### P2 — prepare architectural agility for 2031–2036

19. **Post-quantum migration attacks** — downgrade/misconfiguration, legacy crypto discovery, certificate/signature migration gaps and harvest-now-decrypt-later risk. Crypto-agility must exist before a cryptographic emergency.
20. **AI ecosystem compromise at scale** — model theft, model backdoors, training/RAG poisoning, agent-to-agent trust abuse and poisoned tool registries.
21. **Cross-domain coordinated campaigns** — identity + endpoint + cloud + SaaS + mobile + physical/USB + OT signals combined into one campaign.
22. **Highly adaptive deception/evasion** — adversaries continuously tune behavior to detector thresholds. Prefer multi-window probability/graph evidence over single static thresholds.
23. **Next-generation edge/communications exposure** — 5G/6G/private wireless/satellite/industrial edge should enter as telemetry domains through the same identity/evidence contracts, not separate security silos.

## Required CyberDefender architecture consequences

- Multi-window bounded correlation: seconds -> minutes -> hours -> day.
- Entity/attack graph across user, process, host, IP, domain, cloud role, device, USB hardware and data object.
- Probability fusion must discount dependent evidence; repeated copies of the same sensor signal are not independent proof.
- Every hypothesis carries supporting evidence, counter-evidence, data quality, evidence independence and uncertainty.
- High-impact response needs multiple independent evidence classes and an independently verified outcome.
- Sensor/evidence integrity and anti-replay are first-class threat surfaces.
- The system must operate in degraded mode when cloud/AI/Python is unavailable.

## Sources consulted (current as of 2026-09-14)

- Verizon 2026 DBIR: https://www.verizon.com/business/resources/reports/dbir/
- ENISA Threat Landscape 2025: https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025
- Microsoft Digital Defense Report 2025: https://www.microsoft.com/en-us/security/security-insider/threat-landscape/microsoft-digital-defense-report-2025
- NIST AI RMF / Generative AI Profile: https://www.nist.gov/itl/ai-risk-management-framework
- CISA/NCSC Guidelines for Secure AI System Development: https://www.cisa.gov/news-events/alerts/2023/11/26/cisa-and-uk-ncsc-unveil-joint-guidelines-secure-ai-system-development
- OWASP GenAI Top 10: https://genai.owasp.org/llm-top-10/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
