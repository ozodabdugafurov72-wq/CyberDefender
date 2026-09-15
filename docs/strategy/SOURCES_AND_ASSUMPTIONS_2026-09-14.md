# Sources and Assumptions — 2026-09-14

This file separates **observed evidence** from **architecture inference** and **long-horizon planning scenarios**. Future threat items are not predictions.

## Current authoritative sources consulted

1. Verizon 2026 Data Breach Investigations Report — https://www.verizon.com/business/resources/reports/dbir/
   - Observed baseline used here: 31% vulnerability-led breach entry, 48% ransomware involvement, 15% attack techniques bolstered by GenAI.
2. ENISA Threat Landscape 2025 — https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025
   - Observed baseline used here: DDoS dominance by incident count, ransomware impact, phishing/vulnerability exploitation, supply-chain/dependency and LOTL/LOTS trends.
3. NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
4. NIST AI 600-1, Generative AI Profile — https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
5. CISA/NCSC Guidelines for Secure AI System Development — https://www.cisa.gov/news-events/alerts/2023/11/26/cisa-and-uk-ncsc-unveil-joint-guidelines-secure-ai-system-development
6. OWASP LLM01:2025 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
7. OWASP LLM06:2025 Excessive Agency — https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
8. MITRE ATLAS — https://atlas.mitre.org/
9. NIST Post-Quantum Cryptography — https://csrc.nist.gov/projects/post-quantum-cryptography
10. NIST FIPS 203/204/205 announcement — https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved

## Architecture inferences

The following are CyberDefender design decisions, not claims that a source mandates this exact architecture:

- AI is outside the privileged TCB.
- A compromised model should produce only rejected/review-required proposals.
- Rust/Go/C#/C++/C/Python have distinct ownership boundaries.
- Deterministic probability fusion is separated from LLM narrative reasoning.
- Multi-window/graph correlation is preferred to a single static scan threshold.
- Cross-language messages never carry implicit authority.

## Long-horizon planning scenarios

Items dated 2028–2036 are resilience scenarios. They are used to prevent architectural dead ends, not to claim that a particular attack will occur on a particular date.
