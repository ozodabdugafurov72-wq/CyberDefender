# AI Manipulation Hardening v1

## Security position

CyberDefender treats every AI/LLM/model output as **UNTRUSTED_ADVISORY_INPUT**. The model is useful for analysis, but it is not a policy engine, authorization service, evidence source of record, secret store, or privileged executor.

## Threats to defend against

- direct prompt injection and jailbreaks
- indirect prompt injection from web/email/docs/logs/images/QR/multimodal content
- RAG/vector poisoning and malicious retrieved instructions
- tool/plugin poisoning and spoofed tool output
- agent context/memory poisoning
- system-prompt leakage and secret extraction
- excessive agency / confused-deputy behavior
- model output manipulation / hallucination / misinformation
- training/fine-tuning data poisoning
- model artifact tampering/backdoors
- model theft / inference abuse
- cross-tenant context leakage
- prompt self-replication / autonomous propagation
- unbounded token/tool/cost consumption
- AI-generated phishing/deepfake/synthetic identity used against operators
- malicious coding-agent instructions, dependency hallucination and poisoned configuration/rules files

## Maximum-practical defense model

### 1. AI outside the TCB

The AI cannot mint `AuthorizationTicket`, directly call an OS actuator, change Policy/Safety, modify firewall/registry/service state, or mark verification PASS.

### 2. Capability broker, not general shell

AI receives narrow read-only tools. No generic `shell`, arbitrary URL fetch, arbitrary database write or unrestricted filesystem tool. Privileged actions are represented only as typed proposals which enter normal admission.

### 3. Complete mediation

Every proposed action is checked by deterministic code after the model call. No instruction in prompt, RAG content, memory or tool output can bypass Policy/Safety/Authorization.

### 4. Taint/provenance for context

Every context item carries source, tenant, trust level, timestamp, digest and evidence identity. External/retrieved content is explicitly tainted `UNTRUSTED_CONTENT`. Instructions found inside data are never promoted to system authority.

### 5. Retrieval isolation

Tenant-scoped retrieval, bounded top-k, allowlisted repositories, document provenance, freshness checks, content-type validation and poisoned-vector detection. RAG is evidence retrieval, not policy.

### 6. Tool-response verification

Tool output is schema-validated, size-bounded, provenance-bound and independently re-read for high-impact claims. Tool text cannot redefine tool permissions.

### 7. Memory isolation

No global cross-tenant AI memory. Short-lived scoped memory, integrity digest, provenance, TTL/size limits, no secrets, and explicit reset on model/session identity changes.

### 8. Model/data supply-chain controls

Pin model/artifact identities, hashes and signatures where available. Maintain SBOM/model bill of materials, dataset lineage, approved model registry and rollback. Treat downloaded model files, adapters and prompt templates as supply-chain artifacts.

### 9. Structured output + abstention

AI must emit a strict advisory schema. Required fields: hypotheses, supporting evidence, counter-evidence, uncertainty, data quality, recommended action and alternative. Invalid output is rejected. AI is allowed and expected to `ABSTAIN` when evidence is insufficient.

### 10. Probability is deterministic outside the LLM

Posterior/probability fusion must be computed in deterministic code. AI may interpret the result but cannot silently change it. Correlated evidence is discounted by dependency group.

### 11. High-impact two-source rule

A high-impact future action normally requires >=2 independent evidence classes, plus policy/safety and independent post-action verification. Model confidence never substitutes for evidence independence.

### 12. Egress and secret control

AI service receives only minimized context. Secrets/tokens/private keys are never placed in prompts. Model egress is allowlisted/audited. Sensitive raw telemetry can be summarized or tokenized before AI use.

### 13. Resource/cost bounds

Bound prompt size, retrieved documents, tool calls, recursive agent steps, wall time, memory, output tokens and retry counts. Exhaustion transitions to degraded safe state, never more autonomy.

### 14. Independent guard path

A deterministic guard checks AI output for schema, tenant, evidence refs, tool/action allowlists, stale context and manipulation indicators. Guard failure means `NOT_GRANTED`.

### 15. Adversarial validation

Maintain a permanent red-team corpus for direct/indirect/multimodal injections, poisoned RAG, tool poisoning, memory poisoning, fake authority text, forged tickets, cross-tenant data, malformed Unicode/encoding and cost-DoS patterns.

## Threat-model assumption: prompt injection is not perfectly preventable

The architecture assumes a model can eventually be manipulated by direct, indirect or multimodal content. Therefore the primary control is **impact containment**, not belief that prompt filtering is perfect. Model compromise must not imply policy compromise, capability compromise, tenant compromise or host compromise.

### Mandatory blast-radius controls

- AI process identity has no OS-admin/root token and no long-lived privileged credential.
- AI cannot hold or derive authorization signing keys.
- Tool capabilities are allowlisted, typed, short-lived, tenant-bound and read-only by default.
- Every tool response is data, never a new instruction authority.
- Retrieved/RAG content is tainted and provenance-bound; tainted content cannot change system policy.
- Model/session memory is tenant/session scoped, bounded and discardable.
- Model artifacts, adapters, prompts, tool manifests and vector indexes are supply-chain artifacts with digest/provenance.
- A compromised AI must still pass deterministic admission, Policy, Safety, narrow capability and independent verification.
- Failures/ambiguity transition to `ABSTAIN`, `REVIEW_REQUIRED` or `DEGRADED_SAFE`, never more autonomy.

### Agentic-AI attack classes kept in the permanent regression corpus

- AI agent tool invocation abuse
- context poisoning and tool-data poisoning
- tool/plugin description poisoning
- RAG poisoning / malicious retrieved instructions
- prompt self-replication and propagation attempts
- agent configuration modification attempts
- forged authority/ticket text
- cross-tenant context extraction
- multimodal hidden instructions
- resource-exhaustion loops and recursive agent storms

## Required advisory shape

```text
classification = UNTRUSTED_ADVISORY_INPUT
authorization = NOT_GRANTED
hypotheses[]
supporting_evidence[]
counter_evidence[]
posterior_probability (from deterministic engine)
data_quality
evidence_independence
epistemic_uncertainty
recommended_action
alternative_action
abstain = true/false
```

## Security invariant

Even a fully compromised AI model should be able to cause, at worst, a stream of rejected or review-required proposals — not privileged OS/network actions.

## Reference alignment

This design intentionally follows the direction of NIST AI RMF/GenAI Profile, CISA/NCSC Secure AI System Development, NSA AI Data Security guidance, OWASP GenAI risks (Prompt Injection, Excessive Agency, System Prompt Leakage, vector/embedding risks) and MITRE ATLAS agent/prompt/data-poisoning techniques.
