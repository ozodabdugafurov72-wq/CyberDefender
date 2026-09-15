# Threat Registry v1.1 reference boundary

The JSONL is byte-for-byte from the independently verified user-supplied Catalog ZIP. Its SHA-256 is `e490b548af65e6b07f0770e7ac46838238dfaad45b226d90a737c6c1943cf71a`. ThreatRegistry refuses missing, changed, oversized or invalid data. It returns defensive copies; no catalog directive, candidate action or selector is executed.

All 2,000 stable IDs remain **DEFINED**, with PENDING test/lab statuses and NOT_CLAIMED production validation. Base severity is only a seed; final_risk remains DYNAMIC_ONLY. Detection, risk and AI cannot authorize actions. PolicyEngine → SafetyCore → IndependentVerifier remains mandatory for any future privileged response.

The shipped validator and schema were inspected and executed, then supplemented independently: the manifest is mandatory with exact file coverage, duplicate JSON keys are rejected, all status fields are checked and unsupported lifecycle promotions fail. The shipped schema allows extra properties and its validator permits an absent manifest; neither limitation is relied upon for admission here. The exact JSONL pin prevents accepting an altered future document through those gaps.

The ZIP SHA establishes a reproducible identity for the provided package, not publisher signature or original draft provenance. Package claims are not runtime evidence. See evidence/closure-catalog-ndr/catalog-independent-validation.json and docs/lab/NDR_V00_SYNTHETIC.md.
