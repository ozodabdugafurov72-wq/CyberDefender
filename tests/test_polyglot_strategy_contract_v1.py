import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def require(ok,msg):
    if not ok: raise AssertionError(msg)

m=json.loads((ROOT/'docs/architecture/LANGUAGE_OWNERSHIP_MATRIX_v1.json').read_text(encoding='utf-8'))
langs={x['language']:x for x in m['languages']}
for name in ['Rust','Go','C','C++','C#','Python']:
    require(name in langs, f'missing language {name}')
require('sole privileged enforcement dependency' in langs['Python']['authority_policy'], 'python authority boundary missing')

ai=(ROOT/'docs/security/AI_MANIPULATION_HARDENING_v1.md').read_text(encoding='utf-8')
for token in ['UNTRUSTED_ADVISORY_INPUT','AuthorizationTicket','Complete mediation','RAG','ABSTAIN','counter-evidence','AI outside the TCB']:
    require(token.lower() in ai.lower(), f'AI hardening missing {token}')

prob=(ROOT/'docs/security/PROBABILISTIC_INTELLIGENCE_CONTRACT_v1.md').read_text(encoding='utf-8')
for token in ['Probability != Truth','evidence_independence','dependency group','ABSTAIN','calibration']:
    require(token.lower() in prob.lower(), f'probability contract missing {token}')

threat=(ROOT/'docs/strategy/THREAT_HORIZON_2026_2036.md').read_text(encoding='utf-8')
for token in ['vulnerability exploitation','USB','low-and-slow','agentic AI','post-quantum','supply-chain']:
    require(token.lower() in threat.lower(), f'threat horizon missing {token}')


policy=json.loads((ROOT/'spec/AI_TRUST_BOUNDARY_v1.json').read_text(encoding='utf-8'))
require(policy['ai_in_tcb'] is False, 'AI entered TCB')
require(policy['authorization']=='NOT_GRANTED', 'AI authorization boundary broken')
require(policy['can_mint_authorization_ticket'] is False, 'AI can mint ticket')
require(policy['can_call_privileged_executor'] is False, 'AI can call executor')

fixtures=json.loads((ROOT/'spec/fixtures/probability_fusion_v1.json').read_text(encoding='utf-8'))
require(len(fixtures['cases']) >= 5, 'probability fixtures missing')
for c in fixtures['cases']:
    require(0.0 < c['expected_posterior'] < 1.0, 'posterior bound')
    require(c['authorization']=='NOT_GRANTED', 'probability granted authority')

sources=(ROOT/'docs/strategy/SOURCES_AND_ASSUMPTIONS_2026-09-14.md').read_text(encoding='utf-8')
for token in ['Verizon 2026','ENISA Threat Landscape 2025','OWASP','MITRE ATLAS','Post-Quantum']:
    require(token.lower() in sources.lower(), f'source ledger missing {token}')

print('POLYGLOT_STRATEGY_CONTRACT: PASS')
