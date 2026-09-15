from __future__ import annotations

import base64
import os
import tempfile

from agent.config import load_config
from agent.main import CyberDefenderRuntime
from agent.safety import SafetyCore


def check(label, condition):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)

print('CYBERDEFENDER — POLICY ENGINE v1 MAIN INTEGRATION TEST')
print('=' * 72)

old_state = os.environ.get('CYBERDEFENDER_STATE_DIR')
old_key = os.environ.get('CYBERDEFENDER_STORAGE_KEY_B64')
state_dir = tempfile.mkdtemp(prefix='cd-policy-')
os.environ['CYBERDEFENDER_STATE_DIR'] = state_dir
os.environ['CYBERDEFENDER_STORAGE_KEY_B64'] = base64.b64encode(b'P' * 32).decode()

try:
    runtime = CyberDefenderRuntime(SafetyCore(), load_config())
    check('PolicyEngine initialized', runtime.policy_engine is not None)
    check('PolicyEngine HEALTHY', runtime.policy_engine.health_check()['status'] == 'HEALTHY')
    check('RiskEngine HEALTHY', runtime.risk_engine.health_check()['status'] == 'HEALTHY')
    check('AttackGraph HEALTHY', runtime.attack_graph.health_check()['status'] == 'HEALTHY')

    risk = {
        'component':'RiskEngine','version':'1.0','accepted':True,
        'overall_risk_score':85,'overall_risk_level':'HIGH',
        'assessments':[{'incident_id':'INC-POLICY-001','risk_score':85,'risk_level':'HIGH'}],
        'authorization':'NOT_GRANTED','action':'OBSERVE_ONLY'
    }
    runtime.last_risk_result = risk
    result = runtime.update_policy()
    check('Policy update returned dict', isinstance(result, dict))
    check('Policy result accepted', result.get('accepted') is True)
    check('Policy requires verification for high risk', result.get('policy_outcome') == 'REQUIRE_VERIFICATION')
    check('Policy does not grant authorization', result.get('authorization') == 'NOT_GRANTED')
    check('Policy remains observe-only', result.get('action') == 'OBSERVE_ONLY')
    check('Policy recommendation is bounded to verification', result.get('recommendation') == 'ESCALATE_TO_INDEPENDENT_VERIFICATION')

    runtime.last_risk_result = {
        'assessments':[{'incident_id':'INC-POLICY-002','risk_score':95,'risk_level':'CRITICAL','requested_action':'PROCESS_TERMINATE'}]
    }
    result = runtime.update_policy()
    check('Privileged policy request processed', result.get('accepted') is True)
    check('Privileged policy request cannot authorize', result.get('authorization') == 'NOT_GRANTED')
    check('Privileged policy request cannot execute', result.get('action') == 'OBSERVE_ONLY')

    health = runtime.health_snapshot()
    check('Runtime health exposes PolicyEngine', 'policy_engine' in health)
    check('Runtime reports PolicyEngine HEALTHY', health['policy_engine']['status'] == 'HEALTHY')
    check('Runtime health exposes RiskEngine', 'risk_engine' in health)
    check('Runtime health exposes AttackGraph', 'attack_graph' in health)
    check('Policy failure counter remains zero', runtime.policy_engine_failures == 0)
    check('Overall runtime remains HEALTHY', health['runtime']['status'] == 'HEALTHY')

finally:
    if old_state is None:
        os.environ.pop('CYBERDEFENDER_STATE_DIR', None)
    else:
        os.environ['CYBERDEFENDER_STATE_DIR'] = old_state
    if old_key is None:
        os.environ.pop('CYBERDEFENDER_STORAGE_KEY_B64', None)
    else:
        os.environ['CYBERDEFENDER_STORAGE_KEY_B64'] = old_key

print('\nRESULT: PASS')
