from __future__ import annotations

from agent.policy_engine import PolicyEngine


def check(label, condition):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    if not condition:
        raise AssertionError(label)

print('CYBERDEFENDER — POLICY ENGINE v1 FOCUSED + ADVERSARIAL TEST')
print('=' * 72)

engine = PolicyEngine(max_incidents=4)
check('Fresh PolicyEngine HEALTHY', engine.health_check()['status'] == 'HEALTHY')

low = {'incident_id':'I-LOW','risk_score':20,'risk_level':'LOW'}
high = {'incident_id':'I-HIGH','risk_score':85,'risk_level':'HIGH'}
critical = {'incident_id':'I-CRIT','risk_score':95,'risk_level':'CRITICAL','requested_action':'PROCESS_TERMINATE'}

r = engine.evaluate({'assessments':[low]})
check('Low risk assessment accepted', r['accepted'] is True)
check('Low risk remains OBSERVE_ONLY', r['assessments'][0]['action'] == 'OBSERVE_ONLY')
check('Low risk has no authorization', r['assessments'][0]['authorization'] == 'NOT_GRANTED')

r = engine.evaluate({'assessments':[high]})
item = r['assessments'][0]
check('High risk accepted', r['accepted'] is True)
check('High risk requires verification', item['policy_outcome'] == 'REQUIRE_VERIFICATION')
check('High risk recommends verification only', item['recommendation'] == 'ESCALATE_TO_INDEPENDENT_VERIFICATION')
check('High risk does not authorize', item['authorization'] == 'NOT_GRANTED')
check('High risk remains observe-only', item['action'] == 'OBSERVE_ONLY')

r = engine.evaluate({'assessments':[critical]})
item = r['assessments'][0]
check('Privileged request accepted as policy input', r['accepted'] is True)
check('Privileged request requires verification', item['requires_independent_verification'] is True)
check('Privileged request never authorized', item['authorization'] == 'NOT_GRANTED')
check('Privileged request never executed', item['action'] == 'OBSERVE_ONLY')

r = engine.evaluate({'assessments':[low]}, safety={'safe_mode':True})
check('Safe mode forces DENY', r['assessments'][0]['policy_outcome'] == 'DENY')
check('Safe mode remains fail-closed', r['assessments'][0]['action'] == 'OBSERVE_ONLY')

r = engine.evaluate({'assessments':[low]}, safety={'shutdown_requested':True})
check('Shutdown forces DENY', r['assessments'][0]['policy_outcome'] == 'DENY')

before = engine.health_check()['failed']
r = engine.evaluate({'assessments':[{}]})
check('Malformed assessment is rejected', r['incidents_rejected'] == 1)
check('Malformed assessment does not degrade health', engine.health_check()['failed'] == before)

r = engine.evaluate({'assessments':'not-a-list'})
check('Malformed top-level input rejected', r['accepted'] is False)
check('Malformed top-level input does not authorize', r['authorization'] == 'NOT_GRANTED')
check('Invalid input counter incremented', engine.health_check()['invalid_operations'] >= 1)

r = engine.evaluate({'assessments':[{'incident_id':f'I-{i}','risk_score':i} for i in range(20)]})
check('Incident evaluation is bounded', r['incidents_evaluated'] <= 4)
check('Bounded evaluation remains healthy', engine.health_check()['status'] == 'HEALTHY')

print('\nFINAL STATS')
print(engine.get_stats())
print('\nRESULT: PASS')
