"""Fixture-only response tests. No host services, processes or networking."""
import copy
import json
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from response_control.contracts import ACTIONS, RECOVERY, PROTECTIONS, Principal, advisory
from response_control.ledger import SimulationLedger, PATH
from response_control.simulation import FixtureContext, ResponseControlPlane
from agent.event import SecurityEvent
from agent.risk_engine import RiskEngine
from agent.attack_graph import AttackGraph


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='cd-response-fixture-')
        self.path=Path(self.tmp.name)/'journal.sqlite';self.key=b'x'*32;self.now=1000.
        self.ledger=SimulationLedger(self.path,self.key,create=True)
        self.event=SecurityEvent('DETECTION','HIGH',{'synthetic':True},'fixture','synthetic',event_id='e1',tenant_id='t1')
        self.incident=dict(incident_id='i1',tenant_id='t1',target_ids=['target1'],evidence_refs=['e1'],risk_score=90,severity='CRITICAL',event_count=1)
        self.target=dict(tenant_id='t1',target_id='target1',target_type='process',instance_id='instance1',protection_classes=[],classification_complete=True,asset_criticality=2,state='UNCHANGED')
        self.context=FixtureContext([self.event],{('t1','i1'):self.incident},{('t1','target1'):self.target})
        self.engine=ResponseControlPlane(self.ledger,self.context,clock=lambda:self.now)
        score=RiskEngine().assess(AttackGraph(),[self.incident])['assessments'][0]
        self.intent=dict(intent_id='intent1',incident_id='i1',tenant_id='t1',target_id='target1',target_type='process',action_type='PROCESS_QUARANTINE',request_source='OPERATOR',requested_by='alice',evidence_refs=['e1'],risk_snapshot={k:score[k] for k in ('risk_score','risk_level')},policy_context=dict(policy_version='1.0',duration_seconds=60,recovery=copy.deepcopy(RECOVERY)),created_at=1000,expires_at=1200,idempotency_key='once1',mode='SIMULATE')
        self.principal=Principal('t1','alice','OPERATOR',True)
    def tearDown(self):
        self.ledger.close();self.tmp.cleanup()
    def authorize(self):
        result=self.engine.prepare(self.intent,self.principal)
        self.assertEqual(result['state'],'AUTHORIZED_FOR_SIMULATION',result)
        return result['ticket']
    def denied(self,result):
        self.assertNotIn(result['state'],('VERIFIED','AUTHORIZED_FOR_SIMULATION'),result)
        self.assertIs(result['real_world_effect'],False)
    def restart(self):
        self.ledger.close();self.ledger=SimulationLedger(self.path,self.key)
        self.engine=ResponseControlPlane(self.ledger,self.context,clock=lambda:self.now)
    def test_valid_simulation(self):
        result=self.engine.simulate(self.authorize(),self.intent,self.principal)
        self.assertEqual(result['state'],'VERIFIED',result)
        row=self.ledger.read()['records']['intent1']
        self.assertEqual([h['state'] for h in row['history']],list(PATH))
        self.assertTrue(row['consumed']);self.assertEqual(result['verification_scope'],'SIMULATION_ONLY')
    def test_duplicate_intent(self):
        self.authorize();self.denied(self.engine.prepare(self.intent,self.principal))
    def test_duplicate_idempotency(self):
        self.authorize();self.intent['intent_id']='intent2';self.denied(self.engine.prepare(self.intent,self.principal))
    def test_ticket_replay(self):
        ticket=self.authorize();self.assertEqual(self.engine.simulate(ticket,self.intent,self.principal)['state'],'VERIFIED')
        self.denied(self.engine.simulate(json.loads(json.dumps(ticket)),self.intent,self.principal))
    def test_renamed_copied_ticket(self):
        ticket=self.authorize();copy_path=Path(self.tmp.name)/'renamed.json';copy_path.write_text(json.dumps(ticket))
        self.engine.simulate(ticket,self.intent,self.principal)
        self.denied(self.engine.simulate(json.loads(copy_path.read_text()),self.intent,self.principal))
    def test_ticket_expiry(self):
        ticket=self.authorize();self.now+=31;self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_ticket_tamper(self):
        ticket=self.authorize();ticket['payload']['mode']='EXECUTE';self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_wrong_session(self):
        ticket=self.authorize();self.restart();self.denied(self.engine.simulate(ticket,self.intent,self.principal))
        self.assertEqual(self.ledger.data['records']['intent1']['state'],'REVIEW_REQUIRED')
    def test_missing_evidence(self):
        self.intent['evidence_refs']=[];self.denied(self.engine.prepare(self.intent,self.principal))
    def test_unknown_evidence(self):
        self.intent['evidence_refs']=['unknown'];self.denied(self.engine.prepare(self.intent,self.principal))
    def test_tampered_evidence(self):
        self.context.events['e1']['message']='changed';self.denied(self.engine.prepare(self.intent,self.principal))
    def test_evidence_changed_after_authorization(self):
        ticket=self.authorize();self.context.events['e1']['message']='changed';self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_partial_evidence(self):
        second=SecurityEvent('DETECTION','HIGH',{'synthetic':True},'fixture','synthetic',event_id='e2',tenant_id='t1')
        self.incident['evidence_refs'].append('e2')
        self.engine.context=FixtureContext([self.event,second],{('t1','i1'):self.incident},{('t1','target1'):self.target})
        result=self.engine.prepare(self.intent,self.principal);self.denied(result);self.assertEqual(result['reason'],'INCIDENT_SCOPE_OR_PARTIAL_EVIDENCE')
    def test_unauthorized(self):
        self.denied(self.engine.prepare(self.intent,Principal('t1','alice','OPERATOR',False)))
    def test_ai_direct(self):
        self.intent['request_source']='AI';self.denied(self.engine.prepare(self.intent,Principal('t1','alice','AI',True)))
    def test_ai_forged_ticket(self):
        self.intent['request_source']='AI';self.denied(self.engine.simulate({'payload':{},'mac':'a'*64},self.intent,Principal('t1','alice','AI',True)))
    def test_cross_tenant(self):
        self.denied(self.engine.prepare(self.intent,Principal('t2','alice','OPERATOR',True)))
    def test_policy_denial(self):
        self.engine.policy.evaluate=Mock(return_value={'accepted':True,'policy_outcome':'DENY'});self.denied(self.engine.prepare(self.intent,self.principal))
    def test_policy_exception(self):
        self.engine.policy.evaluate=Mock(side_effect=RuntimeError('secret-do-not-export'));result=self.engine.prepare(self.intent,self.principal);self.denied(result);self.assertNotIn('secret-do-not-export',json.dumps(self.ledger.data))
    def test_safety_denial(self):
        self.engine.safety.health_snapshot=Mock(return_value={'safe_mode':True,'shutdown_requested':False});self.denied(self.engine.prepare(self.intent,self.principal))
    def test_gate_exception(self):
        self.engine.gate.authorize_dry_run=Mock(side_effect=RuntimeError());self.denied(self.engine.prepare(self.intent,self.principal))
    def test_policy_changed(self):
        ticket=self.authorize();self.engine.policy.evaluate=Mock(return_value={'accepted':False});self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_safety_changed(self):
        ticket=self.authorize();self.engine.safety.health_snapshot=Mock(return_value={'safe_mode':True});self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_conflicting_intents(self):
        self.authorize();self.intent.update(intent_id='intent2',idempotency_key='once2');self.denied(self.engine.prepare(self.intent,self.principal))
    def test_interrupted_simulation(self):
        ticket=self.authorize();self.engine.gateway.execute_dry_run=Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):self.engine.simulate(ticket,self.intent,self.principal)
        self.assertTrue(self.ledger.data['records']['intent1']['consumed']);self.restart()
        self.denied(self.engine.simulate(ticket,self.intent,self.principal));self.assertEqual(self.ledger.data['records']['intent1']['state'],'REVIEW_REQUIRED')
    def test_interrupted_authorization(self):
        self.engine.gate.authorize_dry_run=Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):self.engine.prepare(self.intent,self.principal)
        self.restart();self.denied(self.engine.prepare(self.intent,self.principal))
    def test_missing_ledger(self):
        with self.assertRaises(ValueError):SimulationLedger(Path(self.tmp.name)/'missing.sqlite',self.key)
    def test_corrupt_ledger(self):
        self.ledger.db.execute("UPDATE journal SET mac='bad'")
        self.denied(self.engine.prepare(self.intent,self.principal));self.assertTrue(self.engine.blocked)
    def test_corrupt_marker(self):
        self.ledger.marker.write_bytes(b'bad');self.denied(self.engine.prepare(self.intent,self.principal))
    def test_stale_ledger(self):
        old=self.ledger.db.execute('SELECT payload,mac FROM journal').fetchone();self.authorize()
        self.ledger.db.execute('UPDATE journal SET payload=?,mac=?',old)
        self.denied(self.engine.prepare(self.intent,self.principal));self.assertTrue(self.engine.blocked)
    def test_clock_backward(self):
        ticket=self.authorize();self.now-=1;self.denied(self.engine.simulate(ticket,self.intent,self.principal));self.assertTrue(self.engine.blocked)
    def test_clock_forward(self):
        ticket=self.authorize();self.now+=301;self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_audit_write_failure(self):
        self.ledger.commit=Mock(side_effect=OSError());self.denied(self.engine.prepare(self.intent,self.principal));self.assertTrue(self.engine.blocked)
    def test_partial_write_atomic(self):
        initial=copy.deepcopy(self.ledger.data)
        self.ledger.db.execute("CREATE TRIGGER reject_write BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT,'fixture'); END")
        self.denied(self.engine.prepare(self.intent,self.principal));self.assertEqual(self.ledger.read(),initial)
    def test_verifier_exception(self):
        ticket=self.authorize();self.engine.verifier.verify=Mock(side_effect=RuntimeError());self.denied(self.engine.simulate(ticket,self.intent,self.principal))
        self.assertEqual(self.ledger.data['records']['intent1']['state'],'REVIEW_REQUIRED')
    def test_verifier_failure(self):
        ticket=self.authorize();self.engine.verifier.verify=Mock(return_value={'verified':False});self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_missing_recovery_plan(self):
        self.intent['policy_context'].pop('recovery');self.denied(self.engine.prepare(self.intent,self.principal))
    def test_recovery_denied(self):
        ticket=self.authorize();self.engine.recovery.plan=Mock(return_value={'accepted':False});self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_recovery_failure(self):
        ticket=self.authorize();self.engine.recovery.plan=Mock(side_effect=RuntimeError());self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_interrupted_recovery(self):
        ticket=self.authorize();self.engine.recovery.plan=Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):self.engine.simulate(ticket,self.intent,self.principal)
        self.restart();self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_missing_prestate(self):
        self.engine.context.observe=Mock(return_value={});self.denied(self.engine.prepare(self.intent,self.principal))
    def test_stale_prestate(self):
        original=self.context.observe('t1','target1',self.now-6);self.context.observe=Mock(return_value=original);self.denied(self.engine.prepare(self.intent,self.principal))
    def test_duplicate_state_transition(self):
        self.authorize()
        with self.assertRaises(ValueError):self.engine._step('intent1','AUTHORIZED_FOR_SIMULATION')
    def test_skipped_verification_transition(self):
        self.authorize()
        with self.assertRaises(ValueError):self.engine._step('intent1','VERIFIED')
    def test_bounded_retention(self):
        self.ledger.MAX_RECORDS=1;self.authorize();self.intent.update(intent_id='intent2',idempotency_key='once2');self.denied(self.engine.prepare(self.intent,self.principal))
    def test_no_ticket_secrets_in_ledger(self):
        ticket=self.authorize();raw=json.dumps(self.ledger.read());self.assertNotIn(ticket['mac'],raw);self.assertNotIn('token_mac',raw);self.assertNotIn(self.key.decode(),raw)
    def test_duplicate_event(self):
        with self.assertRaises(ValueError):FixtureContext([self.event,self.event],{}, {})
    def test_ai_advisory_only(self):
        result=advisory(dict(analysis='synthetic',hypothesis='synthetic',confidence=1,attack_chain='synthetic',recommended_action='PROCESS_QUARANTINE',evidence_refs=['e1'],explanation='synthetic'))
        self.assertEqual(result['authorization'],'NOT_GRANTED')
    def test_cancellation(self):
        ticket=self.authorize();self.assertEqual(self.engine.cancel('intent1',self.principal)['state'],'CANCELLED')
        self.denied(self.engine.simulate(ticket,self.intent,self.principal));self.assertEqual(self.engine.cancel('intent1',self.principal)['state'],'DENIED')
    def test_wrong_tenant_cancel(self):
        self.authorize();self.assertEqual(self.engine.cancel('intent1',Principal('t2','alice','OPERATOR',True))['state'],'DENIED')
    def test_observe_mode(self):
        self.intent['mode']='OBSERVE';self.assertEqual(self.engine.simulate(self.authorize(),self.intent,self.principal)['state'],'VERIFIED')
    def test_ai_missing_evidence(self):
        with self.assertRaises(ValueError):advisory(dict(analysis='',hypothesis='',confidence=1,attack_chain='',recommended_action='PROCESS_QUARANTINE',evidence_refs=[],explanation=''))
    def test_ai_malformed_reference(self):
        with self.assertRaises(ValueError):advisory(dict(analysis='',hypothesis='',confidence=1,attack_chain='',recommended_action='PROCESS_QUARANTINE',evidence_refs=['../secret'],explanation=''))
    def test_ai_wrong_tenant(self):
        self.intent.update(request_source='AI',tenant_id='t2');self.denied(self.engine.prepare(self.intent,Principal('t1','alice','AI',True)))
    def test_ai_high_confidence_policy_deny(self):
        advisory(dict(analysis='',hypothesis='',confidence=1,attack_chain='',recommended_action='PROCESS_QUARANTINE',evidence_refs=['e1'],explanation=''))
        self.engine.policy.evaluate=Mock(return_value={'accepted':False})
        self.denied(self.engine.prepare(self.intent,self.principal));self.engine.policy.evaluate.assert_called_once()
    def test_ai_advice_cannot_override_safety(self):
        advisory(dict(analysis='',hypothesis='',confidence=1,attack_chain='',recommended_action='PROCESS_QUARANTINE',evidence_refs=['e1'],explanation=''))
        self.engine.safety.health_snapshot=Mock(return_value={'safe_mode':True});self.denied(self.engine.prepare(self.intent,self.principal))
    def test_dependency_value_error_redaction(self):
        self.engine.policy.evaluate=Mock(side_effect=ValueError('SECRET-TOKEN-ABC'))
        result=self.engine.prepare(self.intent,self.principal);self.assertNotIn('SECRET-TOKEN-ABC',json.dumps(result)+json.dumps(self.ledger.data));self.denied(result)
    def test_consumption_write_failure_prevents_gateway(self):
        ticket=self.authorize();self.engine.gateway.execute_dry_run=Mock();self.ledger.commit=Mock(side_effect=OSError())
        self.denied(self.engine.simulate(ticket,self.intent,self.principal));self.engine.gateway.execute_dry_run.assert_not_called()
    def test_verifier_partial_success(self):
        ticket=self.authorize();self.engine.verifier.verify=Mock(return_value=dict(accepted=True,verified=True,real_world_effect_observed=False,recovery_required=False,verification_scope='SIMULATION_ONLY'))
        self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_recovery_partial_success(self):
        ticket=self.authorize();self.engine.recovery.plan=Mock(return_value=dict(accepted=True,recovery_required=False,recovery_executed=False))
        self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    def test_rejected_request_audited(self):
        self.intent['request_source']='AI';self.denied(self.engine.prepare(self.intent,Principal('t1','alice','AI',True)))
        row=self.ledger.read()['rejections'][0];self.assertEqual(row['requester'],'alice');self.assertEqual(row['source'],'AI');self.assertEqual(len(row['input_digest']),64)
    def test_rejected_history_bound(self):
        for _ in range(70):self.engine.prepare({},self.principal)
        data=self.ledger.read();self.assertEqual(len(data['rejections']),64);self.assertEqual(data['rejection_count'],70)
    def test_concurrent_ticket_consumed_once(self):
        ticket=self.authorize()
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(lambda _:self.engine.simulate(ticket,self.intent,self.principal),range(2)))
        self.assertEqual(sum(r['state']=='VERIFIED' for r in outcomes),1);self.assertEqual(self.engine.gateway.executions,1)
    def test_old_process_instance_cannot_continue(self):
        ticket=self.authorize();old_engine=self.engine;other=SimulationLedger(self.path,self.key)
        try:
            ResponseControlPlane(other,self.context,clock=lambda:self.now)
            self.denied(old_engine.simulate(ticket,self.intent,self.principal));self.assertTrue(old_engine.blocked)
        finally:other.close()

def action_test(action):
    def test(self):
        self.intent.update(action_type=action,target_type=ACTIONS[action][0]);self.context.targets[('t1','target1')]['target_type']=ACTIONS[action][0]
        self.assertEqual(self.engine.simulate(self.authorize(),self.intent,self.principal)['state'],'VERIFIED')
    return test
for action in ACTIONS:setattr(ResponseTests,'test_action_'+action.lower(),action_test(action))
def protected_test(category):
    def test(self):
        self.context.targets[('t1','target1')]['protection_classes']=[category];self.denied(self.engine.prepare(self.intent,self.principal))
    return test
for category in PROTECTIONS:setattr(ResponseTests,'test_protected_'+category,protected_test(category))
def scope_test(field,value):
    def test(self):
        ticket=self.authorize();self.intent[field]=value;self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    return test
for field,value in dict(target_id='target2',action_type='FILE_QUARANTINE',tenant_id='t2',incident_id='i2',mode='EXECUTE').items():setattr(ResponseTests,'test_scope_'+field,scope_test(field,value))
def observation_test(kind):
    def test(self):
        ticket=self.authorize();original=self.context.observe;calls=0
        def observe(*args):
            nonlocal calls
            calls+=1;result=original(*args)
            if calls==2:
                if kind=='missing':return {}
                if kind=='stale':result['observed_at']-=6
                if kind=='target':result['target']['target_id']='other'
                if kind=='conflict':result['target']['state']='CHANGED'
            return result
        self.context.observe=observe;self.denied(self.engine.simulate(ticket,self.intent,self.principal))
    return test
for kind in ('missing','stale','target','conflict'):setattr(ResponseTests,'test_observation_'+kind,observation_test(kind))

if __name__=='__main__':unittest.main(verbosity=2)
