"""Response Control Plane v0.1: opt-in, fixture-only, no runtime wiring.
Composes the real policy/safety/gateway/verifier/recovery interfaces. No OS
executor exists here. The independent observation source is a fixture inventory.
"""
import copy,hashlib,hmac,secrets,threading,time
from agent.event import SecurityEvent
from agent.attack_graph import AttackGraph
from agent.risk_engine import RiskEngine
from agent.policy_engine import PolicyEngine
from agent.safety import SafetyCore
from agent.safety_authorization_gate import SafetyAuthorizationGate
from agent.action_gateway import ActionGateway
from agent.independent_verifier import IndependentVerifier
from agent.post_action_verifier import PostActionVerifier
from agent.recovery_planner import RecoveryPlanner
from agent.blast_radius_guard import BlastRadiusGuard
from .contracts import ACTIONS,PROTECTIONS,ActionIntent,Principal,ContractError,canonical,digest,ident,number,require
from .ledger import TERMINAL,transition_allowed

class FixtureContext:
    """Trusted synthetic assembly input, not an external event-admission API.
    Production ingress must use existing Crypto/Replay -> EventBus -> Correlation.
    No production adapter or EventBus subscription is installed in this sprint.
    """
    def __init__(self,events,incidents,targets):
        require(len(events)<=128 and len(incidents)<=64 and len(targets)<=64,'CONTEXT_BOUND')
        self.events={e.event_id:e.to_dict() for e in events};self.event_hashes={k:digest(v) for k,v in self.events.items()}
        require(len(self.events)==len(events),'DUPLICATE_EVENT')
        require(all(len(canonical(v))<=16384 for v in self.events.values()) and all(len(canonical(v))<=16384 for v in incidents.values()) and all(len(canonical(v))<=4096 for v in targets.values()),'CONTEXT_BYTES')
        self.incidents=copy.deepcopy(incidents);self.targets=copy.deepcopy(targets)
        self.incident_hashes={k:digest(v) for k,v in self.incidents.items()}
        for identity,t in self.targets.items():
            require(set(t)=={'tenant_id','target_id','target_type','instance_id','protection_classes','classification_complete','asset_criticality','state'},'TARGET_SCHEMA')
            for k in ('tenant_id','target_id','instance_id'):ident(t[k])
            require(identity==(t['tenant_id'],t['target_id']) and t['target_type'] in {a[0] for a in ACTIONS.values()},'TARGET_IDENTITY')
            require(t['classification_complete'] is True and type(t['protection_classes']) is list and set(t['protection_classes'])<=PROTECTIONS,'TARGET_CLASSIFICATION_REQUIRED')
            require(type(t['asset_criticality']) is int and 1<=t['asset_criticality']<=5 and t['state']=='UNCHANGED','TARGET_CONTEXT')
    def observe(self,tenant,target,now):
        t=copy.deepcopy(self.targets.get((tenant,target)));require(t is not None,'TARGET_NOT_FOUND')
        return dict(target=t,observed_at=now,source='INDEPENDENT_FIXTURE_INVENTORY')
    def evidence(self,intent):
        v=intent.data;inc=copy.deepcopy(self.incidents.get((v['tenant_id'],v['incident_id'])))
        require(inc is not None and digest(inc)==self.incident_hashes[(v['tenant_id'],v['incident_id'])],'INCIDENT_NOT_FOUND_OR_CHANGED')
        require(inc['tenant_id']==v['tenant_id'] and v['target_id'] in inc['target_ids'] and set(inc['evidence_refs'])==set(v['evidence_refs']),'INCIDENT_SCOPE_OR_PARTIAL_EVIDENCE')
        hashes={}
        for ref in v['evidence_refs']:
            raw=self.events.get(ref);require(raw is not None and digest(raw)==self.event_hashes[ref],'EVIDENCE_NOT_FOUND_OR_CHANGED')
            event=SecurityEvent.from_dict(raw);require(event.tenant_id==v['tenant_id'],'CROSS_TENANT_EVIDENCE');hashes[ref]=digest(raw)
        return inc,hashes

class SimulationVerifier:
    def __init__(self,context):self.context=context;self.receipt_verifier=PostActionVerifier()
    def verify(self,result,request,authorization,before,now):
        receipt=self.receipt_verifier.verify(result,request=request,authorization=authorization)
        after=self.context.observe(before['target']['tenant_id'],before['target']['target_id'],now)
        require(receipt.get('verified') is True,'RECEIPT_VERIFICATION_FAILED')
        require(after['source']=='INDEPENDENT_FIXTURE_INVENTORY' and 0<=now-number(after['observed_at'])<=5 and after['target']==before['target'],'INDEPENDENT_OBSERVATION_FAILED')
        return dict(accepted=True,verified=True,real_world_effect_observed=False,recovery_required=False,
          primary_receipt_digest=receipt['receipt_digest'],independent_observation_digest=digest(after),verification_scope='SIMULATION_ONLY')

class ResponseControlPlane:
    def __init__(self,ledger,context,*,clock=time.time,safety=None,policy=None):
        self.ledger=ledger;self.context=context;self.clock=clock;self.session=secrets.token_hex(16);self.blocked=False
        self.safety=safety if safety is not None else SafetyCore();self.policy=policy if policy is not None else PolicyEngine()
        self.risk=RiskEngine();self.preverifier=IndependentVerifier();self.gate=SafetyAuthorizationGate(max_outstanding=64)
        self.gateway=ActionGateway(self.gate);self.verifier=SimulationVerifier(context);self.recovery=RecoveryPlanner();self.blast=BlastRadiusGuard();self._capabilities={}
        self.lock=ledger.lock;self._audit_context={}
        data=copy.deepcopy(ledger.read());now=number(self.clock());require(now>=data['last_time'],'CLOCK_MOVED_BACKWARD')
        for row in data['records'].values():
            if row['state'] not in TERMINAL:
                row['state']='REVIEW_REQUIRED';row['history'].append(dict(state='REVIEW_REQUIRED',reason='PROCESS_REPLACEMENT',at=now))
        if data!=ledger.data:data['last_time']=now;ledger.commit(data)
    def _now(self):
        now=number(self.clock());require(now>=self.ledger.data['last_time'],'CLOCK_MOVED_BACKWARD');return now
    def _step(self,intent_id,state,reason='VALIDATED',**extra):
        data=copy.deepcopy(self.ledger.data);row=data['records'][intent_id];now=self._now()
        require(transition_allowed(row['state'],state),'INVALID_STATE_TRANSITION')
        row.update(extra);row['state']=state;row['history'].append(dict(state=state,reason=reason,at=now));data['last_time']=now
        self.ledger.commit(data)
    def _failure(self,intent_id,reason,state='DENIED'):
        # Never export exception payloads; dependency exceptions may contain secrets.
        reason=reason if reason.isascii() and reason.replace('_','').isupper() and len(reason)<=80 else 'INVALID_INPUT_OR_DEPENDENCY'
        if state=='DEGRADED_SAFE' or reason.startswith('JOURNAL_') or reason=='CLOCK_MOVED_BACKWARD':self.blocked=True;state='DEGRADED_SAFE'
        if intent_id in self.ledger.data['records']:
            try:self._step(intent_id,state,reason)
            except Exception:self.blocked=True;state='DEGRADED_SAFE'
            self._capabilities.pop(intent_id,None)
        try:
            data=copy.deepcopy(self.ledger.data)
            require(data['rejection_count']<1000000,'REJECTION_BUDGET_EXHAUSTED')
            data['rejection_count']+=1
            data['rejections']=(data['rejections']+[dict(self._audit_context,reason=reason,state=state,at=data['last_time'])])[-64:]
            self.ledger.commit(data)
        except Exception:self.blocked=True;state='DEGRADED_SAFE'
        return dict(state=state,reason=reason,executed=False,real_world_effect=False)
    def _attempt(self,value,principal):
        self._audit_context=dict(input_digest='INVALID_OR_OVERSIZE',requester='UNVALIDATED',tenant='UNVALIDATED',source='UNVALIDATED')
        try:
            raw=canonical(value)
            if len(raw)<=16384:self._audit_context['input_digest']=hashlib.sha256(raw).hexdigest()
            if isinstance(principal,Principal):
                principal.validate();self._audit_context.update(requester=principal.subject,tenant=principal.tenant_id,source=principal.source)
        except Exception:pass
    def prepare(self,value,principal):
        with self.lock:
            self._attempt(value,principal)
            intent_id=None
            try:
                require(not self.blocked,'JOURNAL_UNAVAILABLE');self.ledger.data=self.ledger.read();require(self.ledger.data['rejection_count']<1000000,'REJECTION_BUDGET_EXHAUSTED');now=self._now()
                require(isinstance(principal,Principal),'PRINCIPAL_REQUIRED');principal.validate();intent=ActionIntent.parse(value,now);v=intent.data
                require(v['tenant_id']==principal.tenant_id and v['requested_by']==principal.subject and v['request_source']==principal.source,'REQUESTER_SCOPE')
                require(principal.source!='AI' and principal.may_simulate is True,'AI_OR_UNAUTHORIZED_REQUESTER')
                rows=self.ledger.data['records'];require(v['intent_id'] not in rows and not any(x['intent']['tenant_id']==v['tenant_id'] and x['intent']['idempotency_key']==v['idempotency_key'] for x in rows.values()),'DUPLICATE_REQUEST')
                require(len(rows)<self.ledger.MAX_RECORDS,'INTENT_RETENTION_FULL')
                intent_id=v['intent_id'];data=copy.deepcopy(self.ledger.data)
                data['records'][intent_id]=dict(intent=v,state='PROPOSED',history=[dict(state='PROPOSED',reason='REQUEST_RECEIVED',at=now)],session=self.session,consumed=False)
                data['last_time']=now;self.ledger.commit(data)
                incident,evidence=self.context.evidence(intent);before=self.context.observe(v['tenant_id'],v['target_id'],now);target=before['target']
                require(before['source']=='INDEPENDENT_FIXTURE_INVENTORY' and 0<=now-number(before['observed_at'])<=5,'PRE_STATE_STALE')
                require(target['target_id']==v['target_id'] and target['tenant_id']==v['tenant_id'] and target['target_type']==v['target_type'],'TARGET_SCOPE')
                require(target['classification_complete'] is True and not target['protection_classes'],'PROTECTED_OR_UNKNOWN_TARGET')
                require(not any(x['intent']['tenant_id']==v['tenant_id'] and x['intent']['target_id']==v['target_id'] and x['state'] not in TERMINAL and key!=intent_id for key,x in rows.items()),'CONFLICTING_CONTAINMENT')
                self._step(intent_id,'ADMITTED',evidence_hashes=evidence,before=before)
                risk=self.risk.assess(AttackGraph(),[incident]);require(len(risk.get('assessments',[]))==1,'RISK_UNAVAILABLE')
                assessment=risk['assessments'][0]
                require(v['risk_snapshot']=={k:assessment[k] for k in ('risk_score','risk_level')},'RISK_SNAPSHOT_STALE')
                assessment['requested_action']=ACTIONS[v['action_type']][1]
                policy=self.policy.evaluate(risk,safety=self.safety)
                require(policy.get('accepted') is True and policy.get('policy_outcome')=='REQUIRE_VERIFICATION','POLICY_DENIED')
                self._step(intent_id,'POLICY_EVALUATED',risk=risk,policy=policy)
                verified=self.preverifier.verify(risk,policy,safety=self.safety)
                require(verified.get('accepted') is True and verified.get('verified') is True,'PREAUTH_VERIFICATION_FAILED')
                health=self.safety.health_snapshot();safety={k:health.get(k) for k in ('safe_mode','shutdown_requested')};require(safety.get('safe_mode') is False and safety.get('shutdown_requested') is False,'SAFETY_DENIED')
                self._step(intent_id,'SAFETY_EVALUATED',safety=safety)
                request=dict(incident_id=v['incident_id'],requested_action=ACTIONS[v['action_type']][1],target=digest(target),requester=principal.subject,evidence_ref=digest(evidence),decision_digest=verified['assessments'][0]['decision_digest'],execution_mode='DRY_RUN')
                require(self.blast.evaluate(request).get('allowed') is True,'BLAST_RADIUS_DENIED')
                authorization=self.gate.authorize_dry_run(request,policy_result=policy,verification_result=verified,safety=self.safety)
                require(authorization.get('authorized') is True,'SAFETY_AUTHORIZATION_DENIED')
                payload=dict(ticket_id=secrets.token_hex(16),intent_id=intent_id,tenant_id=principal.tenant_id,session=self.session,scope=digest(dict(intent=v,evidence=evidence,target=target,policy=policy,safety=safety)),created_at=now,expires_at=min(v['expires_at'],now+30),mode=v['mode'])
                mac=hmac.new(self.ledger._key,b'SIMULATION_TICKET\0'+canonical(payload),hashlib.sha256).hexdigest()
                self._step(intent_id,'AUTHORIZED_FOR_SIMULATION',ticket=payload,request=request)
                self._capabilities[intent_id]=(authorization,request)
                return dict(state='AUTHORIZED_FOR_SIMULATION',ticket=dict(payload=payload,mac=mac),executed=False,real_world_effect=False)
            except ContractError as e:return self._failure(intent_id,str(e),'EXPIRED' if str(e)=='EXPIRED_OR_INVALID_INTENT' else 'DENIED')
            except Exception:return self._failure(intent_id,'ENGINE_OR_AUDIT_FAILURE','DEGRADED_SAFE')
    def simulate(self,ticket,value,principal):
        with self.lock:
            self._attempt(value,principal)
            intent_id=None
            try:
                require(not self.blocked,'JOURNAL_UNAVAILABLE');self.ledger.data=self.ledger.read();require(self.ledger.data['rejection_count']<1000000,'REJECTION_BUDGET_EXHAUSTED');now=self._now()
                require(isinstance(principal,Principal),'PRINCIPAL_REQUIRED');principal.validate();intent=ActionIntent.parse(value,now);v=intent.data
                require(principal.source!='AI' and principal.may_simulate is True and v['tenant_id']==principal.tenant_id and v['requested_by']==principal.subject and v['request_source']==principal.source,'REQUESTER_SCOPE')
                require(type(ticket) is dict and set(ticket)=={'payload','mac'} and len(canonical(ticket))<=4096,'TICKET_SCHEMA')
                expected=hmac.new(self.ledger._key,b'SIMULATION_TICKET\0'+canonical(ticket['payload']),hashlib.sha256).hexdigest()
                require(type(ticket['mac']) is str and hmac.compare_digest(ticket['mac'],expected),'TICKET_INTEGRITY')
                row=self.ledger.data['records'].get(v['intent_id']);require(row is not None,'UNKNOWN_INTENT')
                require(row['intent']==v and row['ticket']==ticket['payload'] and row['session']==self.session,'TICKET_SCOPE')
                require(row['state']=='AUTHORIZED_FOR_SIMULATION' and row['consumed'] is False,'TICKET_REPLAY')
                require(now<row['ticket']['expires_at'],'TICKET_EXPIRED')
                _,hashes=self.context.evidence(intent);require(hashes==row['evidence_hashes'],'EVIDENCE_CHANGED')
                before=self.context.observe(v['tenant_id'],v['target_id'],now);require(before['target']==row['before']['target'] and before['source']=='INDEPENDENT_FIXTURE_INVENTORY' and 0<=now-number(before['observed_at'])<=5,'TARGET_CHANGED')
                require(self.policy.evaluate(row['risk'],safety=self.safety)==row['policy'],'POLICY_CHANGED')
                health=self.safety.health_snapshot();require(health.get('safe_mode') is False and health.get('shutdown_requested') is False,'SAFETY_CHANGED')
                intent_id=v['intent_id'];authorization,request=self._capabilities[intent_id]
                self._step(intent_id,'SIMULATING',consumed=True) # durable before the no-op executor
                result=self.gateway.execute_dry_run(authorization,request=request)
                require(result.get('simulated') is True and result.get('executed') is False and result.get('real_world_effect') is False,'DRY_RUN_FAILED')
                plan=dict(action_type=v['action_type'],target=before['target'],what_would_happen='PROPOSED_CONTAINMENT_ONLY',required_privilege='ADMINISTRATOR_FOR_FUTURE_REAL_ACTION',expected_changes='NONE_IN_SIMULATION',expected_blast_radius='ONE_REGISTERED_TARGET',business_impact_estimate='POTENTIAL_SERVICE_DISRUPTION_REQUIRES_OWNER_REVIEW',confidence=self.ledger.data['records'][intent_id]['risk']['assessments'][0]['confidence'],asset_criticality=before['target']['asset_criticality'],duration_seconds=v['policy_context']['duration_seconds'],expires_at=v['expires_at'],reason='EVIDENCE_BACKED_SIMULATION',evidence_refs=v['evidence_refs'],verification_plan='INDEPENDENT_FIXTURE_SNAPSHOT_EQUAL',rollback_plan=v['policy_context']['recovery'])
                plan.update(incident_id=v['incident_id'],reversibility='NO_CHANGE_TO_REVERSE_IN_SIMULATION')
                self._step(intent_id,'SIMULATED',plan=plan,primary_result_digest=digest(result));self._step(intent_id,'VERIFYING')
                verification=self.verifier.verify(result,request,authorization,before,self._now())
                require(verification.get('accepted') is True and verification.get('verified') is True and verification.get('real_world_effect_observed') is False and verification.get('recovery_required') is False and verification.get('verification_scope')=='SIMULATION_ONLY','INDEPENDENT_VERIFICATION_FAILED')
                require(all(type(verification.get(k)) is str and len(verification[k])==64 and all(c in '0123456789abcdef' for c in verification[k]) for k in ('primary_receipt_digest','independent_observation_digest')),'VERIFIER_EVIDENCE_MISSING')
                recovery=self.recovery.plan(verification,request=request,action_result=result)
                require(recovery.get('accepted') is True and recovery.get('recovery_required') is False and recovery.get('recovery_executed') is False and recovery.get('execution_supported') is False and recovery.get('real_world_effect') is False and recovery.get('authorization')=='NOT_GRANTED','RECOVERY_UNCERTAIN')
                self._step(intent_id,'VERIFIED',verification=verification,recovery=recovery);self._capabilities.pop(intent_id,None)
                return dict(state='VERIFIED',verification_scope='SIMULATION_ONLY',executed=False,real_world_effect=False,plan=plan)
            except ContractError as e:return self._failure(intent_id,str(e),'REVIEW_REQUIRED' if intent_id else 'DENIED')
            except Exception:return self._failure(intent_id,'SIMULATION_OR_VERIFIER_ERROR','REVIEW_REQUIRED' if intent_id else 'DEGRADED_SAFE')
    def cancel(self,intent_id,principal):
        """One-way cancellation; never resumes or reissues a capability."""
        with self.lock:
            self._attempt({'cancel':intent_id},principal)
            try:
                require(not self.blocked,'JOURNAL_UNAVAILABLE');self.ledger.data=self.ledger.read()
                ident(intent_id);require(isinstance(principal,Principal),'PRINCIPAL_REQUIRED');principal.validate()
                row=self.ledger.data['records'].get(intent_id);require(row is not None,'UNKNOWN_INTENT')
                require(principal.source!='AI' and principal.may_simulate and row['intent']['tenant_id']==principal.tenant_id and row['intent']['requested_by']==principal.subject,'REQUESTER_SCOPE')
                require(row['state']=='AUTHORIZED_FOR_SIMULATION' and row['consumed'] is False,'CANCELLATION_NOT_AVAILABLE')
                self._step(intent_id,'CANCELLED','REQUESTER_CANCELLED');self._capabilities.pop(intent_id,None)
                return dict(state='CANCELLED',executed=False,real_world_effect=False)
            except ContractError as e:return self._failure(None,str(e))
            except Exception:return self._failure(None,'CANCELLATION_AUDIT_FAILURE','DEGRADED_SAFE')
