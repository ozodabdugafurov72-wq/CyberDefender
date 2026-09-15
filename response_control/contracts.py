"""Strict simulation-only inputs; no intent, risk or AI text grants authority."""
from dataclasses import dataclass
import copy,hashlib,json,math,re

ACTIONS={'PROCESS_QUARANTINE':('process','PROCESS_SUSPEND'),'FILE_QUARANTINE':('file','QUARANTINE'),
 'NETWORK_LIMITED':('network','NETWORK_BLOCK'),'ENDPOINT_ISOLATION':('endpoint','ISOLATE_DEVICE'),'SERVICE_CONTAINMENT':('service','SERVICE_MODIFY')}
PROTECTIONS={'critical_os','security_component','recovery_component','identity_infrastructure','boot_component','business_protected'}
RECOVERY={'pre_action_state':'FIXTURE_SNAPSHOT','authorized_change':'NONE','expected_post_state':'UNCHANGED','verification_condition':'INDEPENDENT_SNAPSHOT_EQUAL',
 'rollback_trigger':'VERIFICATION_FAILURE','rollback_plan':'NO_OP_RETAIN_PRE_STATE','post_rollback_verification':'INDEPENDENT_SNAPSHOT_EQUAL','maximum_attempts':1,'failure_terminal_state':'DEGRADED_SAFE'}
class ContractError(ValueError):
    """Fixed local reason code, safe to export; dependency exceptions are not."""
def require(ok,code):
    if not ok:raise ContractError(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def ident(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',value),'INVALID_ID');return value
def number(value):
    require(type(value) in (int,float) and math.isfinite(value),'INVALID_TIME');return float(value)
@dataclass(frozen=True)
class Principal:
    tenant_id:str
    subject:str
    source:str
    may_simulate:bool=False
    def validate(self):
        ident(self.tenant_id);ident(self.subject);require(self.source in {'OPERATOR','AUTOMATION','AI'},'INVALID_SOURCE');require(type(self.may_simulate) is bool,'INVALID_PERMISSION')
@dataclass(frozen=True)
class ActionIntent:
    """Snapshot of caller data; validate again at each boundary to prevent mutation."""
    data:dict
    @classmethod
    def parse(cls,value,now):
        fields={'intent_id','incident_id','tenant_id','target_id','target_type','action_type','request_source','requested_by','evidence_refs','risk_snapshot','policy_context','created_at','expires_at','idempotency_key','mode'}
        require(type(value) is dict and set(value)==fields,'INTENT_SCHEMA');require(len(canonical(value))<=16384,'INTENT_SIZE');v=copy.deepcopy(value)
        for k in ('intent_id','incident_id','tenant_id','target_id','requested_by','idempotency_key'):ident(v[k])
        require(v['action_type'] in ACTIONS and v['target_type']==ACTIONS[v['action_type']][0],'UNSUPPORTED_ACTION_TARGET')
        require(v['mode'] in {'OBSERVE','SIMULATE'},'EXECUTE_DISABLED');require(v['request_source'] in {'OPERATOR','AUTOMATION','AI'},'INVALID_SOURCE')
        refs=v['evidence_refs'];require(type(refs) is list and 1<=len(refs)<=8 and len(set(refs))==len(refs),'EVIDENCE_REQUIRED')
        for x in refs:ident(x)
        created=number(v['created_at']);expires=number(v['expires_at']);require(created<=now<expires and 0<expires-created<=300,'EXPIRED_OR_INVALID_INTENT')
        risk=v['risk_snapshot'];require(type(risk) is dict and set(risk)=={'risk_score','risk_level'} and type(risk['risk_score']) is int and 0<=risk['risk_score']<=100 and risk['risk_level'] in {'INFO','LOW','MEDIUM','HIGH','CRITICAL'},'RISK_SCHEMA')
        ctx=v['policy_context'];require(type(ctx) is dict and set(ctx)=={'policy_version','duration_seconds','recovery'},'POLICY_CONTEXT_SCHEMA')
        require(ctx['policy_version']=='1.0' and type(ctx['duration_seconds']) is int and 1<=ctx['duration_seconds']<=300,'POLICY_CONTEXT_UNSUPPORTED')
        require(ctx['recovery']==RECOVERY and type(ctx['recovery']['maximum_attempts']) is int,'RECOVERY_REQUIRED')
        return cls(v)

def advisory(value):
    """AI advisories are returned to an analyst, never accepted as ActionIntent."""
    fields={'analysis','hypothesis','confidence','attack_chain','recommended_action','evidence_refs','explanation'}
    require(type(value) is dict and set(value)==fields and len(canonical(value))<=8192,'AI_ADVISORY_SCHEMA')
    for k in fields-{'confidence','evidence_refs'}:require(type(value[k]) is str and len(value[k])<=1000,'AI_ADVISORY_TEXT')
    require(type(value['confidence']) in (float,int) and 0<=value['confidence']<=1,'AI_CONFIDENCE')
    require(type(value['evidence_refs']) is list and 1<=len(value['evidence_refs'])<=8,'AI_EVIDENCE_BOUND')
    for x in value['evidence_refs']:ident(x)
    return dict(classification='UNTRUSTED_ADVISORY_INPUT',authorization='NOT_GRANTED',advisory_digest=digest(value))
