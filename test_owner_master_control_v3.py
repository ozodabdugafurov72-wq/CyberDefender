from __future__ import annotations
import json, os, socket, sys, tempfile, threading, time
from pathlib import Path
from urllib.request import urlopen, Request

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from dashboard_owner import server
from dashboard_owner.server import classify_incident


def assert_true(cond, msg):
    if not cond: raise AssertionError(msg)
    print(f"[PASS] {msg}")


def main():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); (root/'state').mkdir(); (root/'logs').mkdir()
        now=time.time()
        snap={
          'schema_version':'1.0','publisher':{'sequence':42,'generated_at':now},
          'runtime':{'running':True,'status':'HEALTHY','cycle_count':12,'component_failures':0,'events_created':4,'events_admitted':4,'events_rejected':0,
                     'risk':{'overall_risk':'CRITICAL','overall_score':100,'overall_risk_score':100,'recommendation':'ESCALATE'}},
          'health':{
            'runtime':{'status':'HEALTHY'},
            'safety_core':{'status':'SAFE','safe_mode':False,'shutdown_requested':False},
            'resource_guard':{'status':'HEALTHY','state':'DEGRADED'},
            'risk_engine':{'status':'HEALTHY','overall_risk':'CRITICAL'},
            'policy_engine':{'status':'HEALTHY'},'independent_verifier':{'status':'HEALTHY'},
            'authorization_gate':{'status':'HEALTHY','dry_run_only':True},
            'action_gateway':{'status':'HEALTHY','real_world_effect':False},
            'event_bus':{'status':'HEALTHY'},'process_graph':{'status':'HEALTHY'},'attack_graph':{'status':'HEALTHY'},
          },
          'observation':{'cpu_percent':21.2,'memory_percent':95.1,'disk_percent':74.2,'process_count':271,'available_memory_mb':412.3},
          'incidents':[
            {'incident_id':'INC-SEC-01','severity':'CRITICAL','risk_score':80,'correlation_key':'suspicious process'},
            {'incident_id':'INC-RES-01','severity':'CRITICAL','risk_score':60,'correlation_key':'agent-local:SystemObserver:HIGH_MEMORY_USAGE'},
          ]}
        (root/'state'/'dashboard_runtime.json').write_text(json.dumps(snap),encoding='utf-8')
        (root/'logs'/'events.jsonl').write_text('\n'.join(json.dumps({'event_type':'HIGH_MEMORY_USAGE','severity':'CRITICAL','message':'memory pressure'}) for _ in range(6)),encoding='utf-8')
        server.ROOT=root; server.STATE_FILE=root/'state'/'dashboard_runtime.json'; server.LOG_FILE=root/'logs'/'events.jsonl'
        state=server.build_state()
        assert_true(state['schema']=='cyberdefender.owner-master-control.v3.5','v3.5 schema is exposed')
        assert_true(state['master_control']['unlocked'] is True,'Master Control is ACTIVE/UNLOCKED')
        assert_true(state['master_control']['real_world_effect'] is False,'Real-world effect remains blocked')
        assert_true(state['safety']['enforcement']=='ACTIVE','Safety enforcement remains active')
        assert_true(state['security_posture']=='CRITICAL','Security posture is represented')
        assert_true(state['risk_score']==80,'Security risk score is separated from aggregate resource risk')
        assert_true(state['aggregate_risk_score']==100,'Aggregate risk remains available for diagnostics')
        assert_true(state['resource_posture']=='DEGRADED','Resource posture is separated from threat posture')
        resource_row = next(row for row in state['components'] if row['key']=='resource_guard')
        assert_true(resource_row['status']=='DEGRADED','Resource component display follows pressure state')
        assert_true(resource_row['operational_status']=='HEALTHY','Resource component operational health remains separately observable')
        assert_true(state['resource_state']['available_memory_mb']==412.3,'Available-memory telemetry alias is normalized')
        assert_true(state['incident_summary']['critical_security_incidents']==1,'Critical security count excludes critical resource incidents')
        assert_true(state['incident_summary']['critical_resource_incidents']==1,'Critical resource severity remains observable separately')
        assert_true(state['incident_summary']['security_incidents']==1,'Security incident classification works')
        assert_true(state['incident_summary']['resource_incidents']==1,'Resource incident classification works')

        assert_true(state['event_groups'][0]['count']==6,'Evidence events are deduplicated')
        nested_resource = {'incident_id':'INC-RES-NESTED','severity':'HIGH','evidence':{'detection_types':['HIGH_MEMORY_USAGE','LOW_AVAILABLE_MEMORY']}}
        assert_true(classify_incident(nested_resource)=='RESOURCE','Nested resource detection classification works')
        assert_true(state['health']['safety_core']['status']=='SAFE','Safety Core health is first-class')
        assert_true(state['governance']['dashboard_direct_os_access'] is False,'Dashboard has no direct OS access')

    # Regression: no security incidents must never render SECURITY POSTURE as UNKNOWN.
    with tempfile.TemporaryDirectory() as td2:
        root2 = Path(td2); (root2/'state').mkdir(); (root2/'logs').mkdir()
        snap2={
          'publisher':{'sequence':1,'generated_at':time.time()},
          'runtime':{'running':True,'status':'HEALTHY'},
          'health':{'runtime':{'status':'HEALTHY'},'resource_guard':{'status':'HEALTHY','state':'NORMAL'},'safety_core':{'status':'SAFE'},
                    'risk_engine':{'status':'HEALTHY'},'policy_engine':{'status':'HEALTHY'},
                    'independent_verifier':{'status':'HEALTHY'},'authorization_gate':{'status':'HEALTHY','dry_run_only':True},
                    'action_gateway':{'status':'HEALTHY','real_world_effect':False}},
          'incidents':[]
        }
        (root2/'state'/'dashboard_runtime.json').write_text(json.dumps(snap2),encoding='utf-8')
        server.ROOT=root2; server.STATE_FILE=root2/'state'/'dashboard_runtime.json'; server.LOG_FILE=root2/'logs'/'events.jsonl'
        clean=server.build_state()
        assert_true(clean['security_posture']=='CLEAR','Clean security posture is CLEAR, not UNKNOWN')
        assert_true(clean['risk_score']==0,'Clean security risk score is zero')
    print('RESULT: PASS')

if __name__=='__main__': main()
