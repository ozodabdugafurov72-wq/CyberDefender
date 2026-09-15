"""Bounded lab ledger; contains no service, reboot, registry or process actuators."""
from __future__ import annotations
import argparse, copy, hashlib, json, os, re, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA='cd.h1d9.lab-state.v2'
STATUSES={'PASS','FAIL','BLOCKED','NOT APPLICABLE','REQUIRES OPERATOR STEP'}
TRANSITIONS={
 'ConfirmC0':({'C0_PREFLIGHT_PASS'},'C0_CHECKPOINT_CONFIRMED'),
 'Install':({'C0_CHECKPOINT_CONFIRMED'},'CLEAN_INSTALL_COMPLETE'),
 'C1Validate':({'CLEAN_INSTALL_COMPLETE','C1_BASELINE_PASS'},'C1_BASELINE_PASS'),
 'ConfirmC1':({'C1_BASELINE_PASS'},'C1_BASELINE_PASS'),
 'EnableRustCanary':({'C1_BASELINE_PASS'},'RUST_CANARY_CONFIGURED'),
 'C2Validate':({'RUST_CANARY_CONFIGURED','C2_BASELINE_PASS','FAULT_TESTS_RUNNING','POST_REBOOT_VALIDATION'},'C2_BASELINE_PASS'),
 'ConfirmC2':({'C2_BASELINE_PASS'},'C2_BASELINE_PASS'),
 'Crash':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING'},'FAULT_TESTS_RUNNING'),
 'SCMStorm':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING'},'ROLLBACK_PENDING'),
 'NativeHang':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING'},'FAULT_TESTS_RUNNING'),
 'CleanRestart':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING'},'FAULT_TESTS_RUNNING'),
 'Resources':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING'},'FAULT_TESTS_RUNNING'),
 'FixtureTests':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING'},'FAULT_TESTS_RUNNING'),
 'StoreFault':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING'},'FAULT_TESTS_RUNNING'),
 'PrepareReboot':({'C2_BASELINE_PASS'},'REBOOT_PENDING'),
 'PostReboot':({'REBOOT_PENDING'},'POST_REBOOT_VALIDATION'),
 'PrepareSleep':({'C2_BASELINE_PASS','POST_REBOOT_VALIDATION'},'SLEEP_WAKE_PENDING'),
 'PostSleep':({'SLEEP_WAKE_PENDING'},'POST_REBOOT_VALIDATION'),
 'PreparePowerLoss':({'C2_BASELINE_PASS'},'POWER_LOSS_PENDING'),
 'PostPowerLoss':({'POWER_LOSS_PENDING'},'POST_REBOOT_VALIDATION'),
 'PrepareRollback':({'C2_BASELINE_PASS','FAULT_TESTS_RUNNING','POST_REBOOT_VALIDATION','LAB_FAILED','REVIEW_REQUIRED','CHECKPOINT_RESTORE_PENDING'},'ROLLBACK_PENDING'),
 'PrepareCheckpointRestore':({'ROLLBACK_PENDING'},'CHECKPOINT_RESTORE_PENDING'),
 'ResumeCheckpoint':({'CHECKPOINT_RESTORE_PENDING'},'C2_BASELINE_PASS'),
 'RollbackValidate':({'ROLLBACK_PENDING'},'LAB_COMPLETE'),
}
SERVICES=('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI')
def now():return datetime.now(timezone.utc).isoformat()
def canonical(data):return json.dumps(data,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
def digest(data):return hashlib.sha256(data).hexdigest()
def require(ok,code):
    if not ok:raise ValueError(code)
def strict(raw,limit=262144):
    require(0<len(raw)<=limit,'LAB_STATE_SIZE')
    def pairs(rows):
        result={}
        for k,v in rows:
            require(k not in result,'LAB_DUPLICATE_KEY');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('LAB_NONFINITE')))
def catalog(path):
    data=strict(Path(path).read_bytes());require(set(data)=={'schema','cases'} and data['schema']=='cd.h1d9.catalog.v1','LAB_CATALOG_SCHEMA')
    require(len(data['cases'])==26,'LAB_CATALOG_COUNT');seen=set()
    fields={'id','legacy_id','title','purpose','precondition','mutation','expected','fail_condition','evidence','recovery','execution','risk','mandatory'}
    for row in data['cases']:
        require(set(row)==fields and re.fullmatch(r'[A-Z]+-[0-9]{2}',row['id']) is not None and row['id'] not in seen,'LAB_CATALOG_CASE')
        require(type(row['mandatory']) is bool and row['execution'] in {'AUTOMATED','OPERATOR','MIXED'} and row['risk'] in {'LOW','MEDIUM','HIGH'},'LAB_CATALOG_TYPES')
        require(all(type(row[k]) is str and 0<len(row[k])<=8192 for k in fields-{'legacy_id','mandatory'}),'LAB_CATALOG_TEXT')
        seen.add(row['id'])
    require({r['legacy_id'] for r in data['cases']}==set(range(1,27)),'LAB_CATALOG_MAPPING')
    return data
def fresh(binding,cat):
    require(set(binding)=={'machine','package','session','boot'},'LAB_BINDING_SCHEMA')
    require(all(re.fullmatch(r'[a-f0-9]{64}',binding[k]) for k in ('machine','package')) and re.fullmatch(r'[a-f0-9]{32,64}',binding['session']),'LAB_BINDING_INVALID')
    require(type(binding['boot']) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',binding['boot']),'LAB_BOOT_INVALID')
    return dict(schema=SCHEMA,binding=binding,phase='C0_PREFLIGHT_PASS',revision=0,in_flight=None,
      operator_required=True,checkpoints={},fault_debits={s:0 for s in SERVICES},branch_debits={s:0 for s in SERVICES},restore_count=0,history=[],
      cases={r['id']:dict(status='BLOCKED',started_at=None,completed_at=None,observed='NOT_EXECUTED',evidence_files=[],operator_action=False,limitation='NOT_EXECUTED') for r in cat['cases']})
def validate(state,cat):
    required=set(fresh(dict(machine='a'*64,package='b'*64,session='c'*32,boot='fixture'),cat))
    require(type(state) is dict and set(state)==required and state['schema']==SCHEMA,'LAB_STATE_SCHEMA')
    fresh(state['binding'],cat)
    require(type(state['operator_required']) is bool and type(state['history']) is list and type(state['checkpoints']) is dict,'LAB_STATE_TYPES')
    require(set(state['checkpoints'])<={'C0','C1','C2'} and all(type(v) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,120}',v) for v in state['checkpoints'].values()),'LAB_CHECKPOINT_SCHEMA')
    require(state['phase'] in {'C0_PREFLIGHT_PASS','LAB_FAILED','REVIEW_REQUIRED'}|{v[1] for v in TRANSITIONS.values()},'LAB_STATE_PHASE')
    require(type(state['revision']) is int and 0<=state['revision']<=256 and len(state['history'])<=128,'LAB_HISTORY_BOUND')
    require(set(state['cases'])=={r['id'] for r in cat['cases']},'LAB_STATE_CASES')
    require(set(state['fault_debits'])==set(SERVICES) and all(type(v) is int and 0<=v<=32 for v in state['fault_debits'].values()) and sum(state['fault_debits'].values())<=64,'LAB_FAULT_BOUND')
    require(set(state['branch_debits'])==set(SERVICES) and all(type(v) is int and 0<=v<=4 for v in state['branch_debits'].values()),'LAB_BRANCH_BOUND')
    require(type(state['restore_count']) is int and 0<=state['restore_count']<=12,'LAB_RESTORE_BOUND')
    for row in state['cases'].values():
        require(set(row)=={'status','started_at','completed_at','observed','evidence_files','operator_action','limitation'} and row['status'] in STATUSES,'LAB_RESULT_SCHEMA')
        require(len(row['evidence_files'])<=16 and type(row['operator_action']) is bool,'LAB_EVIDENCE_BOUND')
        require(type(row['evidence_files']) is list,'LAB_EVIDENCE_TYPE')
        require(row['status']!='PASS' or (row['started_at'] is not None and row['completed_at'] is not None and len(row['evidence_files'])>0 and row['observed']!='NOT_EXECUTED'),'LAB_PASS_WITHOUT_EVIDENCE')
        require(type(row['observed']) is str and re.fullmatch(r'[A-Z0-9_]{1,80}',row['observed']),'LAB_OBSERVATION_SCHEMA')
        for e in row['evidence_files']:
            require(type(e) is dict and set(e)=={'path','sha256'} and type(e['path']) is str and re.fullmatch(r'[a-f0-9]{64}',e['sha256']),'LAB_EVIDENCE_SCHEMA')
    require(state['in_flight'] is None or (set(state['in_flight'])=={'phase','started_at','service'} and state['in_flight']['phase'] in TRANSITIONS),'LAB_IN_FLIGHT_SCHEMA')
    return state
def load(root,cat,binding):
    raw=strict((root/'state.json').read_bytes());require(set(raw)=={'payload','sha256'},'LAB_ENVELOPE')
    require(digest(canonical(raw['payload']))==raw['sha256'],'LAB_CORRUPTION')
    state=validate(raw['payload'],cat)
    require(all(state['binding'].get(k)==binding.get(k) for k in ('machine','package','session')),'LAB_WRONG_SESSION')
    return state
def write(root,state,cat):
    validate(state,cat);raw=canonical(dict(payload=state,sha256=digest(canonical(state))))
    require(len(raw)<=262144,'LAB_STATE_SIZE')
    fd,path=tempfile.mkstemp(prefix='.pending-',dir=root)
    try:
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(path,root/'state.json')
    finally:
        if os.path.exists(path):os.unlink(path)
def begin(state,phase,service=None):
    require(state['revision']<250 and len(state['history'])<127,'LAB_HISTORY_FULL')
    if phase=='PrepareRollback' and state['in_flight'] is not None:
        state['history'].append(dict(phase=state['in_flight']['phase'],started_at=state['in_flight']['started_at'],completed_at=now(),status='FAIL'))
        state['phase']='LAB_FAILED';state['in_flight']=None
    require(phase in TRANSITIONS and state['phase'] in TRANSITIONS[phase][0],'LAB_INVALID_TRANSITION')
    require(state['in_flight'] is None,'LAB_INTERRUPTED_OPERATION_REQUIRES_REVIEW')
    if phase=='EnableRustCanary':require('C1' in state['checkpoints'],'LAB_C1_CHECKPOINT_REQUIRED')
    if phase in {'PrepareCheckpointRestore','ResumeCheckpoint'}:
        require('C2' in state['checkpoints'] and state['restore_count']<12,'LAB_RESTORE_BOUND_OR_CHECKPOINT')
    if phase in {'Crash','SCMStorm','NativeHang','StoreFault','PrepareReboot','PrepareSleep','PreparePowerLoss'}:require('C2' in state['checkpoints'],'LAB_C2_CHECKPOINT_REQUIRED')
    if phase in {'Crash','SCMStorm','NativeHang','StoreFault'}:
        debit=4 if phase=='SCMStorm' else 1
        require(service in SERVICES and state['branch_debits'][service]+debit<=4 and state['fault_debits'][service]+debit<=32 and sum(state['fault_debits'].values())+debit<=64,'LAB_FAULT_BUDGET_EXHAUSTED')
        state['fault_debits'][service]+=debit # durable before actuator, including failed/uncertain attempts
        state['branch_debits'][service]+=debit
    state['in_flight']=dict(phase=phase,started_at=now(),service=service);state['revision']+=1
    return state
def finish(state,ok,checkpoint=None):
    op=state['in_flight'];require(op is not None,'LAB_NO_OPERATION')
    if ok and op['phase'].startswith('Confirm'):
        require(type(checkpoint) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,120}',checkpoint),'LAB_CHECKPOINT_ID')
        state['checkpoints'][op['phase'][-2:]]=checkpoint
    # ResumeCheckpoint must use complete_restore after independent verification.
    require(not ok or op['phase']!='ResumeCheckpoint','LAB_RESTORE_VERIFICATION_REQUIRED')
    state['phase']=TRANSITIONS[op['phase']][1] if ok else ('REVIEW_REQUIRED' if op['phase']=='ResumeCheckpoint' else 'LAB_FAILED')
    state['operator_required']=state['phase'].endswith('PENDING') or not ok
    require(len(state['history'])<128,'LAB_HISTORY_FULL')
    state['history'].append(dict(phase=op['phase'],started_at=op['started_at'],completed_at=now(),status='PASS' if ok else 'FAIL'))
    state['in_flight']=None;state['revision']+=1;return state

def complete_restore(state,verification):
    require(state['in_flight'] is not None and state['in_flight']['phase']=='ResumeCheckpoint','LAB_NO_RESTORE_OPERATION')
    require(verification=={'admission':True,'receipt':True,'preserved_evidence':True,'checkpoint':True,'live_baseline':True},'LAB_RESTORE_UNVERIFIED')
    require(state['restore_count']<12,'LAB_RESTORE_BOUND')
    op=state['in_flight'];state['restore_count']+=1
    state['branch_debits']={s:0 for s in SERVICES} # lifetime debits/history/case evidence never reset
    state['history'].append(dict(phase='ResumeCheckpoint',started_at=op['started_at'],completed_at=now(),status='PASS'))
    state['in_flight']=None;state['phase']='C2_BASELINE_PASS';state['operator_required']=False;state['revision']+=1
    return state
def record(state,case_id,status,files,operator=False,code='ASSERTIONS_PASSED'):
    require(case_id in state['cases'] and status in STATUSES,'LAB_CASE_OR_STATUS')
    require(re.fullmatch(r'[A-Z0-9_]{1,80}',code),'LAB_FIXED_CODE_REQUIRED')
    require(0<len(files)<=16,'LAB_EVIDENCE_REQUIRED')
    require(state['cases'][case_id]['status']!='FAIL' or status=='FAIL','LAB_FAILURE_IS_STICKY')
    if state['cases'][case_id]['status']=='PASS' and status=='PASS':return
    state['cases'][case_id]=dict(status=status,started_at=now(),completed_at=now(),observed=code,evidence_files=files,operator_action=operator,limitation='OPERATOR_VERIFIED' if operator else 'AUTOMATED_ASSERTIONS_ONLY')
    state['revision']+=1
def decision(state,cat):
    validate(state,cat)
    if state['phase']=='LAB_FAILED' or any(r['status']=='FAIL' for r in state['cases'].values()) or any(r['status']=='FAIL' for r in state['history']):return 'H1D9 DISPOSABLE INTEGRATION FAIL'
    complete=state['in_flight'] is None and state['phase']=='LAB_COMPLETE' and all(state['cases'][r['id']]['status']=='PASS' or (not r['mandatory'] and state['cases'][r['id']]['status']=='NOT APPLICABLE') for r in cat['cases'])
    return 'H1D9 DISPOSABLE INTEGRATION PASS — READY FOR CONTROLLED PRODUCTION-UPGRADE REVIEW' if complete else 'H1D9 DISPOSABLE INTEGRATION INCOMPLETE'
def evidence(root,path):
    p=Path(path).resolve();require(p.is_relative_to(root.resolve()) and p.is_file() and p.stat().st_size<=1048576,'LAB_EVIDENCE_PATH')
    return dict(path=p.relative_to(root.resolve()).as_posix(),sha256=digest(p.read_bytes()))
def verify_evidence(root,state,cat):
    validate(state,cat)
    # Detect alteration of the previous exported report before regenerating it.
    report_path=root/'LAB_REPORT.md';receipt=root/'LAB_REPORT.sha256.json'
    if report_path.exists() or receipt.exists():
        require(report_path.is_file() and receipt.is_file(),'LAB_REPORT_PAIR_INCOMPLETE')
        previous=strict(receipt.read_bytes(),1024)
        require(set(previous)=={'sha256'} and report_path.stat().st_size<=262144 and digest(report_path.read_bytes())==previous['sha256'],'LAB_REPORT_CHANGED')
    for row in state['cases'].values():
        for e in row['evidence_files']:
            actual=evidence(root,root/e['path']);require(actual==e,'LAB_EVIDENCE_CHANGED')
def report(root,state,cat):
    verify_evidence(root,state,cat)
    report_path=root/'LAB_REPORT.md';receipt=root/'LAB_REPORT.sha256.json'
    counts={s:sum(r['status']==s for r in state['cases'].values()) for s in sorted(STATUSES)}
    lines=['# LAB_REPORT','',f"Package SHA: {state['binding']['package']}",f"Machine UUID SHA: {state['binding']['machine']}",f"Phase: {state['phase']}",'',json.dumps(counts,sort_keys=True),'',
      'Authority invariants: Python authoritative; Rust non-authoritative; primary compile-locked. See AUTH case evidence; unexecuted assertions are not verified.',
      'Security invariant violations: '+('YES / REVIEW FAILURES' if any(r['status']=='FAIL' for r in state['cases'].values()) else 'NO OBSERVED; incomplete coverage is not proof of absence.'),'',
      '| Case | Status | Observation |','|---|---|---|']
    lines += [f"| {r['id']} — {r['title']} | {state['cases'][r['id']]['status']} | {state['cases'][r['id']]['observed']} |" for r in cat['cases']]
    lines += ['','Runtime baseline hashes: packaged runtime-baseline.json. Environment: environment.json. Evidence hashes are in state.json.',
      'Limitations: arbitrary hung Python work is detectable but not safely auto-recoverable; unsupported sleep is not tested; power-loss requires operator evidence; HMAC does not prevent privileged whole-directory rollback; no production upgrade.', '',decision(state,cat)]
    report_path.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    receipt.write_bytes(canonical({'sha256':digest(report_path.read_bytes())}))
def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['init','begin','finish','record','report','inspect']);p.add_argument('--root',type=Path,required=True);p.add_argument('--binding',type=Path,required=True);p.add_argument('--catalog',type=Path,required=True);p.add_argument('--phase');p.add_argument('--service');p.add_argument('--ok',choices=['true','false']);p.add_argument('--checkpoint');p.add_argument('--case');p.add_argument('--status',choices=sorted(STATUSES));p.add_argument('--evidence',type=Path);p.add_argument('--operator',action='store_true');p.add_argument('--code',default='ASSERTIONS_PASSED');a=p.parse_args()
    cat=catalog(a.catalog);binding=strict(a.binding.read_bytes());root=a.root
    if a.action=='init':
        require(not (root/'state.json').exists() and not (root/'initialized').exists(),'LAB_ALREADY_INITIALIZED')
        (root/'initialized').write_bytes(b'cd.lab.initialized.v1\n');state=fresh(binding,cat)
    else:state=load(root,cat,binding)
    if a.action=='begin':state=begin(state,a.phase,a.service)
    if a.action=='finish':state=finish(state,a.ok=='true',a.checkpoint)
    if a.action=='record':record(state,a.case,a.status,[evidence(root,a.evidence)],a.operator,a.code)
    if a.action not in {'report','inspect'}:write(root,state,cat)
    if a.action=='report':report(root,state,cat)
    print(json.dumps(dict(phase=state['phase'],in_flight=state['in_flight'],operator_required=state['operator_required'],decision=decision(state,cat))))
if __name__=='__main__':
    try:main()
    except Exception:print('LAB_STATE_REJECTED_REQUIRES_OPERATOR_REVIEW',file=sys.stderr);raise SystemExit(20)
