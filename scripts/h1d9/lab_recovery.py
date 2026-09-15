"""Bounded checkpoint export/resume verification. No restore or OS actuator."""
import json,re,uuid
from pathlib import Path
import lab_state as s
IGNORED={'engine.lock','orchestrator.lock'}
def files(root,exclude=()):
    rows={};total=0
    for p in sorted(root.iterdir()):
        if p.name in IGNORED or p.name in exclude:continue
        s.require(not p.is_symlink() and not p.is_junction() and p.is_file(),'LAB_EXPORT_UNEXPECTED_ENTRY')
        s.require(re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',p.name),'LAB_EXPORT_NAME')
        total+=p.stat().st_size
        s.require(len(rows)<512 and total<=32*1024*1024,'LAB_EXPORT_BOUND')
        rows[p.name]=s.evidence(root,p)
    return rows
def prepare(root,state):
    s.require(state['phase']=='CHECKPOINT_RESTORE_PENDING' and state['in_flight'] is None,'LAB_EXPORT_PHASE')
    checkpoint=s.strict((root/'checkpoint-C2.json').read_bytes())
    s.require(checkpoint['checkpoint']==state['checkpoints']['C2'],'LAB_CHECKPOINT_BINDING')
    name=f'checkpoint-export-{state["revision"]}.json'
    data=dict(schema='cd.lab.checkpoint-export.v1',nonce=uuid.uuid4().hex,revision=state['revision'],restore_count=state['restore_count'],
      binding=state['binding'],checkpoint=state['checkpoints']['C2'],files=files(root))
    raw=s.canonical(data);s.require(len(raw)<=262144,'LAB_EXPORT_MANIFEST_BOUND')
    with (root/name).open('xb') as f:f.write(raw);f.flush();__import__('os').fsync(f.fileno())
    return dict(file=name,state_sha256=s.digest((root/'state.json').read_bytes()),export_sha256=s.digest(raw),nonce=data['nonce'])
def verify(root,state,receipt,state_sha,export_sha,boot):
    s.require(state['phase']=='CHECKPOINT_RESTORE_PENDING' and state['in_flight'] is None,'LAB_RESTORE_NOT_PENDING')
    s.require(all(type(h) is str and re.fullmatch('[a-f0-9]{64}',h) for h in (state_sha,export_sha)),'LAB_EXTERNAL_HASH_REQUIRED')
    s.require(s.digest((root/'state.json').read_bytes())==state_sha,'LAB_PRESERVED_STATE_MISMATCH')
    name=f'checkpoint-export-{state["revision"]}.json';raw=(root/name).read_bytes()
    s.require(s.digest(raw)==export_sha,'LAB_EXPORT_HASH_MISMATCH');data=s.strict(raw)
    s.require(set(data)=={'schema','nonce','revision','restore_count','binding','checkpoint','files'} and data['schema']=='cd.lab.checkpoint-export.v1','LAB_EXPORT_SCHEMA')
    s.require(data['binding']==state['binding'] and data['revision']==state['revision'] and data['restore_count']==state['restore_count'],'LAB_STALE_EXPORT')
    s.require(data['files']==files(root,exclude=(name,)),'LAB_PRESERVED_EVIDENCE_CHANGED')
    fields={'schema','session','package_sha256','machine_sha256','checkpoint','nonce','state_sha256','export_sha256','current_boot','staff_reference','restored','preserved_evidence'}
    s.require(type(receipt) is dict and set(receipt)==fields and receipt['schema']=='cd.lab.restore-receipt.v1','LAB_RESTORE_RECEIPT_SCHEMA')
    expected=dict(session=state['binding']['session'],package_sha256=state['binding']['package'],machine_sha256=state['binding']['machine'],
      checkpoint=state['checkpoints']['C2'],nonce=data['nonce'],state_sha256=state_sha,export_sha256=export_sha,current_boot=boot)
    s.require(all(receipt[k]==v for k,v in expected.items()) and data['checkpoint']==expected['checkpoint'],'LAB_STALE_CHECKPOINT_OR_RECEIPT')
    s.require(receipt['restored'] is True and receipt['preserved_evidence'] is True and re.fullmatch(r'[A-Za-z0-9_.:-]{3,80}',receipt['staff_reference']),'LAB_STAFF_RESTORE_ACK_REQUIRED')
    checkpoint=s.strict((root/'checkpoint-C2.json').read_bytes())
    s.require(checkpoint['checkpoint']==expected['checkpoint'],'LAB_CHECKPOINT_BINDING')
    return checkpoint['observation']

def live_errors(checkpoint,current):
    import lab_probe
    errors=lab_probe.baseline_errors(current,True)
    for name in s.SERVICES:
        old=checkpoint['stores'][name];new=current['stores'][name]
        if not old['valid'] or not new['valid'] or new.get('revision',-1)<old.get('revision',0) or new.get('cumulative_failures',-1)<old.get('cumulative_failures',0):errors.append('CHECKPOINT_STORE_REGRESSION')
        if not current['services'][name]['scm_finite']:errors.append('SCM_CONFIG_NOT_FINITE')
    return sorted(set(errors))
