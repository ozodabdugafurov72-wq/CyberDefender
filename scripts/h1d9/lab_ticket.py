"""At-most-once legacy actuator tickets inside the admitted protected lab root.
Exclusive consumed markers survive process replacement and checkpoint export.
No ticket authorizes any production action. ACL/administrator trust is required.
"""
import argparse,os,re,sys
from pathlib import Path
import lab_state as s
MAP={'Install':({'Install'},1),'EnableCanary':({'EnableRustCanary'},1),'CrashOnce':({'Crash','SCMStorm'},4),'CleanRestart':({'CleanRestart'},1)}
def check(root,state,action,service):
    s.require(action in MAP and state['in_flight'] is not None,'LAB_ACTUATOR_WITHOUT_OPERATION')
    op=state['in_flight'];s.require(op['phase'] in MAP[action][0] and op['service']==service,'LAB_ACTUATOR_OPERATION_MISMATCH')
    return 4 if op['phase']=='SCMStorm' else 1
def issue(root,state,action,service):
    limit=check(root,state,action,service)
    for i in range(limit):
        path=root/f'act-{state["revision"]}-{i}.json'
        if path.exists():continue
        data=dict(schema='cd.lab.actuator.v1',ordinal=i,revision=state['revision'],binding=state['binding'],action=action,service=service,in_flight=state['in_flight'])
        with path.open('xb') as f:f.write(s.canonical(data));f.flush();os.fsync(f.fileno())
        return path
    raise ValueError('LAB_ACTUATOR_TICKET_LIMIT')
def consume(root,state,path,action,service):
    limit=check(root,state,action,service)
    match=re.fullmatch(r'act-([0-9]+)-([0-3])\.json',path.name)
    s.require(path.parent==root and match is not None,'LAB_TICKET_PATH')
    ordinal=int(match[2]);s.require(int(match[1])==state['revision'] and ordinal<limit,'LAB_TICKET_ORDINAL')
    s.require(path.name==f'act-{state["revision"]}-{ordinal}.json','LAB_NONCANONICAL_TICKET_PATH')
    data=s.strict(path.read_bytes(),4096)
    s.require(data==dict(schema='cd.lab.actuator.v1',ordinal=ordinal,revision=state['revision'],binding=state['binding'],action=action,service=service,in_flight=state['in_flight']),'LAB_STALE_ACTUATOR_TICKET')
    # Durable consume precedes actuator: uncertainty loses this attempt, never retries it.
    with path.with_suffix('.used').open('xb') as f:f.write(b'CONSUMED\n');f.flush();os.fsync(f.fileno())
def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--ticket',type=Path,required=True);p.add_argument('--action',required=True);p.add_argument('--service',choices=s.SERVICES,required=True);p.add_argument('--package',required=True);p.add_argument('--machine',required=True);p.add_argument('--session',required=True);a=p.parse_args()
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]));from agent.service_crash_store import protected_path
    protected_path(a.root);protected_path(a.ticket)
    s.require(a.root==Path('C:/H1D9/results')/a.session,'LAB_TICKET_ROOT')
    cat=s.catalog(Path(__file__).with_name('test_catalog.json'))
    state=s.load(a.root,cat,dict(package=a.package,machine=a.machine,session=a.session))
    consume(a.root,state,a.ticket,a.action,a.service)
if __name__=='__main__':
    try:main()
    except Exception:print('LAB_ACTUATOR_DENIED_REVIEW_REQUIRED');raise SystemExit(20)
