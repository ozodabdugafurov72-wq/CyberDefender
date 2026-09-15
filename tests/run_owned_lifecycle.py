"""Run an unchanged, allowlisted lifecycle test under explicit identity guarding."""
import json,os,runpy,sys,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tests.support.owned_lifecycle import SCRIPTS,install
import psutil

def services():
    result={}
    for name in ('CyberDefenderAgent','CyberDefenderControlPlane','CyberDefenderOwnerUI'):
        s=psutil.win_service_get(name).as_dict();p=psutil.Process(s['pid'])
        result[name]=dict(pid=s['pid'],created=p.create_time(),status=s['status'],start_type=s['start_type'])
    return result

if __name__=='__main__':
    script=Path(sys.argv[1]).resolve();out=Path(sys.argv[2]).resolve()
    assert script.parent==ROOT/'tests' and script.name in SCRIPTS
    out.mkdir(parents=True,exist_ok=True);before=services();start=time.time();run=uuid.uuid4().hex
    guard=install(run,out);sys.argv=[str(script)];code=0
    try:runpy.run_path(str(script),run_name='__main__')
    except SystemExit as exc:code=exc.code or 0
    finally:
        guard.finish();after=services()
        # All recorded children, including native children of deliberately exited parents,
        # must be gone. Reused PIDs are never terminated or treated as our old child.
        remaining=[]
        for p in out.glob(run+'-*.json'):
            for e in json.loads(p.read_text())['events']:
                if e['kind']!='spawn':continue
                identity=e['identity']
                try:
                    process=psutil.Process(identity['pid'])
                    from datetime import datetime
                    if abs(process.create_time()-datetime.fromisoformat(identity['created']).timestamp())<.001:
                        try:process.wait(timeout=5)
                        except psutil.TimeoutExpired:remaining.append(identity['pid'])
                except psutil.NoSuchProcess:pass
        summary=dict(script=str(script),run=run,start=start,end=time.time(),exit=code,production_before=before,production_after=after,production_unchanged=before==after,remaining_owned_children=remaining)
        (out/'result.json').write_text(json.dumps(summary,indent=2))
        assert before==after and not remaining,'UNEXPECTED_PROCESS_EFFECT'
    raise SystemExit(code)
