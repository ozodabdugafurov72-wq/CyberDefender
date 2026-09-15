"""Guest-only read-only observations; no privileged actuators, raw telemetry export or keys."""
from __future__ import annotations
import argparse, hashlib, hmac, json, os, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from agent.service_crash_store import canonical, strict_json, validate_record, protected_path, MAX_BYTES
from agent.service_crash_guard import SERVICES
from agent.service_lifecycle import boot_identity
from agent.service_watchdog import active_time

def read_store(root,service,validator=protected_path):
    """Read-only coherent authenticated anchor/slot/anchor, without claiming writer ownership."""
    validator(root)
    for name in ('guard.key','provisioned'):validator(root/name)
    with (root/'guard.key').open('rb') as f:key=f.read(33)
    if len(key)!=32:raise ValueError('STORE_KEY_INVALID')
    with (root/'provisioned').open('rb') as f:marker=f.read(64)
    if marker!=b'cd.crash-provision.v1\n':raise ValueError('STORE_MARKER_INVALID')
    def read(path):
        validator(path)
        with path.open('rb') as f:raw=f.read(MAX_BYTES+1)
        data=strict_json(raw)
        if set(data)!={'payload','mac'} or not hmac.compare_digest(data['mac'],hmac.new(key,canonical(data['payload']),hashlib.sha256).hexdigest()):raise ValueError('STORE_AUTH_INVALID')
        return data['payload']
    for _ in range(3):
        a=read(root/(service+'.anchor'))
        if set(a)!={'schema','service','revision','digest'} or a['schema']!='cd.crash-anchor.v1' or a['service']!=service or type(a['revision']) is not int or a['revision']<0:raise ValueError('STORE_ANCHOR_INVALID')
        r=read(root/(service+f'.{a["revision"]%2}.json'));validate_record(r,service)
        again=read(root/(service+'.anchor'))
        if a!=again:continue
        if r['revision']!=a['revision'] or hashlib.sha256(canonical(r)).hexdigest()!=a['digest']:raise ValueError('STORE_REPLAY_INVALID')
        return {k:r[k] for k in ('service','state','revision','boot','generation','cumulative_failures','attempts_since_stable','probes_used','repair_count','progress_count','clean_stop','active_attempt')}
    raise ValueError('STORE_BUSY_UNVERIFIED')

def directory_size(root):
    total=count=0
    if not root.exists():return 0
    for directory,_,files in os.walk(root,followlinks=False):
        for name in files:
            count+=1
            if count>10000:raise ValueError('FILE_COUNT_BOUND')
            p=Path(directory)/name
            if not p.is_symlink():total+=p.stat().st_size
    return total

def bounded_hash(path):
    if not path.is_file() or path.stat().st_size>64*1024*1024:return None
    h=hashlib.sha256()
    with path.open('rb') as f:
        total=0
        while chunk:=f.read(65536):
            total+=len(chunk)
            if total>64*1024*1024:raise ValueError('HASH_SIZE_BOUND')
            h.update(chunk)
    return h.hexdigest()

def snapshot():
    import psutil
    import win32service as scm
    from win32com.shell import shell,shellcon
    installed=Path(shell.SHGetFolderPath(0,shellcon.CSIDL_PROGRAM_FILES,None,0))/'CyberDefender/app'
    data=Path(shell.SHGetFolderPath(0,shellcon.CSIDL_COMMON_APPDATA,None,0))
    baseline=json.loads((ROOT/'scripts/h1d9/runtime-baseline.json').read_text())
    runtime_hashes=all(bounded_hash(installed/n)==h for n,h in baseline['hashes'].items())
    services={}
    modules=('agent.windows_service','control_plane.windows_service','dashboard_owner.windows_service')
    for name,module in zip(SERVICES,modules):
        s=psutil.win_service_get(name).as_dict();pid=s['pid'];p=psutil.Process(pid) if pid else None
        expected='"'+str(installed/'.venv/Scripts/python.exe')+'" -m '+module+' --service-run'
        services[name]=dict(pid=pid,status=s['status'],automatic=s['start_type']=='automatic',
          identity_ok=s['binpath']==expected and s['username']=='LocalSystem',
          created=p.create_time() if p else None,cpu_seconds=sum(p.cpu_times()[:2]) if p else None,
          rss=p.memory_info().rss if p else None,handles=p.num_handles() if p else None)
        manager=scm.OpenSCManager(None,None,scm.SC_MANAGER_CONNECT)
        handle=None
        try:
            handle=scm.OpenService(manager,name,scm.SERVICE_QUERY_CONFIG)
            recovery=scm.QueryServiceConfig2(handle,scm.SERVICE_CONFIG_FAILURE_ACTIONS)
            flag=scm.QueryServiceConfig2(handle,scm.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)
            services[name]['scm_finite']=recovery['Actions']==((1,5000),(1,15000),(1,60000),(0,0)) and recovery['ResetPeriod']==86400 and flag is True
        finally:
            if handle is not None:scm.CloseServiceHandle(handle)
            scm.CloseServiceHandle(manager)
    f=data/'CyberDefender/state/dashboard_runtime.json'
    with f.open('rb') as handle:raw=handle.read(8*1024*1024+1)
    if len(raw)>8*1024*1024:raise ValueError('RUNTIME_SIZE')
    runtime=json.loads(raw)
    # Never export arbitrary strings through nominally numeric diagnostics fields.
    import math
    failures=runtime['runtime'].get('component_failures');sequence=runtime['publisher']['sequence'];generated=runtime['publisher']['generated_at']
    if type(failures) is not int or failures<0 or type(sequence) is not int or sequence<0 or type(generated) not in (int,float) or not math.isfinite(generated):raise ValueError('RUNTIME_NUMERIC_SCHEMA')
    a=runtime['health']['process_sensor_authority'];c=runtime['health']['rust_process_canary']
    target=installed/'native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe'
    manifest=json.loads((ROOT.parent/'manifest.json').read_text())
    pin=next(r['sha256'] for r in manifest['files'] if r['path']=='native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe')
    children=[]
    for p in psutil.process_iter(['pid','name','ppid','create_time']):
        if p.info['name']!='cyberdefender-process-sensor.exe':continue
        expected_path=Path(p.exe())==target
        bound=p.info['ppid']==services['CyberDefenderAgent']['pid']
        allowed={'SYSTEMROOT','WINDIR','CYBERDEFENDER_SENSOR_LAUNCH_NONCE','CYBERDEFENDER_SENSOR_SUPERVISOR_PID'}
        env=p.environ() if expected_path and bound else {}
        children.append(dict(pid=p.pid,parent=p.ppid(),created=p.create_time(),path_ok=expected_path,bound=bound,
                             environment_ok=set(env)==allowed and env.get('CYBERDEFENDER_SENSOR_SUPERVISOR_PID')==str(p.ppid())))
    stores={}
    for s in SERVICES:
        try:stores[s]=dict(valid=True,**read_store(data/'CyberDefenderCrashGuard',s))
        except Exception:stores[s]=dict(valid=False,reason='STORE_UNVERIFIED')
    import urllib.request
    http=[]
    for url in ('http://127.0.0.1:8785/health','http://127.0.0.1:8775/owner/api/state'):
        try:
            with urllib.request.urlopen(url,timeout=2) as r:http.append(r.status==200)
        except Exception:http.append(False)
    return dict(schema='cd.lab.observation.v1',utc=time.time(),boot=boot_identity(),awake=active_time(),
      services=services,children=children,stores=stores,http_ok=all(http),runtime_hashes_valid=runtime_hashes,
      runtime_healthy=runtime['runtime'].get('status')=='HEALTHY',component_failures=failures,
      runtime_age=time.time()-generated,sequence=sequence,
      python_authoritative=a.get('authoritative_sensor')=='ProcessSensor',primary_locked=a.get('compiled_primary_enabled') is False,
      rust_non_authoritative=c.get('authoritative') is False,canary_healthy=c.get('status')=='HEALTHY',
      canary_mode=a.get('mode')=='RUST_CANARY',python_only_mode=a.get('mode')=='PYTHON_ONLY',pin_valid=bounded_hash(target)==pin,
      identity_material_present=all((data/'CyberDefender'/n).is_file() for n in ('secrets/storage_key.b64','secrets/fleet_token.txt','identity/endpoint_id.txt')),
      cpu_percent=psutil.cpu_percent(interval=0.25),available_ram=psutil.virtual_memory().available,
      process_count=len(psutil.pids()),disk_free=psutil.disk_usage('C:/').free,
      log_bytes=directory_size(data/'CyberDefender/logs'),guard_bytes=directory_size(data/'CyberDefenderCrashGuard'))

def baseline_errors(s,canary=None):
    errors=[]
    for k in ('http_ok','runtime_hashes_valid','runtime_healthy','python_authoritative','primary_locked','rust_non_authoritative','pin_valid','identity_material_present'):
        if s.get(k) is not True:errors.append(k.upper())
    if s.get('component_failures')!=0:errors.append('COMPONENT_FAILURES')
    if not 0<=s.get('runtime_age',9999)<=15:errors.append('STALE_RUNTIME')
    for name in SERVICES:
        row=s['services'][name]
        if row['status']!='running' or not row['automatic'] or not row['identity_ok']:errors.append('SERVICE_UNHEALTHY')
        if not s['stores'][name]['valid']:errors.append('STORE_UNVERIFIED')
    children=s['children']
    if len(children)>1 or any(not c['path_ok'] or not c['bound'] or not c['environment_ok'] for c in children):errors.append('CHILD_INVARIANT')
    if canary is True and (len(children)!=1 or not s['canary_healthy'] or not s['canary_mode']):errors.append('CANARY_NOT_READY')
    if canary is False and (children or not s['python_only_mode']):errors.append('PYTHON_BASELINE_NOT_CLEAN')
    return sorted(set(errors))
def persistence_errors(before,after,reboot=False):
    errors=[]
    if reboot and before['boot']==after['boot']:errors.append('REBOOT_NOT_PROVEN')
    for name in SERVICES:
        a=before['stores'][name];b=after['stores'][name]
        if not a['valid'] or not b['valid']:errors.append('STORE_UNVERIFIED');continue
        if b['revision']<a['revision'] or b['cumulative_failures']<a['cumulative_failures']:errors.append('PERSISTENCE_REGRESSION')
        if reboot and b['boot']!=after['boot']:errors.append('STORE_BOOT_MISMATCH')
    return sorted(set(errors))
def main():
    p=argparse.ArgumentParser();p.add_argument('--authorization',required=True);p.add_argument('--archive',required=True);p.add_argument('--sha',required=True);a=p.parse_args()
    native=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0';env=os.environ.copy();env['PSModulePath']=str(native/'Modules')
    cmd=[str(native/'powershell.exe'),'-NoProfile','-NonInteractive','-File',str(ROOT/'scripts/h1d9/guest.ps1'),'-Phase','Admission','-GuestAuthorization',a.authorization,'-Archive',a.archive,'-PackageSha256',a.sha]
    gate=subprocess.run(cmd,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
    if gate.returncode:raise ValueError('ADMISSION_REQUIRED')
    print(json.dumps(snapshot(),allow_nan=False))
if __name__=='__main__':
    try:main()
    except Exception:print('{"schema":"cd.lab.observation.v1","error":"OBSERVATION_UNVERIFIED"}');raise SystemExit(20)
