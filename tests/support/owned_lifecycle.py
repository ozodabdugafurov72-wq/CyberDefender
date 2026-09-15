"""Explicit opt-in guardian for the six reviewed lifecycle tests; never runtime code.

Termination uses retained creation handles/private jobs, never PID reopening.
The run binding is recorded at launch, independent of the tested child environment.
"""
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import threading

ROOT=Path(__file__).resolve().parents[2]
SCRIPTS=('test_h1d_child_containment.py','test_h1d_child_environment.py','test_h1d_launch_admission.py','test_h1d_native_live.py','test_h1d9_release_native.py','test_native_process_supervisor_contract_v1.py')
ACTIVE=None

def validate(expected,current,token):
    if token!=expected['run'] or any(current.get(k)!=expected[k] for k in ('pid','created','parent','session','executable')):
        raise PermissionError('FIXTURE_IDENTITY_MISMATCH')
    if not current['alive']:raise PermissionError('FIXTURE_ALREADY_EXITED')

def snapshot(child):
    import psutil,win32process,win32event,win32ts
    handle=child._handle
    pid=win32process.GetProcessId(handle)
    created=win32process.GetProcessTimes(handle)['CreationTime'].isoformat()
    alive=win32event.WaitForSingleObject(handle,0)==258
    if not alive:return dict(pid=pid,created=created,alive=False)
    p=psutil.Process(pid)
    result=dict(pid=pid,created=created,parent=p.ppid(),session=win32ts.ProcessIdToSessionId(pid),executable=str(Path(p.exe()).resolve()).lower(),alive=True)
    # A PID lookup can race with exit/reuse, but the retained HANDLE cannot.
    if child.poll() is not None:raise PermissionError('FIXTURE_EXIT_DURING_IDENTITY_CHECK')
    if abs(p.create_time()-win32process.GetProcessTimes(handle)['CreationTime'].timestamp())>0.001:
        raise PermissionError('FIXTURE_PID_REUSED')
    return result

class Guardian:
    def __init__(self,run,out):
        import win32ts
        self.run=run;self.out=Path(out);self.records=[];self.events=[];self.lock=threading.RLock()
        self.session=win32ts.ProcessIdToSessionId(os.getpid());self.parent=os.getpid()
        self.path=self.out/f'{run}-{os.getpid()}.json'
        self.allowed_code=set()
        for name in SCRIPTS:
            tree=ast.parse((ROOT/'tests'/name).read_text())
            for node in ast.walk(tree):
                if isinstance(node,ast.Constant) and isinstance(node.value,str) and 'import ' in node.value:
                    self.allowed_code.add(node.value)
        # Nested code literal inside the reviewed parent-death fixture.
        self.allowed_code.add('import os,time; print(os.getpid(),flush=True); time.sleep(60)')
        self.images={str(Path(sys._base_executable).resolve()).lower(),str(Path(sys.executable).resolve()).lower()}
        self.native={str((ROOT/f'native/process_sensor_v0_5_1/target/{build}/cyberdefender-process-sensor.exe').resolve()).lower():hashlib.sha256((ROOT/f'native/process_sensor_v0_5_1/target/{build}/cyberdefender-process-sensor.exe').read_bytes()).hexdigest() for build in ('debug','release')}
    def event(self,kind,**data):
        with self.lock:
            if len(self.events)>=4096:raise PermissionError('FIXTURE_AUDIT_BOUND')
            self.events.append(dict(kind=kind,time=time.time(),**data))
            raw=json.dumps(dict(schema='cd.test-child.v1',run=self.run,owner_pid=self.parent,events=self.events),indent=2)
            temp=self.path.with_suffix('.tmp');temp.write_text(raw,encoding='utf-8');os.replace(temp,self.path)
    def command(self,args):
        args=list(args);exe=str(Path(args[0]).resolve()).lower()
        if exe in self.native:
            if hashlib.sha256(Path(args[0]).read_bytes()).hexdigest()!=self.native[exe]:raise PermissionError('FIXTURE_BINARY_CHANGED')
            return args
        if exe not in self.images:raise PermissionError('FIXTURE_EXECUTABLE_NOT_ALLOWED')
        if len(args)>2 and args[1]=='-c':
            code=args[2]
            if code not in self.allowed_code:raise PermissionError('FIXTURE_INLINE_NOT_REVIEWED')
            tail=args[3:]
        elif len(args)>=2 and Path(args[1]).resolve()==ROOT/'tests/support/fake_process_sensor_ipc_v1.py':
            code='import runpy; runpy.run_path('+repr(str(ROOT/'tests/support/fake_process_sensor_ipc_v1.py'))+',run_name="__main__")'
            tail=args[2:]
        else:raise PermissionError('FIXTURE_COMMAND_NOT_ALLOWED')
        # Use the same Python installation directly to avoid an untracked venv launcher.
        # Explicit paths preserve imports even when the sensor environment is restricted.
        prefix='import sys,site; sys.path.insert(0,'+repr(str(ROOT))+'); site.addsitedir('+repr(str(ROOT/'.venv/Lib/site-packages'))+'); from tests.support.owned_lifecycle import install; install('+repr(self.run)+','+repr(str(self.out))+'); '
        return [sys._base_executable,'-c',prefix+code,*tail]
    def register(self,child,command):
        if len(self.records)>=256:raise PermissionError('FIXTURE_CHILD_BOUND')
        current=snapshot(child)
        expected=dict(current,run=self.run,launch_id=uuid.uuid4().hex)
        if current['alive'] and (current['parent']!=self.parent or current['session']!=self.session or current['executable'] not in self.images|set(self.native)):
            raise PermissionError('FIXTURE_LAUNCH_IDENTITY')
        row=dict(child=child,identity=expected,exited=not current['alive']);self.records.append(row)
        self.event('spawn',identity=expected,command_sha256=hashlib.sha256(json.dumps(command).encode()).hexdigest())
        return row
    def authorize(self,row,reason):
        if row['exited']:
            self.event('already_exited_no_termination',launch_id=row['identity']['launch_id']);return False
        current=snapshot(row['child'])
        if not current['alive']:
            row['exited']=True;self.event('natural_exit',launch_id=row['identity']['launch_id']);return False
        validate(row['identity'],current,self.run)
        self.event('identity_verified_before_termination',reason=reason,identity=current,launch_id=row['identity']['launch_id'])
        return True
    def ended(self,row):
        row['child'].wait(timeout=3);row['exited']=True
        self.event('exit_verified',launch_id=row['identity']['launch_id'],pid=row['identity']['pid'])
    def finish(self):
        for row in self.records:
            if not row['exited']:self.ended(row)
        self.event('owner_cleanup_complete',children=len(self.records))

def install(run,out):
    global ACTIVE
    if ACTIVE is not None:return ACTIVE
    import win32job
    from agent.sensors import windows_child_containment as containment
    guard=Guardian(run,out);ACTIVE=guard
    original_popen=subprocess.Popen;original_launch=containment.launch_contained
    original_kill=containment.ContainedProcess.kill;original_release=containment.ContainedProcess.release
    original_exit=os._exit;original_job_terminate=win32job.TerminateJobObject
    class GuardedPopen(original_popen):
        def __init__(self,args,*a,**kw):
            if kw.get('shell') or kw.get('executable'):raise PermissionError('FIXTURE_SHELL_DENIED')
            command=guard.command(args);super().__init__(command,*a,**kw);self._owned=guard.register(self,command)
        def terminate(self):
            if guard.authorize(self._owned,'Popen retained handle'):
                original_popen.terminate(self);guard.ended(self._owned)
        kill=terminate
    class Job:
        def __init__(self,raw,row):self.raw=raw;self.row=row;self.closed=False
        def Close(self):
            if self.closed:return
            live=guard.authorize(self.row,'Private Job Object close')
            self.raw.Close();self.closed=True
            if live:guard.ended(self.row)
    def launch(command,env):
        command=guard.command(command);child=original_launch(command,env)
        child._owned=guard.register(child,command);child._job=Job(child._job,child._owned)
        return child
    def kill(child):
        if guard.authorize(child._owned,'Private Job Object termination'):
            original_job_terminate(child._job.raw,1);guard.ended(child._owned)
    def release(child):
        if child.poll() is None:raise PermissionError('FIXTURE_RELEASE_ALIVE')
        child._owned['exited']=True
        guard.event('exit_verified',launch_id=child._owned['identity']['launch_id'],pid=child.pid)
        original_release(child)
    def abrupt(code):
        # OS job-handle closure on this owned parent's death is the test subject.
        for row in guard.records:
            guard.authorize(row,'Owned parent about to exit; kernel job containment')
        guard.event('owned_parent_exit',exit_code=code)
        original_exit(code)
    subprocess.Popen=GuardedPopen;containment.launch_contained=launch
    containment.ContainedProcess.kill=kill;containment.ContainedProcess.release=release;os._exit=abrupt
    return guard
