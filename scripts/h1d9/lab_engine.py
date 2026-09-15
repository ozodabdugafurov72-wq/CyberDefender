"""One admitted lab phase per invocation. No automatic reboot, power-off or rollback."""
from __future__ import annotations
import argparse,json,os,re,subprocess,sys,tempfile,time,shutil
from pathlib import Path
import lab_state as ledger
import lab_probe as probe
import lab_recovery as recovery
import lab_ticket as tickets
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
NATIVE=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'

def guest(args,phase):
    env=os.environ.copy();env['PSModulePath']=str(NATIVE.parent/'Modules')
    cmd=[str(NATIVE),'-NoProfile','-NonInteractive','-File',str(HERE/'guest.ps1'),'-Phase',phase,
      '-GuestAuthorization',args.authorization,'-Archive',args.archive,'-PackageSha256',args.sha,'-Python',sys.executable,'-Service',args.service]
    if phase in tickets.MAP:
        raw=ledger.strict((args.root/'state.json').read_bytes());state=raw['payload']
        ledger.require(ledger.digest(ledger.canonical(state))==raw['sha256'],'LAB_STATE_CORRUPTION')
        ledger.validate(state,ledger.catalog(HERE/'test_catalog.json'))
        ticket=tickets.issue(args.root,state,phase,args.service)
        cmd+=['-ActuatorTicket',str(ticket)]
    p=subprocess.run(cmd,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900 if phase=='Install' else 60)
    ledger.require(p.returncode==0,'LAB_GUEST_PHASE_FAILED')

def save(root,name,data):
    ledger.require(re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}',name),'LAB_EVIDENCE_NAME')
    raw=ledger.canonical(data);ledger.require(len(raw)<=1048576,'LAB_EVIDENCE_SIZE')
    files=list(root.glob('*.json'));ledger.require(len(files)<256 and sum(p.stat().st_size for p in files)+len(raw)<32*1024*1024,'LAB_EVIDENCE_RETENTION')
    path=root/name
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return path

def wait_baseline(canary=None,timeout=95):
    deadline=time.monotonic()+timeout;previous=None;stable=0
    while time.monotonic()<deadline:
        try:
            s=probe.snapshot();errors=probe.baseline_errors(s,canary)
            if not s['primary_locked'] or len(s['children'])>1:raise RuntimeError('LAB_CRITICAL_INVARIANT')
            progressing=previous is not None and s['sequence']>previous['sequence'] and all(s['stores'][n].get('progress_count',0)>previous['stores'][n].get('progress_count',0) for n in ledger.SERVICES)
            stable=stable+1 if not errors and progressing else 0;previous=s
            if stable>=2:return s
        except RuntimeError:raise
        except Exception:stable=0
        time.sleep(5)
    raise ValueError('LAB_BASELINE_TIMEOUT')

def main():
    p=argparse.ArgumentParser();p.add_argument('--phase',required=True);p.add_argument('--root',type=Path,required=True)
    p.add_argument('--authorization',required=True);p.add_argument('--archive',required=True);p.add_argument('--sha',required=True)
    p.add_argument('--service',choices=ledger.SERVICES,default=ledger.SERVICES[0]);p.add_argument('--checkpoint');p.add_argument('--receipt',type=Path)
    p.add_argument('--preserved-state-sha');p.add_argument('--export-sha')
    p.add_argument('--samples',type=int,default=60);p.add_argument('--variant',choices=['truncate','corrupt','oversized','wrong-schema','wrong-service','delete-slot','delete-anchor'],default='truncate');args=p.parse_args()
    # Defense in depth for direct Python invocation, before any state/machine access.
    guest(args,'Admission')
    from agent.service_crash_store import protected_path,default_root
    protected_path(args.root)
    auth=ledger.strict(Path(args.authorization).read_bytes(),8192)
    ledger.require(auth.get('schema')=='cd.h1d9.authorization.v2' and auth.get('staff_authorized') is True and auth.get('warnings_reviewed') is True,'UNIVERSITY_LAB_AUTHORIZATION_REQUIRED')
    ledger.require(args.root.absolute()==Path('C:/H1D9/results')/auth['lab_nonce'],'LAB_ROOT_REJECTED')
    import win32file,win32con
    lock_path=args.root/'engine.lock'
    if lock_path.exists():
        from agent.service_crash_store import no_reparse
        no_reparse(lock_path)
    engine_lock=win32file.CreateFile(str(lock_path),win32con.GENERIC_READ|win32con.GENERIC_WRITE,0,None,win32con.OPEN_ALWAYS,0,None)
    binding=dict(machine=auth['guest_uuid_sha256'],package=args.sha,session=auth['lab_nonce'],boot=probe.boot_identity())
    cat=ledger.catalog(HERE/'test_catalog.json');root=args.root
    if args.phase=='Preflight':
        guest(args,'Preflight')
        ledger.require(not (root/'state.json').exists() and not (root/'initialized').exists(),'LAB_ALREADY_INITIALIZED')
        save(root,'initialized',dict(schema='cd.lab.initialized.v1'))
        state=ledger.fresh(binding,cat);ledger.write(root,state,cat)
        save(root,'binding.json',binding)
        env=os.environ.copy();env['PSModulePath']=str(NATIVE.parent/'Modules')
        result=subprocess.run([str(NATIVE),'-NoProfile','-NonInteractive','-File',str(HERE/'lab_preflight.ps1')],capture_output=True,text=True,env=env,timeout=60)
        ledger.require(result.returncode in (0,10),'LAB_PREFLIGHT_BLOCKED')
        save(root,'environment.json',ledger.strict(result.stdout.encode(),1048576))
        ledger.report(root,state,cat);print('C0_PREFLIGHT_PASS; CONFIRM_C0_REQUIRED');return
    state=ledger.load(root,cat,binding)
    ledger.verify_evidence(root,state,cat)
    if args.phase=='ResumeCheckpoint' and state['in_flight'] is not None:
        state['phase']='REVIEW_REQUIRED';state['operator_required']=True;ledger.write(root,state,cat)
        print('REVIEW_REQUIRED; DEGRADED_SAFE; INTERRUPTED_RESUME_NOT_REPEATED');return 20
    if args.phase in {'Report','Status'}:
        ledger.report(root,state,cat);print(json.dumps(dict(phase=state['phase'],in_flight=state['in_flight'],decision=ledger.decision(state,cat))));return
    if args.phase=='RecordOperatorCase':
        ledger.require(args.receipt is not None,'LAB_RECEIPT_REQUIRED');r=ledger.strict(args.receipt.read_bytes(),16384)
        required={'schema','case_id','status','package_sha256','machine_uuid_sha256','session','staff_reference','checks','evidence_files'}
        ledger.require(set(r)==required and r['schema']=='cd.lab.operator-receipt.v1','LAB_RECEIPT_SCHEMA')
        ledger.require(r['package_sha256']==args.sha and r['machine_uuid_sha256']==binding['machine'] and r['session']==binding['session'],'LAB_RECEIPT_BINDING')
        row=next(c for c in cat['cases'] if c['id']==r['case_id'])
        ledger.require(row['execution']!='AUTOMATED' and r['status'] in ledger.STATUSES,'LAB_MANUAL_OVERRIDE_DENIED')
        ledger.require(re.fullmatch(r'[A-Za-z0-9_.:-]{3,80}',r['staff_reference']) and r['checks'] and len(r['checks'])<=32 and all(re.fullmatch(r'[A-Z_]{1,60}',k) and type(v) is bool for k,v in r['checks'].items()),'LAB_RECEIPT_CHECKS')
        ledger.require(set(r['checks'])=={'PRECONDITIONS_MET','EXPECTED_RESULTS_MET','FAIL_CONDITIONS_ABSENT','EVIDENCE_COMPLETE','RECOVERY_VERIFIED','ALL_VARIANTS_COMPLETE'},'LAB_REQUIRED_RECEIPT_CHECKS')
        ledger.require(r['status']!='PASS' or all(r['checks'].values()),'LAB_RECEIPT_FAILED_CHECK')
        ledger.require(r['status']!='NOT APPLICABLE' or not row['mandatory'],'LAB_MANDATORY_GATE')
        files=[ledger.evidence(root,root/f) for f in r['evidence_files']]
        ledger.require(files,'LAB_SUPPORTING_EVIDENCE_REQUIRED')
        copied=save(root,f'{state["revision"]:03}-operator-{r["case_id"]}.json',r)
        ledger.record(state,r['case_id'],r['status'],files+[ledger.evidence(root,copied)],True,'OPERATOR_RECEIPT_RECORDED')
        ledger.write(root,state,cat);ledger.report(root,state,cat);return
    checkpoint_before=None
    if args.phase=='ResumeCheckpoint':
        try:
            ledger.require(args.receipt is not None,'LAB_RESTORE_RECEIPT_REQUIRED')
            checkpoint_before=recovery.verify(root,state,ledger.strict(args.receipt.read_bytes(),16384),args.preserved_state_sha,args.export_sha,binding['boot'])
        except Exception:
            # Duplicate invocation after success has no effect. Pending ambiguity latches review.
            if state['phase']=='CHECKPOINT_RESTORE_PENDING':
                state['phase']='REVIEW_REQUIRED';state['operator_required']=True;ledger.write(root,state,cat)
            print('REVIEW_REQUIRED; DEGRADED_SAFE; RESTORE_NOT_VERIFIED');return 20
    ledger.begin(state,args.phase,args.service);ledger.write(root,state,cat)
    prefix=f'{state["revision"]:03}-{args.phase}'
    passed_cases=[];observed={};pending=None
    try:
        if args.phase.startswith('Confirm'):
            ledger.require(bool(args.checkpoint),'LAB_CHECKPOINT_REQUIRED');observed={'checkpoint_acknowledged':True}
            if args.phase=='ConfirmC2':
                save(root,'checkpoint-C2.json',dict(checkpoint=args.checkpoint,observation=wait_baseline(True)))
        elif args.phase=='PrepareCheckpointRestore':
            observed={'operator_restore_required':True,'automatic_restore':False,'preserve_current_ledger':True}
        elif args.phase=='ResumeCheckpoint':
            observed=wait_baseline(True)
            ledger.require(not recovery.live_errors(checkpoint_before,observed),'LAB_RESTORED_CHECKPOINT_UNVERIFIED')
        elif args.phase=='Install':
            guest(args,'Install');observed={'installer_exit':0} # C1 supplies independent installation evidence.
        elif args.phase in {'C1Validate','C2Validate'}:
            observed=wait_baseline(args.phase=='C2Validate')
            ledger.require(all(v['scm_finite'] for v in observed['services'].values()),'LAB_SCM_CONFIG_NOT_FINITE')
            # Authority snapshots support the cross-fault cases but cannot finish them.
            passed_cases=['BASE-01']
            if args.phase=='C1Validate':passed_cases+=['INSTALL-01']
        elif args.phase=='EnableRustCanary':guest(args,'EnableCanary');observed={'canary_configured':True}
        elif args.phase=='CleanRestart':guest(args,'CleanRestart');observed=wait_baseline(None)
        elif args.phase=='Crash':
            before=wait_baseline(None);save(root,prefix+'-before.json',before)
            guest(args,'CrashOnce');after=wait_baseline(None)
            ledger.require(after['services'][args.service]['created']!=before['services'][args.service]['created'],'LAB_REPLACEMENT_NOT_PROVEN')
            ledger.require(all(after['services'][n]['created']==before['services'][n]['created'] for n in ledger.SERVICES if n!=args.service),'LAB_SIBLING_DISTURBED')
            ledger.require(not probe.persistence_errors(before,after),'LAB_PERSISTENCE_FAILED')
            if args.service==ledger.SERVICES[0]:
                import psutil
                for old in before['children']:
                    ledger.require(not psutil.pid_exists(old['pid']) or psutil.Process(old['pid']).create_time()!=old['created'],'LAB_ORPHAN_CHILD')
            observed=after # This single-service test does not certify full SCM storm/catalog case.
        elif args.phase=='NativeHang':
            import psutil
            ledger.require(args.service==ledger.SERVICES[0],'LAB_NATIVE_AGENT_ONLY')
            before=wait_baseline(None);ledger.require(len(before['children'])==1,'LAB_EXACT_CHILD_REQUIRED')
            child=before['children'][0];process=psutil.Process(child['pid'])
            ledger.require(process.create_time()==child['created'] and process.ppid()==before['services'][args.service]['pid'],'LAB_CHILD_CHANGED')
            save(root,prefix+'-before.json',before)
            process.suspend() # psutil guards PID reuse; only the validated canary child.
            try:
                process.wait(timeout=20)
            except psutil.TimeoutExpired:
                if process.is_running():process.resume() # undo our suspension only; never kill healthy core.
                raise ValueError('LAB_HUNG_CHILD_NOT_CONTAINED')
            after=wait_baseline(None)
            ledger.require(after['services'][args.service]['created']==before['services'][args.service]['created'],'LAB_OPTIONAL_CHILD_KILLED_CORE')
            observed=after
        elif args.phase=='SCMStorm':
            import psutil
            before=wait_baseline(None);ledger.require(before['services'][args.service]['scm_finite'],'LAB_SCM_CONFIGURATION')
            save(root,prefix+'-before.json',before);events=[]
            for attempt in range(4):
                old=psutil.win_service_get(args.service).as_dict();started=time.monotonic()
                ledger.require(old['status']=='running' and old['pid']>0,'LAB_SCM_TARGET_NOT_RUNNING')
                guest(args,'CrashOnce')
                if attempt<3:
                    deadline=time.monotonic()+85;new=None
                    while time.monotonic()<deadline:
                        new=psutil.win_service_get(args.service).as_dict()
                        if new['status']=='running' and new['pid'] and new['pid']!=old['pid']:break
                        time.sleep(.5)
                    ledger.require(new is not None and new['status']=='running' and new['pid']!=old['pid'],'LAB_SCM_REPLACEMENT_TIMEOUT')
                    delay=time.monotonic()-started
                    ledger.require(delay>=(5,15,60)[attempt]-1,'LAB_SCM_RESTART_TOO_EARLY')
                    events.append(dict(attempt=attempt+1,old_pid=old['pid'],new_pid=new['pid'],delay_seconds=delay))
                else:
                    # SCM may briefly report STOP_PENDING after the process exits.
                    grace=time.monotonic()+5
                    while time.monotonic()<grace:
                        stopped=psutil.win_service_get(args.service).as_dict()
                        if stopped['status']=='stopped' and stopped['pid']==0:break
                        ledger.require(stopped['pid'] in (0,old['pid']),'LAB_SCM_TERMINAL_RESTART')
                        time.sleep(.25)
                    deadline=time.monotonic()+180
                    while time.monotonic()<deadline:
                        stopped=psutil.win_service_get(args.service).as_dict()
                        ledger.require(stopped['status']=='stopped' and stopped['pid']==0,'LAB_SCM_TERMINAL_RESTART')
                        time.sleep(2)
                    events.append(dict(attempt=4,terminal_none_observed_seconds=180))
                for sibling in ledger.SERVICES:
                    if sibling!=args.service:ledger.require(psutil.win_service_get(sibling).pid()==before['services'][sibling]['pid'],'LAB_SCM_SIBLING_CHANGED')
            if args.service==ledger.SERVICES[0]:ledger.require(not any(p.info['name']=='cyberdefender-process-sensor.exe' for p in psutil.process_iter(['name'])),'LAB_SCM_NATIVE_ORPHAN')
            observed={'service':args.service,'bounded_scm_events':events,'rollback_required':True};pending='ROLLBACK_PENDING'
        elif args.phase=='Resources':
            ledger.require(2<=args.samples<=600,'LAB_SAMPLE_BOUND');start=time.monotonic();rows=[]
            for _ in range(args.samples):
                ledger.require(time.monotonic()-start<1200,'LAB_RESOURCE_DEADLINE')
                s=probe.snapshot();ledger.require(not probe.baseline_errors(s,None),'LAB_RESOURCE_INVARIANT')
                row={k:s[k] for k in ('utc','cpu_percent','available_ram','process_count','disk_free','log_bytes','guard_bytes')}
                row['rust_count']=len(s['children']);row['services']={n:{k:v[k] for k in ('pid','rss','cpu_seconds','handles')} for n,v in s['services'].items()};rows.append(row)
                ledger.require(s['available_ram']>=1*1024**3 and s['disk_free']>=5*1024**3 and s['guard_bytes']<100*1024**2,'LAB_RESOURCE_TRIPWIRE')
                ledger.require(all(row['services'][n]['rss']-rows[0]['services'][n]['rss']<=512*1024**2 for n in ledger.SERVICES),'LAB_RSS_GROWTH')
                ledger.require(row['log_bytes']-rows[0]['log_bytes']<100*1024**2,'LAB_LOG_GROWTH')
                if len(rows)>=16:ledger.require(not all(r['cpu_percent']>80 for r in rows[-16:]),'LAB_CPU_TRIPWIRE')
                time.sleep(2)
            observed={'samples':rows,'scope':'OBSERVATION_WINDOW_ONLY'}
        elif args.phase=='FixtureTests':
            tests=['test_h1d_launch_admission.py','test_h1d_child_containment.py','test_h1d_child_environment.py','test_h1d_crash_store.py','test_h1d_watchdog.py','test_h1d_http_progress.py','test_h1d_privacy.py','test_h1d9_release_native.py','test_process_sensor_authority_foundation_v1.py','test_process_sensor_authority_runtime_integration_v1.py']
            results=[]
            with tempfile.TemporaryDirectory(prefix='fixtures-',dir=root) as td:
                copy=Path(td)/'source';shutil.copytree(ROOT,copy,ignore=shutil.ignore_patterns('__pycache__','.venv','evidence','logs','state'))
                env=os.environ.copy();env.update(PYTHONPATH=str(copy),PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8',CYBERDEFENDER_LOG_DIR=str(Path(td)/'logs'))
                for test in tests:
                    p=subprocess.run([sys.executable,'-B',str(copy/'tests'/test)],cwd=copy,env=env,capture_output=True,timeout=180)
                    # Never retain raw fixture stdout/stderr; only exit and test-run counts.
                    text=(p.stdout+p.stderr).decode(errors='replace');count=re.search(r'Ran (\d+) tests? in',text)
                    results.append(dict(test=test,exit=p.returncode,cases=int(count[1]) if count else None))
                    ledger.require(p.returncode==0,'LAB_FIXTURE_FAILURE')
            observed={'source_fixture_results':results,'installed_machine_cases_not_certified':True}
        elif args.phase=='StoreFault':
            # One service, one variant, one debit. Restore checkpoint before another variant.
            before=probe.snapshot();ledger.require(not probe.baseline_errors(before,None),'LAB_STORE_FAULT_PRECONDITION');save(root,prefix+'-before.json',before)
            scm_stop(args.service)
            directory=default_root();protected_path(directory)
            store=probe.read_store(directory,args.service);slot=directory/(args.service+f'.{store["revision"]%2}.json');protected_path(slot)
            variant=args.variant
            if variant=='delete-anchor':target=directory/(args.service+'.anchor');protected_path(target);target.unlink()
            elif variant=='delete-slot':slot.unlink()
            elif variant=='oversized':slot.write_bytes(b'x'*(32768+1))
            elif variant=='truncate':slot.write_bytes(b'{')
            elif variant=='corrupt':slot.write_bytes(b'{}')
            elif variant=='wrong-schema':slot.write_bytes(b'{"schema":"invalid"}')
            elif variant=='wrong-service':
                other=next(n for n in ledger.SERVICES if n!=args.service);other_state=probe.read_store(directory,other)
                slot.write_bytes((directory/(other+f'.{other_state["revision"]%2}.json')).read_bytes())
            scm_start(args.service);time.sleep(10)
            after=probe.snapshot();ledger.require(after['stores'][args.service]['valid'] is False,'LAB_CORRUPTION_TRUSTED')
            observed={'variant':variant,'store_rejected':True,'rollback_required':True}
            # Do not assert comprehensive tamper-case PASS from one variant or stale runtime.
            pending='ROLLBACK_PENDING'
        elif args.phase in {'PrepareReboot','PrepareSleep','PreparePowerLoss','PrepareRollback'}:
            if args.phase!='PrepareRollback':observed=probe.snapshot()
            else:observed={'rollback_target':'C0','evidence_export_required':True}
            save(root,args.phase+'-latest.json',observed)
            observed={'operator_action_required':True,'automatic_power_action':False,'evidence_flushed':True}
        elif args.phase in {'PostReboot','PostPowerLoss','PostSleep'}:
            before=ledger.strict((root/(dict(PostReboot='PrepareReboot',PostPowerLoss='PreparePowerLoss',PostSleep='PrepareSleep')[args.phase]+'-latest.json')).read_bytes())
            after=wait_baseline(True);ledger.require(not probe.persistence_errors(before,after,reboot=args.phase!='PostSleep'),'LAB_POST_POWER_PERSISTENCE')
            observed=after
            # The catalog also requires interrupted/latch reboot variants, so this
            # clean reboot observation is supporting evidence, not whole-case PASS.
            # Sleep and hard power-off additionally require operator power-event/timing evidence.
        elif args.phase=='RollbackValidate':
            import psutil
            from win32com.shell import shell,shellcon
            common=Path(shell.SHGetFolderPath(0,shellcon.CSIDL_COMMON_APPDATA,None,0));program=Path(shell.SHGetFolderPath(0,shellcon.CSIDL_PROGRAM_FILES,None,0))
            present={s.name() for s in psutil.win_service_iter()}
            ledger.require(not present.intersection(ledger.SERVICES),'LAB_ROLLBACK_SERVICE_RESIDUE')
            ledger.require(not any((common/n).exists() for n in ('CyberDefender','CyberDefenderCrashGuard')) and not (program/'CyberDefender').exists(),'LAB_ROLLBACK_FILE_RESIDUE')
            ledger.require(not any(p.info['name']=='cyberdefender-process-sensor.exe' for p in psutil.process_iter(['name'])),'LAB_ROLLBACK_CHILD_RESIDUE')
            ledger.require(not any(c.status=='LISTEN' and c.laddr.port in (8775,8785) for c in psutil.net_connections(kind='tcp')),'LAB_ROLLBACK_PORT_RESIDUE')
            observed={'c0_app_service_child_ports_absent':True,'task_registry_baseline_comparison_requires_operator':True}
        else:raise ValueError('LAB_PHASE_UNSUPPORTED')
        path=save(root,prefix+'-result.json',observed)
        for case_id in passed_cases:ledger.record(state,case_id,'PASS',[ledger.evidence(root,path)])
        if args.phase=='ResumeCheckpoint':
            ledger.complete_restore(state,dict(admission=True,receipt=True,preserved_evidence=True,checkpoint=True,live_baseline=True))
        else:ledger.finish(state,True,args.checkpoint)
        if pending:state['phase']=pending;state['operator_required']=True
    except Exception:
        path=save(root,prefix+'-failure.json',{'phase':args.phase,'status':'FAIL','code':'LAB_PHASE_UNVERIFIED_OR_FAILED','operator_review':True})
        ledger.finish(state,False)
        ledger.write(root,state,cat);ledger.report(root,state,cat)
        print('LAB_FAILED; STOP_AND_REVIEW_SANITIZED_EVIDENCE');return 20
    ledger.write(root,state,cat);ledger.report(root,state,cat)
    if args.phase=='PrepareCheckpointRestore':print(ledger.canonical(recovery.prepare(root,state)).decode())
    print(state['phase']);return 0

def scm_stop(name):
    import win32serviceutil
    win32serviceutil.StopService(name);win32serviceutil.WaitForServiceStatus(name,1,30)
def scm_start(name):
    import win32serviceutil
    win32serviceutil.StartService(name);win32serviceutil.WaitForServiceStatus(name,4,30)
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:print('LAB_BLOCKED_REQUIRES_OPERATOR_REVIEW');raise SystemExit(20)
