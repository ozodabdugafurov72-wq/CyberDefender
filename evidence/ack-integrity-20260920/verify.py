"""Source-only regression with existing owned-child guard; no lab actuators."""
import ast, hashlib, json, os, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / ('verification-' + str(time.time_ns()))
OUT.mkdir(exist_ok=True)
env = os.environ.copy()
env.update(PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8',
           CYBERDEFENDER_LOG_DIR=str(OUT/'fixture-logs'))
env['PSModulePath'] = str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/Modules')
tests = [r['test'] for r in json.loads((ROOT/'evidence/closure-catalog-ndr/verification-20260914T123159Z/regression.json').read_text())]
extras = ['tests/test_runtime_consumer_admission_ack.py','test_p08_bridge_correlation.py',
 'test_p11_17_a_crash_ack_atomicity.py','test_p11_17_failure_resilience.py',
 'test_p11_19_failure_recovery.py','test_p11_19_adversarial.py','test_p10_duplicate_replay.py',
 'test_main_full_runtime_traversal_v1.py','test_main_risk_engine_integration_v1.py']
guarded = {'tests/test_h1d_child_containment.py','tests/test_h1d_child_environment.py',
 'tests/test_h1d_launch_admission.py','tests/test_h1d_native_live.py',
 'tests/test_h1d9_release_native.py','tests/test_native_process_supervisor_contract_v1.py'}
sources = ['agent/main.py','agent/correlation/adapter.py','agent/correlation/engine.py','test_main_correlation_ownership_v1_5.py',extras[0]]
for name in sources:
    compile((ROOT/name).read_bytes(),name,'exec')
(OUT/'compile.json').write_text(json.dumps({'pass':len(sources),'fail':0}))
results=[]
for name in extras+tests:
    cmd=[sys.executable,'-B',str(ROOT/name)]
    if name in guarded:
        cmd=[sys.executable,'-B',str(ROOT/'tests/run_owned_lifecycle.py'),name,str(OUT/Path(name).stem)]
    cwd=ROOT
    if name in extras and not name.startswith('tests/'):
        cwd=OUT/(Path(name).stem+'-workspace');cwd.mkdir(exist_ok=True)
    started=time.monotonic()
    p=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,text=True)
    (OUT/(Path(name).stem+'.log')).write_text(p.stdout+p.stderr,encoding='utf-8')
    results.append(dict(test=name,command=cmd,cwd=str(cwd),exit=p.returncode,
                        status='PASS' if p.returncode==0 else 'FAIL',seconds=round(time.monotonic()-started,2)))
    (OUT/'results.json').write_text(json.dumps(results,indent=2))
    print(name,p.returncode,flush=True)
(OUT/'summary.json').write_text(json.dumps({'pass':sum(x['exit']==0 for x in results),
 'fail':sum(x['exit']!=0 for x in results),'skipped':0,'established_scripts':len(tests),'additional_scripts':len(extras)},indent=2))
sys.exit(any(x['exit']!=0 for x in results))
