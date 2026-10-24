"""Isolated import/runtime gate for VM trial; uses disposable state, never SCM."""
from __future__ import annotations
import argparse
import base64
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile

MODULES = (
    'agent.windows_service', 'agent.service_lifecycle',
    'agent.service_crash_guard', 'agent.service_crash_store',
    'agent.service_watchdog', 'agent.fleet.client',
    'agent.sensors.file_activity_collector', 'agent.main',
    'control_plane.fleet_protocol', 'control_plane.xdr_compat',
)

def probe(root: Path, with_runtime=False) -> dict:
    root = root.resolve()
    if not (root / 'agent' / 'main.py').is_file():
        raise ValueError('missing agent release')
    with tempfile.TemporaryDirectory(prefix='cd-agent-vm-gate-') as dirname:
        state = Path(dirname)
        settings = {
            'CYBERDEFENDER_ROOT':str(root),
            'CYBERDEFENDER_STATE_DIR':str(state/'state'),
            'CYBERDEFENDER_LOG_DIR':str(state/'logs'),
            'CYBERDEFENDER_DATA_DB':str(state/'data.db'),
            'CYBERDEFENDER_ENDPOINT_ID':'ISOLATED_VM_GATE',
            'CYBERDEFENDER_STORAGE_KEY_B64':base64.b64encode(os.urandom(32)).decode('ascii'),
            'CYBERDEFENDER_LAB_FILE_ACTIVITY_ENABLED':'0',
            'CYBERDEFENDER_LAB_AUTO_QUARANTINE_ENABLED':'0',
        }
        os.environ.update(settings)
        for variable in ('CYBERDEFENDER_DISTRIBUTION_URL','CYBERDEFENDER_FLEET_TOKEN_FILE',
                         'CYBERDEFENDER_LAB_FILE_ACTIVITY_ROOT','CYBERDEFENDER_LAB_QUARANTINE_VAULT'):
            os.environ.pop(variable, None)
        sys.path.insert(0,str(root))
        for name in MODULES:
            module=importlib.import_module(name)
            actual=Path(module.__file__).resolve()
            if root not in actual.parents:
                raise ValueError('module resolved outside pinned release: '+name)
        result={'status':'ISOLATED_IMPORTS_PASS','module_count':len(MODULES),
                'runtime_tested':bool(with_runtime),'state_disposable':True}
        if with_runtime:
            from agent.main import build_managed_runtime
            runtime=build_managed_runtime(allow_optional_sensors=False)
            try:
                runtime.run_cycle()
                failures=int(runtime.component_failures)
                last_error=runtime.last_error
                if failures != 0 or last_error:
                    raise RuntimeError('runtime cycle critical failure')
                result['status']='ISOLATED_RUNTIME_CYCLE_PASS'
                result['component_failures']=failures
                result['events_acked']=int(runtime.events_acked)
            finally:
                runtime.close()
        return result


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument('root',type=Path)
    parser.add_argument('--runtime',action='store_true')
    args=parser.parse_args()
    try:
        result=probe(args.root,args.runtime)
        print(json.dumps(result,sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'status':'BLOCKED','reason':f'{type(exc).__name__}: {str(exc)[:140]}'},sort_keys=True))
        return 1

if __name__=='__main__':sys.exit(main())
