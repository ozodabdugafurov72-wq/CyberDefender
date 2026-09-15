"""Source-only packaging/admission tests. Guest mutation script is never run."""
import hashlib, importlib.util, json, os, re, subprocess, tempfile, unittest, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('h1d9_builder',ROOT/'scripts/h1d9/build_package.py')
builder=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(builder)
REQUIRED=['scripts/install_machine.ps1','scripts/service_recovery_policy.ps1','scripts/h1d9/guest.ps1',
 'scripts/h1d9/admission.ps1','agent/windows_service.py','control_plane/windows_service.py',
 'dashboard_owner/windows_service.py','requirements.txt','config/process_sensor_runtime.example.json',
 'native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe']

def fixtures(root):
    cases=[]
    for name in ('valid','wrong_sha','wrong_schema','wrong_binding','missing_required','duplicate_path','duplicate_zip',
                 'traversal','payload_tamper','extra_file','local_manifest','archived_tamper'):
        folder=root/name; expanded=folder/'expanded'; expanded.mkdir(parents=True)
        data={n:b'fixture harmless non-executable content\n' for n in REQUIRED}
        if name=='missing_required': data.pop(REQUIRED[0])
        rows=[dict(path=n,sha256=builder.digest(b),bytes=len(b)) for n,b in sorted(data.items())]
        metadata=dict(schema='cd.h1d9.package.v1',readiness='PREPARATION_ONLY',package_id='H1D9-'+'a'*24,
                      excluded_host_uuid_sha256=builder.HOST,files=rows)
        if name=='wrong_schema': metadata['schema']='wrong'
        if name=='wrong_binding': metadata['excluded_host_uuid_sha256']='d'*64
        if name=='duplicate_path': rows.append(dict(rows[0]))
        if name=='traversal': rows[0]['path']='../escape.py'
        entries={'manifest.json':json.dumps(metadata).encode(),'guest-authorization.example.json':b'{}'}
        for n,b in data.items(): entries['payload/'+n]=b
        for n,b in entries.items():
            p=expanded/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        if name=='archived_tamper': entries['payload/'+REQUIRED[0]]=b'X'*len(data[REQUIRED[0]])
        archive=folder/'package.zip';builder.write_archive(archive,entries)
        if name=='duplicate_zip':
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with zipfile.ZipFile(archive,'a') as z:z.writestr('manifest.json',entries['manifest.json'])
        if name=='payload_tamper': (expanded/'payload'/REQUIRED[0]).write_bytes(b'bad')
        if name=='extra_file': (expanded/'payload/extra.py').write_bytes(b'extra')
        if name=='local_manifest': (expanded/'manifest.json').write_bytes(b'{}')
        expected={'valid':'PASS','wrong_sha':'ARCHIVE_SHA_MISMATCH','wrong_schema':'SCHEMA_OR_BINDING_INVALID',
          'wrong_binding':'SCHEMA_OR_BINDING_INVALID','missing_required':'REQUIRED_FILE_MISSING',
          'duplicate_path':'PATH_OR_ENTRY_INVALID','duplicate_zip':'DUPLICATE_ARCHIVE_ENTRY','traversal':'PATH_OR_ENTRY_INVALID',
          'payload_tamper':'PAYLOAD_HASH_MISMATCH','extra_file':'UNMANIFESTED_FILES','local_manifest':'MANIFEST_ARCHIVE_MISMATCH',
          'archived_tamper':'ARCHIVED_PAYLOAD_MISMATCH'}[name]
        cases.append(dict(name=name,package_id=metadata['package_id'],expected=expected,
                          sha256='0'*64 if name=='wrong_sha' else builder.digest(archive.read_bytes())))
    (root/'cases.json').write_text(json.dumps(cases))

class PreparationTests(unittest.TestCase):
    def test_deterministic_archive(self):
        with tempfile.TemporaryDirectory() as td:
            a=Path(td)/'a.zip';b=Path(td)/'b.zip'
            builder.write_archive(a,{'b':b'2','a':b'1'});builder.write_archive(b,{'a':b'1','b':b'2'})
            self.assertEqual(a.read_bytes(),b.read_bytes())

    def test_runtime_and_path_inclusion_rejected(self):
        for n in ['../escape.py','state/sensitive.py','.venv/data.py','agent/__pycache__/x.py',
                  'native/process_sensor_v0_5_1/target/debug/sensor.exe','config/key.pem','logs/debug.py','C:/bad.py']:
            with self.subTest(path=n), tempfile.TemporaryDirectory() as td:
                p=Path(td)/'list.json';p.write_text(json.dumps([n]))
                with self.assertRaises(ValueError): builder.selected(Path(td),p)

    def test_duplicate_allowlist_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'list.json';p.write_text('["agent/x.py","AGENT/X.py"]')
            with self.assertRaises(ValueError): builder.selected(Path(td),p)

    def test_reviewed_payload_only(self):
        paths=builder.selected();names={p.relative_to(ROOT).as_posix() for p in paths}
        self.assertTrue(set(REQUIRED)<=names)
        self.assertEqual([n for n in names if n.endswith('.exe')],[REQUIRED[-1]])
        self.assertNotIn('config/process_sensor_runtime.json',names)
        self.assertTrue(all(p.is_file() for p in paths))

    def test_entrypoint_gates_precede_dispatch(self):
        text=(ROOT/'scripts/h1d9/guest.ps1').read_text()
        gate=text.index('$metadata=Assert-H1D9Package')
        for action in ['Stop-Service','Start-Service','New-Item','Set-Content','$p.Kill()',"& (Join-Path $source 'scripts/install_machine.ps1')"]:
            self.assertGreater(text.index(action),gate)
        self.assertLess(text.index('H1D9_PRODUCTION_HOST_DENIED'),text.index('. (Join-Path'))
        self.assertNotRegex(text,r'(?i)skipguard|bypassguard|forcehost|bcdedit|Enable-WindowsOptionalFeature')

    def test_powershell_admission_fixtures(self):
        with tempfile.TemporaryDirectory(prefix='h1d9-admission-') as td:
            folder=Path(td);fixtures(folder)
            script=ROOT/'tests/test_h1d9_admission.ps1'; admission=ROOT/'scripts/h1d9/admission.ps1'
            # Single-quoted literal paths; never shell interpolation of source text.
            quote=lambda s:"'"+str(s).replace("'","''")+"'"
            command='& ([scriptblock]::Create([IO.File]::ReadAllText('+quote(script)+'))) -FixtureRoot '+quote(folder)+' -Admission '+quote(admission)
            # Do not mix Codex/pwsh module paths into Windows PowerShell 5.1.
            env=os.environ.copy()
            native=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0'
            env['PSModulePath']=str(native/'Modules')
            p=subprocess.run([str(native/'powershell.exe'),'-NoProfile','-NonInteractive','-Command',command],env=env,capture_output=True,text=True,timeout=120)
            print(p.stdout,end='')
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            self.assertRegex(p.stdout,r'RESULT passed=44 failed=0')

if __name__=='__main__':unittest.main()
