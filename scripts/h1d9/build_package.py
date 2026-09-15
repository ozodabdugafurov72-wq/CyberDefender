"""Allowlisted source snapshot; no installer, service, or production state access."""
import hashlib
import json
from pathlib import Path
import zipfile
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'evidence/h1d9-prelab'
HOST = '195d1d40f7e40d281fe8d46d33f4c4e13d44490ffa58edc6a1e2d634375b6732'
ALLOWLIST = ROOT / 'scripts/h1d9/package-files.json'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def require(condition, code):
    if not condition:
        raise ValueError(code)

def selected(root=ROOT, allowlist=ALLOWLIST):
    names=json.loads(allowlist.read_text(encoding='utf-8'))
    require(type(names) is list and 1 <= len(names) <= 2000, 'ALLOWLIST_INVALID')
    require(len({n.casefold() for n in names}) == len(names), 'ALLOWLIST_DUPLICATE')
    for name in names:
        require(type(name) is str and '\\' not in name and ':' not in name and
                not name.startswith('/') and all(p not in ('','..','.') for p in name.split('/')), 'ALLOWLIST_PATH')
        parts=name.split('/')
        require(parts[0] not in ('evidence','state','logs','quarantine','.venv') and
                not any(p in ('__pycache__','.git','.venv') or p.startswith('_backup') for p in parts), 'RUNTIME_EXCLUDED')
        require('target' not in parts or name == 'native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe', 'BUILD_TREE_EXCLUDED')
        require(Path(name).suffix.lower() not in ('.key','.pem','.pfx','.db','.b64','.log','.cdtest'), 'SENSITIVE_EXTENSION')
    return [root/name for name in sorted(names)]

def write_archive(path, entries):
    # Fixed metadata and ordering make identical reviewed inputs byte reproducible.
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name,data in sorted(entries.items()):
            info=zipfile.ZipInfo(name, date_time=(1980,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED; info.create_system=0; info.external_attr=0x20
            z.writestr(info,data,compresslevel=9)

def main():
    OUT.mkdir(exist_ok=True, parents=True)
    inventory = json.loads((ROOT / 'evidence/h1d-implementation/source-inventory.json').read_text())
    backup = Path(inventory['backup'])
    original = json.loads((backup / 'manifest.json').read_text(encoding='utf-8-sig'))
    for row in original:
        require(digest((backup / row['path']).read_bytes()) == row['sha256'].lower(), 'BACKUP_MISMATCH')
    for name, expected in inventory['source_sha256'].items():
        require(digest((ROOT / name).read_bytes()) == expected, 'H1D_SOURCE_DRIFT')
    manifest = dict(schema='cd.h1d9.package.v1', readiness='PREPARATION_ONLY',
                    excluded_host_uuid_sha256=HOST, files=[],
                    rust=dict(version='0.5.1',profile='release',command='cargo build --offline --release',
                              toolchain=subprocess.check_output(['rustc','--version'],text=True).strip(),
                              cargo=subprocess.check_output(['cargo','--version'],text=True).strip()),
                    h1d_verified_files=len(inventory['source_sha256']), backup_verified_files=len(original))
    manifest['lab_profile']='UNIVERSITY_PRELAB_V1'
    entries={}
    for p in selected():
        require(p.is_file() and not p.is_symlink(), 'SOURCE_MISSING_OR_LINK')
        for parent in (p, *p.parents):
            if parent == ROOT.parent:
                break
            require(not parent.is_junction() and not parent.is_symlink(), 'SOURCE_REPARSE')
        relative = p.relative_to(ROOT).as_posix()
        data = p.read_bytes()
        if relative in inventory['source_sha256']:
            require(digest(data)==inventory['source_sha256'][relative],'H1D_SNAPSHOT_DRIFT')
        manifest['files'].append(dict(path=relative, bytes=len(data), sha256=digest(data)))
        entries['payload/'+relative]=data
    package_id='H1D9-'+digest(json.dumps(manifest,sort_keys=True).encode())[:24]
    manifest['package_id']=package_id
    entries['manifest.json']=json.dumps(manifest,indent=2).encode()
    entries['guest-authorization.example.json']=json.dumps(dict(schema='cd.h1d9.authorization.v2',
        guest_uuid_sha256='',package_id=package_id,package_sha256='',disposable=False,
        isolated_network=False,rollback_verified=False,operator_acknowledged=False,dependencies_ready=False,
        clean_checkpoint='',lab_nonce='',expires_utc='',environment_type='VM',staff_authorized=False,
        staff_reference='',no_unrelated_data=False,recovery_image_verified=False,warnings_reviewed=False),indent=2).encode()
    package=OUT/(package_id+'.zip')
    if package.exists():
        # Never truncate historical archives, even on a deterministic repeat build.
        import tempfile,os
        fd,temporary=tempfile.mkstemp(prefix='repeat-',suffix='.zip',dir=OUT);os.close(fd)
        try:
            write_archive(Path(temporary),entries)
            require(Path(temporary).read_bytes()==package.read_bytes(),'EXISTING_PACKAGE_DIFFERS')
        finally:Path(temporary).unlink()
    else:write_archive(package,entries)
    with zipfile.ZipFile(package) as z:
        require(z.testzip() is None,'ARCHIVE_CRC')
        for row in manifest['files']:
            require(digest(z.read('payload/' + row['path'])) == row['sha256'],'ARCHIVE_HASH')
    result = dict(package=str(package), sha256=digest(package.read_bytes()),
                  bytes=package.stat().st_size, files=len(manifest['files']),
                  backup_verified=len(original), h1d_source_verified=len(inventory['source_sha256']),
                  package_id=package_id, offline_dependencies_included=False)
    (OUT / 'package-result.json').write_text(json.dumps(result, indent=2))
    (OUT / 'package-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
