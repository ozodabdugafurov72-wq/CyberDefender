from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def check(cond,msg):
    if not cond: raise AssertionError(msg)
    print(f"PASS | {msg}")

def main():
    owner_html=(ROOT/'dashboard_owner/static/index.html').read_text(encoding='utf-8')
    owner_js=(ROOT/'dashboard_owner/static/owner.js').read_text(encoding='utf-8')
    admin_html=(ROOT/'dashboard_owner/static/admin/index.html').read_text(encoding='utf-8')
    admin_js=(ROOT/'dashboard_owner/static/admin/admin.js').read_text(encoding='utf-8')
    server=(ROOT/'dashboard_owner/server.py').read_text(encoding='utf-8')
    mainpy=(ROOT/'agent/main.py').read_text(encoding='utf-8')
    check('Active Applications' in owner_html,"Owner shows Active Applications")
    check('Active Applications' in admin_html,"Admin shows Active Applications")
    check('humanEvent' in owner_js and 'code:' in owner_js,"Owner humanizes event codes while preserving raw code")
    check('humanEvent' in admin_js and 'code:' in admin_js,"Admin humanizes event codes while preserving raw code")
    check('process_inventory' in server,"Owner/Admin API exposes process inventory")
    check('build_process_inventory' in mainpy,"Runtime derives inventory from authoritative Python snapshot")
    check('dashboard_direct_os_access' in server,"Dashboard no-direct-OS-access invariant remains declared")
    check('cyberdefender-shield-c.png' in owner_html and 'cyberdefender-shield-c.png' in admin_html,"Slide-derived shield-C logo is used")
    print('RESULT: PASS')

if __name__=='__main__': main()
