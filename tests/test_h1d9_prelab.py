"""Owned fixtures only. Never executes lab engine or machine actuators."""
import copy, hashlib, json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/h1d9'));sys.path.insert(0,str(ROOT))
import lab_state as s
import lab_probe as p
from agent.service_crash_store import provision,no_reparse,FileCrashStore

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='h1d9-prelab-fixture-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.cat=s.catalog(ROOT/'scripts/h1d9/test_catalog.json')
        self.binding=dict(machine='a'*64,package='b'*64,session='c'*32,boot='fixture')
        self.state=s.fresh(self.binding,self.cat)
    def c2(self):
        self.state['phase']='C2_BASELINE_PASS';self.state['checkpoints']={'C0':'c0','C1':'c1','C2':'c2'}
    def test_catalog_exact_unique_cases(self):
        self.assertEqual(len({r['id'] for r in self.cat['cases']}),26)
        self.assertEqual([r['id'] for r in self.cat['cases'] if not r['mandatory']],['POWER-02'])
    def test_unexecuted_report_never_pass(self):
        s.report(self.root,self.state,self.cat)
        self.assertTrue(s.decision(self.state,self.cat).endswith('INCOMPLETE'))
        self.assertEqual(sum(r['status']=='BLOCKED' for r in self.state['cases'].values()),26)
    def test_atomic_roundtrip(self):
        s.write(self.root,self.state,self.cat);self.assertEqual(s.load(self.root,self.cat,self.binding),self.state)
    def test_wrong_bindings(self):
        s.write(self.root,self.state,self.cat)
        for k in ('machine','package','session'):
            b=dict(self.binding);b[k]='d'*64
            with self.subTest(k=k),self.assertRaises(ValueError):s.load(self.root,self.cat,b)
    def test_reboot_preserves_session(self):
        s.write(self.root,self.state,self.cat)
        b=dict(self.binding,boot='newboot');self.assertEqual(s.load(self.root,self.cat,b),self.state)
    def test_corrupt_state(self):
        s.write(self.root,self.state,self.cat);path=self.root/'state.json'
        raw=path.read_bytes();path.write_bytes(raw.replace(b'C0_PREFLIGHT_PASS',b'LAB_COMPLETE'))
        with self.assertRaises(ValueError):s.load(self.root,self.cat,self.binding)
    def test_duplicate_nonfinite_and_oversize(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'x'*262145):
            with self.subTest(raw=raw[:32]),self.assertRaises(ValueError):s.strict(raw)
    def test_interrupted_atomic_write_preserves_previous(self):
        s.write(self.root,self.state,self.cat);old=(self.root/'state.json').read_bytes()
        self.state['revision']+=1
        with patch.object(s.os,'replace',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):s.write(self.root,self.state,self.cat)
        self.assertEqual((self.root/'state.json').read_bytes(),old)
    def test_missing_state_does_not_initialize(self):
        (self.root/'initialized').write_bytes(b'fixture')
        with self.assertRaises(FileNotFoundError):s.load(self.root,self.cat,self.binding)
    def test_checkpoint_required_before_fault(self):
        self.state['phase']='C2_BASELINE_PASS'
        with self.assertRaises(ValueError):s.begin(self.state,'Crash',s.SERVICES[0])
    def test_inflight_debit_survives_reload(self):
        self.c2();s.begin(self.state,'Crash',s.SERVICES[0]);s.write(self.root,self.state,self.cat)
        loaded=s.load(self.root,self.cat,self.binding)
        self.assertEqual(loaded['fault_debits'][s.SERVICES[0]],1)
        with self.assertRaises(ValueError):s.begin(loaded,'Crash',s.SERVICES[0])
    def test_finite_budget(self):
        self.c2()
        for _ in range(4):s.begin(self.state,'Crash',s.SERVICES[0]);s.finish(self.state,True)
        with self.assertRaises(ValueError):s.begin(self.state,'Crash',s.SERVICES[0])
    def test_storm_consumes_whole_budget(self):
        self.c2();s.begin(self.state,'SCMStorm',s.SERVICES[0])
        self.assertEqual(self.state['fault_debits'][s.SERVICES[0]],4)
    def test_interrupted_rollback_keeps_failure(self):
        self.c2();s.begin(self.state,'Crash',s.SERVICES[0]);s.begin(self.state,'PrepareRollback');s.finish(self.state,True)
        s.begin(self.state,'RollbackValidate');s.finish(self.state,True)
        self.assertTrue(s.decision(self.state,self.cat).endswith('FAIL'))
    def test_reboot_resume_transition(self):
        self.c2();s.begin(self.state,'PrepareReboot');s.finish(self.state,True)
        with self.assertRaises(ValueError):s.begin(self.state,'Crash',s.SERVICES[0])
        s.begin(self.state,'PostReboot');s.finish(self.state,True)
        self.assertEqual(self.state['phase'],'POST_REBOOT_VALIDATION')
    def test_evidence_tamper(self):
        path=self.root/'safe.json';path.write_text('{}');e=s.evidence(self.root,path)
        s.record(self.state,'AUTH-01','PASS',[e]);path.write_text('{"changed":true}')
        with self.assertRaises(ValueError):s.report(self.root,self.state,self.cat)
    def test_evidence_escape(self):
        with self.assertRaises(ValueError):s.evidence(self.root,ROOT/'requirements.txt')
    def test_failure_is_sticky(self):
        e=[dict(path='fixture',sha256='d'*64)];s.record(self.state,'AUTH-01','FAIL',e)
        with self.assertRaises(ValueError):s.record(self.state,'AUTH-01','PASS',e)
    def test_fixed_observation_codes(self):
        with self.assertRaises(ValueError):s.record(self.state,'AUTH-01','PASS',[{}],code='raw secret with spaces')
    def test_history_bound(self):
        self.c2();self.state['revision']=250
        with self.assertRaises(ValueError):s.begin(self.state,'Crash',s.SERVICES[0])
    def test_checkpoint_schema(self):
        self.state['checkpoints']={'C2':'bad\nreceipt'}
        with self.assertRaises(ValueError):s.validate(self.state,self.cat)
    def test_full_pass_requires_all_cases_and_rollback(self):
        f=self.root/'case-evidence.json';f.write_text('{}')
        for case in self.state['cases']:s.record(self.state,case,'PASS',[s.evidence(self.root,f)])
        self.assertTrue(s.decision(self.state,self.cat).endswith('INCOMPLETE'))
        self.state['phase']='LAB_COMPLETE';self.assertIn('INTEGRATION PASS',s.decision(self.state,self.cat))
        self.state['cases']['STORE-02']['status']='BLOCKED';self.assertTrue(s.decision(self.state,self.cat).endswith('INCOMPLETE'))
    def test_pass_without_evidence_rejected(self):
        self.state['phase']='LAB_COMPLETE'
        for row in self.state['cases'].values():row['status']='PASS'
        with self.assertRaises(ValueError):s.write(self.root,self.state,self.cat)
        with self.assertRaises(ValueError):s.report(self.root,self.state,self.cat)
    def test_exported_report_tamper_rejected(self):
        s.report(self.root,self.state,self.cat)
        (self.root/'LAB_REPORT.md').write_text('synthetic forged PASS')
        with self.assertRaises(ValueError):s.report(self.root,self.state,self.cat)
    def test_missing_report_receipt_rejected(self):
        s.report(self.root,self.state,self.cat);(self.root/'LAB_REPORT.sha256.json').unlink()
        with self.assertRaises(ValueError):s.report(self.root,self.state,self.cat)

class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='h1d9-probe-fixture-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);provision(self.root,path_validator=no_reparse)
    def test_readonly_authenticated_projection(self):
        before={f.name:f.read_bytes() for f in self.root.iterdir() if f.is_file()}
        row=p.read_store(self.root,s.SERVICES[0],no_reparse)
        self.assertEqual(row['revision'],0);self.assertNotIn('key',row);self.assertNotIn('session',row)
        self.assertEqual(before,{f.name:f.read_bytes() for f in self.root.iterdir() if f.is_file()})
    def test_bad_mac_rejected(self):
        target=self.root/(s.SERVICES[0]+'.0.json');target.write_bytes(target.read_bytes().replace(b'READY',b'PROBE'))
        with self.assertRaises(ValueError):p.read_store(self.root,s.SERVICES[0],no_reparse)
    def test_missing_anchor_rejected(self):
        (self.root/(s.SERVICES[0]+'.anchor')).unlink()
        with self.assertRaises(FileNotFoundError):p.read_store(self.root,s.SERVICES[0],no_reparse)
    def test_current_committed_revision(self):
        store=FileCrashStore(self.root,s.SERVICES[0],path_validator=no_reparse)
        try:
            store.write(store.load())
            self.assertEqual(p.read_store(self.root,s.SERVICES[0],no_reparse)['revision'],1)
        finally:store.close()
    def test_store_replay_rejected(self):
        path=self.root/(s.SERVICES[0]+'.0.json');first=path.read_bytes()
        store=FileCrashStore(self.root,s.SERVICES[0],path_validator=no_reparse)
        try:store.write(store.load());store.write(store.load())
        finally:store.close()
        path.write_bytes(first)
        with self.assertRaises(ValueError):p.read_store(self.root,s.SERVICES[0],no_reparse)
    def test_reboot_and_counter_regression(self):
        b=dict(boot='old',stores={n:dict(valid=True,revision=4,cumulative_failures=3,boot='old') for n in s.SERVICES});a=copy.deepcopy(b)
        self.assertIn('REBOOT_NOT_PROVEN',p.persistence_errors(b,a,True))
        a['boot']='new'
        for row in a['stores'].values():row.update(boot='new',revision=5)
        self.assertEqual(p.persistence_errors(b,a,True),[])
        a['stores'][s.SERVICES[0]]['cumulative_failures']=0
        self.assertIn('PERSISTENCE_REGRESSION',p.persistence_errors(b,a,True))
    def test_bounded_hash(self):
        f=self.root/'fixture';f.write_bytes(b'fixture');self.assertEqual(p.bounded_hash(f),hashlib.sha256(b'fixture').hexdigest())
        self.assertIsNone(p.bounded_hash(self.root/'absent'))

if __name__=='__main__':unittest.main()
