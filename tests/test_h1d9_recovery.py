"""Deterministic owned fixtures; no actual checkpoint, process, or service faults."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts/h1d9'));sys.path.insert(0,str(ROOT))
import lab_state as s
import lab_recovery as r
import lab_ticket as t
CHECKS=dict(admission=True,receipt=True,preserved_evidence=True,checkpoint=True,live_baseline=True)
class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='h1d9-recovery-fixture-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.cat=s.catalog(ROOT/'scripts/h1d9/test_catalog.json');self.binding=dict(machine='a'*64,package='b'*64,session='c'*32,boot='boot-old')
        self.state=s.fresh(self.binding,self.cat);self.state['phase']='C2_BASELINE_PASS';self.state['checkpoints']={'C2':'verified-C2'}
        (self.root/'checkpoint-C2.json').write_bytes(s.canonical(dict(checkpoint='verified-C2',observation={'fixture':True})))
        (self.root/'evidence.json').write_text('{"synthetic":true}')
        s.record(self.state,'BASE-01','PASS',[s.evidence(self.root,self.root/'evidence.json')])
    def pending(self):
        s.begin(self.state,'SCMStorm',s.SERVICES[0]);s.finish(self.state,True)
        self.assertEqual(self.state['phase'],'ROLLBACK_PENDING')
        s.begin(self.state,'PrepareCheckpointRestore');s.finish(self.state,True);s.write(self.root,self.state,self.cat);s.report(self.root,self.state,self.cat)
        self.export=r.prepare(self.root,self.state)
        self.receipt=dict(schema='cd.lab.restore-receipt.v1',session=self.binding['session'],package_sha256=self.binding['package'],machine_sha256=self.binding['machine'],checkpoint='verified-C2',nonce=self.export['nonce'],state_sha256=self.export['state_sha256'],export_sha256=self.export['export_sha256'],current_boot='boot-new',staff_reference='staff-001',restored=True,preserved_evidence=True)
    def verify(self):return r.verify(self.root,self.state,self.receipt,self.export['state_sha256'],self.export['export_sha256'],'boot-new')
    def resume(self):
        self.verify();s.begin(self.state,'ResumeCheckpoint');s.write(self.root,self.state,self.cat);s.complete_restore(self.state,CHECKS);s.write(self.root,self.state,self.cat)
    def test_normal_rollback_to_c0_does_not_certify_cases(self):
        s.begin(self.state,'PrepareRollback');s.finish(self.state,True);s.begin(self.state,'RollbackValidate');s.finish(self.state,True)
        self.assertEqual(self.state['phase'],'LAB_COMPLETE');self.assertIn('INCOMPLETE',s.decision(self.state,self.cat))
    def test_checkpoint_restoration_preserves_evidence_and_lifetime_debits(self):
        self.pending();cases=copy.deepcopy(self.state['cases']);history=copy.deepcopy(self.state['history']);self.resume()
        self.assertEqual(self.state['cases'],cases);self.assertEqual(self.state['history'][:len(history)],history)
        self.assertEqual(self.state['fault_debits'][s.SERVICES[0]],4);self.assertEqual(self.state['branch_debits'][s.SERVICES[0]],0)
        self.assertEqual(self.state['restore_count'],1);self.assertIn('INCOMPLETE',s.decision(self.state,self.cat))
        s.begin(self.state,'SCMStorm',s.SERVICES[1]);self.assertEqual(self.state['fault_debits'][s.SERVICES[1]],4)
    def test_interrupted_rollback_cannot_restart_fault(self):
        self.pending();s.begin(self.state,'ResumeCheckpoint');s.write(self.root,self.state,self.cat)
        loaded=s.load(self.root,self.cat,self.binding)
        with self.assertRaises(ValueError):s.begin(loaded,'ResumeCheckpoint')
        with self.assertRaises(ValueError):s.begin(loaded,'Crash',s.SERVICES[0])
    def test_process_replacement_keeps_pending_state(self):
        self.pending();loaded=s.load(self.root,self.cat,self.binding)
        self.assertEqual(loaded,self.state);self.assertEqual(loaded['fault_debits'][s.SERVICES[0]],4)
        self.assertEqual(self.verify(),{'fixture':True})
    def test_service_restart_does_not_authorize_resume(self):
        self.pending()
        with self.assertRaises(ValueError):s.begin(self.state,'CleanRestart',s.SERVICES[0])
        self.assertEqual(self.state['phase'],'CHECKPOINT_RESTORE_PENDING')
    def test_stop_pending_is_not_successful_rollback(self):
        s.begin(self.state,'SCMStorm',s.SERVICES[0]);s.finish(self.state,False)
        self.assertEqual(self.state['phase'],'LAB_FAILED')
        with self.assertRaises(ValueError):s.begin(self.state,'PrepareCheckpointRestore')
    def test_repeated_crashes_during_rollback_rejected(self):
        self.pending();before=copy.deepcopy(self.state)
        for _ in range(20):
            with self.assertRaises(ValueError):s.begin(self.state,'Crash',s.SERVICES[0])
        self.assertEqual(self.state,before)
    def test_stale_checkpoint_receipt_rejected(self):
        self.pending();self.receipt['checkpoint']='stale-C2'
        with self.assertRaises(ValueError):self.verify()
    def test_corrupt_checkpoint_rejected(self):
        self.pending();(self.root/'checkpoint-C2.json').write_text('{}')
        with self.assertRaises(ValueError):self.verify()
    def test_corrupt_state_rejected(self):
        self.pending();(self.root/'state.json').write_text('{}')
        with self.assertRaises(ValueError):self.verify()
        with self.assertRaises(ValueError):s.load(self.root,self.cat,self.binding)
    def test_old_state_after_snapshot_restore_rejected(self):
        previous=copy.deepcopy(self.state);self.pending();s.write(self.root,previous,self.cat)
        with self.assertRaises(ValueError):self.verify()
    def test_duplicate_resume_is_not_repeatable(self):
        self.pending();self.resume();after=copy.deepcopy(self.state)
        with self.assertRaises(ValueError):self.verify()
        with self.assertRaises(ValueError):s.begin(self.state,'ResumeCheckpoint')
        self.assertEqual(self.state,after)
    def test_reboot_requires_current_boot_receipt(self):
        self.pending();self.receipt['current_boot']='boot-old'
        with self.assertRaises(ValueError):self.verify()
        self.receipt['current_boot']='boot-new';self.assertEqual(self.verify(),{'fixture':True})
    def test_missing_verification_cannot_complete(self):
        self.pending();s.begin(self.state,'ResumeCheckpoint')
        with self.assertRaises(ValueError):s.finish(self.state,True)
        for field in CHECKS:
            checks=dict(CHECKS);checks[field]=False
            with self.assertRaises(ValueError):s.complete_restore(self.state,checks)
    def test_failed_live_verification_requires_review(self):
        self.pending();s.begin(self.state,'ResumeCheckpoint');s.finish(self.state,False)
        self.assertEqual(self.state['phase'],'REVIEW_REQUIRED');self.assertIn('FAIL',s.decision(self.state,self.cat))
    def test_missing_evidence_rejected(self):
        self.pending();(self.root/'evidence.json').unlink()
        with self.assertRaises(ValueError):self.verify()
    def test_wrong_package_rejected(self):
        self.pending();self.receipt['package_sha256']='e'*64
        with self.assertRaises(ValueError):self.verify()
    def test_untrusted_string_ack_rejected(self):
        self.pending();self.receipt['restored']='true'
        with self.assertRaises(ValueError):self.verify()
    def test_wrong_export_hash_rejected(self):
        self.pending();self.export['export_sha256']='e'*64
        with self.assertRaises(ValueError):self.verify()
    def test_resume_limit(self):
        self.state['phase']='ROLLBACK_PENDING';self.state['restore_count']=12
        with self.assertRaises(ValueError):s.begin(self.state,'PrepareCheckpointRestore')
    def test_lifetime_budget_not_reset_by_branches(self):
        self.state['fault_debits'][s.SERVICES[0]]=32
        with self.assertRaises(ValueError):s.begin(self.state,'Crash',s.SERVICES[0])
    def test_crash_ticket_at_most_once_across_process_replacement(self):
        s.begin(self.state,'Crash',s.SERVICES[0]);s.write(self.root,self.state,self.cat)
        ticket=t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0]);t.consume(self.root,self.state,ticket,'CrashOnce',s.SERVICES[0])
        loaded=s.load(self.root,self.cat,self.binding)
        with self.assertRaises(FileExistsError):t.consume(self.root,loaded,ticket,'CrashOnce',s.SERVICES[0])
        with self.assertRaises(ValueError):t.issue(self.root,loaded,'CrashOnce',s.SERVICES[0])
    def test_unaccounted_legacy_call_denied(self):
        with self.assertRaises(ValueError):t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0])
    def test_explicit_storm_permits_exactly_four_distinct_tickets(self):
        s.begin(self.state,'SCMStorm',s.SERVICES[0])
        for _ in range(4):
            ticket=t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0]);t.consume(self.root,self.state,ticket,'CrashOnce',s.SERVICES[0])
        with self.assertRaises(ValueError):t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0])
    def test_wrong_service_ticket_denied(self):
        s.begin(self.state,'Crash',s.SERVICES[0]);ticket=t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0])
        with self.assertRaises(ValueError):t.consume(self.root,self.state,ticket,'CrashOnce',s.SERVICES[1])
    def test_cloned_ticket_cannot_expand_normal_crash_quota(self):
        s.begin(self.state,'Crash',s.SERVICES[0]);ticket=t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0])
        clone=self.root/f'act-{self.state["revision"]}-1.json';clone.write_bytes(ticket.read_bytes())
        with self.assertRaises(ValueError):t.consume(self.root,self.state,clone,'CrashOnce',s.SERVICES[0])
    def test_cloned_storm_ticket_rejected_at_different_ordinal(self):
        s.begin(self.state,'SCMStorm',s.SERVICES[0]);ticket=t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0])
        t.consume(self.root,self.state,ticket,'CrashOnce',s.SERVICES[0])
        clone=self.root/f'act-{self.state["revision"]}-1.json';clone.write_bytes(ticket.read_bytes())
        with self.assertRaises(ValueError):t.consume(self.root,self.state,clone,'CrashOnce',s.SERVICES[0])
    def test_leading_zero_ticket_alias_rejected(self):
        s.begin(self.state,'Crash',s.SERVICES[0]);ticket=t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0])
        clone=self.root/f'act-0{self.state["revision"]}-0.json';clone.write_bytes(ticket.read_bytes())
        with self.assertRaises(ValueError):t.consume(self.root,self.state,clone,'CrashOnce',s.SERVICES[0])
    def test_ticket_survives_export_and_cannot_replay_after_resume(self):
        s.begin(self.state,'Crash',s.SERVICES[0]);ticket=t.issue(self.root,self.state,'CrashOnce',s.SERVICES[0]);t.consume(self.root,self.state,ticket,'CrashOnce',s.SERVICES[0]);s.finish(self.state,True)
        self.state['phase']='ROLLBACK_PENDING';s.begin(self.state,'PrepareCheckpointRestore');s.finish(self.state,True);s.write(self.root,self.state,self.cat);s.report(self.root,self.state,self.cat)
        export=r.prepare(self.root,self.state);data=s.strict((self.root/export['file']).read_bytes())
        self.assertIn(ticket.with_suffix('.used').name,data['files'])
        with self.assertRaises(ValueError):t.consume(self.root,self.state,ticket,'CrashOnce',s.SERVICES[0])
    def test_live_restored_baseline_failure_is_rejected(self):
        import lab_probe as probe
        from unittest.mock import patch
        old={'stores':{n:dict(valid=True,revision=10,cumulative_failures=2) for n in s.SERVICES}}
        current=copy.deepcopy(old);current['services']={n:dict(scm_finite=True) for n in s.SERVICES}
        with patch.object(probe,'baseline_errors',return_value=[]):
            self.assertEqual(r.live_errors(old,current),[])
            current['stores'][s.SERVICES[0]]['revision']=1
            self.assertIn('CHECKPOINT_STORE_REGRESSION',r.live_errors(old,current))
        with patch.object(probe,'baseline_errors',return_value=['STALE_RUNTIME']):
            self.assertIn('STALE_RUNTIME',r.live_errors(old,current))
    def test_authority_false_never_passes_baseline(self):
        import lab_probe as probe
        data=dict(http_ok=True,runtime_hashes_valid=True,runtime_healthy=True,python_authoritative=True,primary_locked=True,rust_non_authoritative=True,pin_valid=True,identity_material_present=True,component_failures=0,runtime_age=0,
          services={n:dict(status='running',automatic=True,identity_ok=True) for n in s.SERVICES},stores={n:dict(valid=True) for n in s.SERVICES},children=[dict(path_ok=True,bound=True,environment_ok=True)],canary_healthy=True,canary_mode=True)
        self.assertEqual(probe.baseline_errors(data,True),[])
        for field in ('python_authoritative','primary_locked','rust_non_authoritative'):
            bad=copy.deepcopy(data);bad[field]=False;self.assertIn(field.upper(),probe.baseline_errors(bad,True))
    def test_report_integrity_precedes_engine_dispatch(self):
        import ast
        tree=ast.parse((ROOT/'scripts/h1d9/lab_engine.py').read_text())
        calls={}
        for n in ast.walk(tree):
            if isinstance(n,ast.Call):calls.setdefault(ast.unparse(n.func),[]).append(n.lineno)
        self.assertLess(min(calls['ledger.verify_evidence']),min(calls['ledger.begin']))
        guest=(ROOT/'scripts/h1d9/guest.ps1').read_text()
        self.assertLess(guest.index('$metadata=Assert-H1D9Package'),guest.index('H1D9_DURABLE_ACTUATOR_TICKET_REQUIRED'))
        self.assertLess(guest.index('H1D9_DURABLE_ACTUATOR_TICKET_REQUIRED'),guest.index('$p.Kill()'))
if __name__=='__main__':unittest.main()
