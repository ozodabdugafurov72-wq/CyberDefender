"""Deterministic synthetic NDR/registry/response-boundary tests. No network traffic."""
import ast,copy,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ndr.synthetic import SensorBinding,SyntheticNDR,FlowObservation,key
from threat_registry.catalog import ThreatRegistry
from agent.event import SecurityEvent
from response_control.simulation import FixtureContext,ResponseControlPlane
from response_control.ledger import SimulationLedger
from response_control.contracts import Principal,advisory

class NDRTests(unittest.TestCase):
    def setUp(self):
        self.now=1000.;self.binding=SensorBinding('tenant1','sensor1','collector1','epoch1',1000.)
        self.ndr=SyntheticNDR(self.binding,clock=lambda:self.now)
    def flow(self,n,**kw):
        row=dict(event_id='event'+str(n),timestamp=self.now,tenant_id='tenant1',sensor_id='sensor1',host_id='collector1',epoch='epoch1',source_ip='10.20.0.1',destination_ip='10.20.0.2',source_port=12345,destination_port=100+n,protocol='TCP',connection_state='REFUSED',tcp_flags=['SYN'],direction='LATERAL',trust_level='SYNTHETIC')
        row.update(kw);return row
    def send(self,n,**kw):return self.ndr.observe(self.flow(n,**kw),self.binding)
    def scan(self,count=4,**kw):
        result=None
        for n in range(count):result=self.send(n,**kw)
        return result
    def families(self,result):
        self.assertIn(result['status'],{'DETECTED','DEGRADED'},result);return result['detection'].value['families']
    def test_vertical_port_scan(self):
        result=self.scan();self.assertEqual(set(self.families(result)),{'PORT_SCAN','VERTICAL_PORT_SCAN'});self.assertFalse(result['executed'])
    def test_horizontal_scan(self):
        for n in range(4):result=self.send(n,destination_ip=f'10.20.1.{n+1}',destination_port=443)
        self.assertIn('HORIZONTAL_HOST_SCAN',self.families(result))
    def test_multi_host(self):
        for n in range(4):result=self.send(n,destination_ip=f'10.20.1.{n+1}')
        self.assertIn('MULTI_HOST_RECON',self.families(result))
    def test_burst(self):self.assertIn('BURST_RECON',self.families(self.scan(8)))
    def test_low_and_slow(self):
        for n in range(4):self.now=1000+n*50;result=self.send(n)
        self.assertIn('LOW_AND_SLOW_RECON',self.families(result));self.assertNotIn('BURST_RECON',self.families(result))
    def test_browsing(self):
        for n in range(12):self.assertIsNone(self.send(n,destination_ip=f'8.8.0.{n+1}',destination_port=443,connection_state='ESTABLISHED',tcp_flags=['ACK'])['detection'])
    def test_approved_scanner_observable(self):
        self.ndr=SyntheticNDR(self.binding,clock=lambda:self.now,context={'10.20.0.1':'APPROVED_SCANNER'})
        result=self.scan();self.assertTrue(self.families(result));self.assertEqual(result['detection'].severity,'LOW');self.assertEqual(len(result['detection'].value['evidence_refs']),4)
    def test_known_admin_observable(self):
        self.ndr=SyntheticNDR(self.binding,clock=lambda:self.now,context={'10.20.0.1':'KNOWN_ADMIN_SECURITY'})
        self.assertEqual(self.scan()['detection'].value['context'],'KNOWN_ADMIN_SECURITY')
    def test_unknown_internal(self):self.assertEqual(self.scan()['detection'].value['context'],'UNKNOWN_INTERNAL')
    def test_external(self):self.assertEqual(self.scan(source_ip='8.8.8.8')['detection'].value['context'],'UNKNOWN_EXTERNAL')
    def test_approved_context_cannot_be_self_asserted(self):self.assertEqual(self.send(1,approved=True)['status'],'DENIED')
    def test_duplicate(self):
        self.send(1);before=self.ndr.health();self.assertEqual(self.send(1)['status'],'DENIED');self.assertEqual(self.ndr.health(),before)
    def test_replay_after_window(self):
        self.send(1);self.now+=301;self.assertEqual(self.send(1)['status'],'DENIED')
    def test_out_of_order(self):
        self.now+=2
        for n in range(4):result=self.send(n,timestamp=1002 if n%2 else 1000)
        self.assertIn('PORT_SCAN',self.families(result))
    def test_future_drift(self):self.assertEqual(self.send(1,timestamp=self.now+3)['status'],'DENIED')
    def test_backward_clock(self):
        self.send(1);self.now-=1;self.assertEqual(self.send(2)['status'],'DENIED')
    def test_stale_flow(self):self.assertEqual(self.send(1,timestamp=600)['status'],'DENIED')
    def test_sensor_restart(self):
        self.scan();new=SensorBinding('tenant1','sensor1','collector1','epoch2',self.now);self.ndr.restart(new)
        self.assertEqual(self.ndr.health()['events'],0);self.assertEqual(self.send(0)['status'],'DENIED')
        self.binding=new;self.assertEqual(self.send(0,epoch='epoch2')['status'],'OBSERVED')
    def test_restart_old_epoch_denied(self):
        new=SensorBinding('tenant1','sensor1','collector1','epoch2',self.now);self.ndr.restart(new)
        with self.assertRaises(ValueError):self.ndr.restart(self.binding)
    def test_empty(self):self.assertEqual(self.ndr.observe({},self.binding)['status'],'DENIED')
    def test_cross_tenant(self):self.assertEqual(self.send(1,tenant_id='tenant2')['status'],'DENIED')
    def test_unregistered_sensor(self):self.assertEqual(self.send(1,sensor_id='sensor2')['status'],'DENIED')
    def test_wrong_collector(self):self.assertEqual(self.send(1,host_id='collector2')['status'],'DENIED')
    def test_no_live_ingress(self):self.assertEqual(self.send(1,trust_level='AUTHENTICATED')['status'],'DENIED')
    def test_invalid_ip(self):self.assertEqual(self.send(1,destination_ip='not-ip')['status'],'DENIED')
    def test_invalid_port(self):self.assertEqual(self.send(1,destination_port=True)['status'],'DENIED')
    def test_nan(self):self.assertEqual(self.send(1,timestamp=float('nan'))['status'],'DENIED')
    def test_ipv6(self):self.assertIn('PORT_SCAN',self.families(self.scan(source_ip='fd00::1',destination_ip='fd00::2')))
    def test_udp(self):self.assertIn('PORT_SCAN',self.families(self.scan(protocol='UDP',tcp_flags=[])))
    def test_icmp_metadata_no_invented_ports(self):self.assertIsNone(self.send(1,protocol='ICMP',source_port=None,destination_port=None,tcp_flags=[])['detection'])
    def test_unknown_outcomes_not_probe_evidence(self):self.assertIsNone(self.scan(connection_state='UNKNOWN')['detection'])
    def test_single_incident_for_many_targets(self):
        ids=[]
        for n in range(12):
            result=self.send(n,destination_ip=f'10.30.0.{n+1}',destination_port=22)
            if result['detection']:ids.append(result['incident']['incident_id'])
        self.assertTrue(ids);self.assertEqual(len(set(ids)),1)
    def test_same_target_many_ports_one_incident(self):
        ids=[self.send(n).get('incident',{}).get('incident_id') for n in range(8)]
        self.assertEqual(len({i for i in ids if i}),1)
    def test_attack_graph_edges(self):
        self.scan();graph=self.ndr.graph.snapshot();self.assertTrue(any(e['edge_type']=='CONNECTS_TO' for e in graph['edges']))
        self.assertTrue(any(e['edge_type']=='OBSERVED_IN' for e in graph['edges']))
        self.assertTrue(all(n['node_type'] in self.ndr.graph.NODE_TYPES for n in graph['nodes']))
    def test_tenant_scoped_graph_identity(self):self.assertNotEqual(key('tenant1','10.0.0.1'),key('tenant2','10.0.0.1'))
    def test_high_cardinality_bounded(self):
        self.ndr=SyntheticNDR(self.binding,clock=lambda:self.now,max_events=8,max_entities=4,max_seen=256)
        for n in range(200):self.send(n,source_ip=f'10.1.{n//254}.{n%254+1}')
        health=self.ndr.health();self.assertLessEqual(health['events'],8);self.assertLessEqual(health['entities'],4);self.assertLessEqual(health['replay_entries'],256);self.assertGreater(health['evictions'],0)
    def test_memory_high_cardinality(self):
        import tracemalloc
        self.ndr=SyntheticNDR(self.binding,clock=lambda:self.now,max_events=8,max_entities=4,max_seen=512)
        tracemalloc.start()
        try:
            for n in range(500):self.send(n,source_ip=f'10.2.{n//254}.{n%254+1}')
            _,peak=tracemalloc.get_traced_memory();self.assertLess(peak,4*1024*1024)
            print('SYNTHETIC_HIGH_CARDINALITY_PEAK_BYTES',peak)
        finally:tracemalloc.stop()
    def test_replay_capacity_fails_closed(self):
        self.ndr=SyntheticNDR(self.binding,clock=lambda:self.now,max_seen=4)
        self.scan();self.assertEqual(self.send(5)['status'],'DENIED');self.assertEqual(self.ndr.health()['replay_entries'],4)
    def test_window_cleanup(self):
        self.send(1);self.now+=301;self.send(2);self.assertEqual(self.ndr.health()['events'],1)
    def test_bound_settings(self):
        with self.assertRaises(ValueError):SyntheticNDR(self.binding,clock=lambda:self.now,max_events=1025)
    def test_epoch_expiry(self):self.now+=3600;self.assertEqual(self.send(1)['status'],'DENIED')
    def test_proposal_is_not_authority(self):
        self.scan();proposal=self.ndr.proposal('intent1','operator1');self.assertEqual(proposal['mode'],'SIMULATE');self.assertNotIn('ticket',proposal);self.assertNotIn('authorization',proposal)
    def test_partial_evidence_prevents_proposal(self):
        self.scan(9)
        with self.assertRaises(ValueError):self.ndr.proposal('intent1','operator1')
    def test_stale_proposal(self):
        self.scan();self.now+=6
        with self.assertRaises(ValueError):self.ndr.proposal('intent1','operator1')
    def test_normal_flow_cannot_refresh_old_detection(self):
        self.scan();self.now+=6;self.send(20,source_ip='10.1.1.1',connection_state='ESTABLISHED')
        with self.assertRaises(ValueError):self.ndr.proposal('intent1','operator1')
    def test_backward_clock_proposal(self):
        self.scan();self.now-=1
        with self.assertRaises(ValueError):self.ndr.proposal('intent1','operator1')
    def test_tampered_detection_proposal(self):
        self.scan();self.ndr.last_detection.value['evidence_refs']=['unknown']
        with self.assertRaises(ValueError):self.ndr.proposal('intent1','operator1')
    def test_capacity_health_and_explicit_recovery(self):
        self.ndr=SyntheticNDR(self.binding,clock=lambda:self.now,max_seen=4);self.scan();self.send(5)
        self.assertEqual(self.ndr.health()['status'],'DEGRADED')
        self.ndr.restart(SensorBinding('tenant1','sensor1','collector1','epoch2',self.now));self.assertEqual(self.ndr.health()['status'],'HEALTHY')
    def test_forged_bus_detection(self):
        forged=SecurityEvent('NDR_RECON','CRITICAL',dict(mode='SYNTHETIC',source_ip='10.0.0.1'), 'SyntheticNDR','fake',tenant_id='tenant1')
        self.ndr.bus.publish(forged);self.ndr.bus.dispatch_all(max_events=32);self.assertIsNone(self.ndr.last_incident)
    def test_correlator_failure_not_stale_success(self):
        self.scan();self.ndr.correlation.ingest=Mock(return_value=None);result=self.send(5);self.assertEqual(result['status'],'DEGRADED');self.assertIsNone(result['detection'])
    def test_no_host_actuator_imports(self):
        tree=ast.parse((Path(__file__).resolve().parents[1]/'ndr/synthetic.py').read_text())
        modules={a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names}
        self.assertFalse(modules&{'subprocess','socket','ctypes','winreg','win32service','psutil'})
        self.assertFalse(hasattr(self.ndr,'execute'));self.assertFalse(hasattr(self.ndr,'authorize'))
    def test_ai_cannot_gain_authority_from_detection(self):
        self.scan();advice=advisory(dict(analysis='scan-like',hypothesis='recon',confidence=1,attack_chain='recon',recommended_action='NETWORK_LIMITED',evidence_refs=['event0'],explanation='synthetic'))
        self.assertEqual(advice['authorization'],'NOT_GRANTED')
    def test_actual_response_boundary(self):
        events=[]
        for n in range(4):result=self.send(n);events.append(result['event'])
        proposal=self.ndr.proposal('intent1','operator1');target=dict(tenant_id='tenant1',target_id=proposal['target_id'],target_type='network',instance_id='synthetic-instance',protection_classes=[],classification_complete=True,asset_criticality=1,state='UNCHANGED')
        context=FixtureContext(events,{('tenant1',proposal['incident_id']):self.ndr.last_incident},{('tenant1',proposal['target_id']):target})
        with tempfile.TemporaryDirectory(prefix='ndr-response-') as td:
            ledger=SimulationLedger(Path(td)/'journal.sqlite',b'k'*32,create=True)
            try:
                engine=ResponseControlPlane(ledger,context,clock=lambda:self.now);principal=Principal('tenant1','operator1','OPERATOR',True)
                with patch.object(engine.gateway,'execute_dry_run',wraps=engine.gateway.execute_dry_run) as gateway:
                    denied=engine.simulate({},proposal,principal);self.assertNotEqual(denied['state'],'VERIFIED');gateway.assert_not_called()
                ai=Principal('tenant1','operator1','AI',True);self.assertNotEqual(engine.prepare(proposal,ai)['state'],'AUTHORIZED_FOR_SIMULATION')
                authorized=engine.prepare(proposal,principal);self.assertEqual(authorized['state'],'AUTHORIZED_FOR_SIMULATION',authorized)
                result=engine.simulate(authorized['ticket'],proposal,principal);self.assertEqual(result['state'],'VERIFIED');self.assertFalse(result['real_world_effect'])
            finally:ledger.close()

class RegistryTests(unittest.TestCase):
    def test_identities(self):
        registry=ThreatRegistry();self.assertEqual(len(registry._rows),2000);self.assertEqual(len(registry.network_definitions()),100)
    def test_definitions_stay_defined(self):self.assertTrue(all(r['lifecycle_status']=='DEFINED' for r in ThreatRegistry().mapping()))
    def test_no_fingerprinting_claim(self):self.assertTrue(all(r['synthetic_relation']=='NOT_IMPLEMENTED' for r in ThreatRegistry().mapping() if 'FINGERPRINTING' in r['selector']))
    def test_defensive_copy(self):
        registry=ThreatRegistry();r=registry.definition('CD-ATK-0001');r['implementation_status']='LAB_VERIFIED';self.assertEqual(registry.definition('CD-ATK-0001')['implementation_status'],'DEFINED')
    def test_missing(self):
        with self.assertRaises(ValueError):ThreatRegistry(Path('missing-registry.jsonl'))
    def test_corruption(self):
        with tempfile.TemporaryDirectory(prefix='registry-negative-') as td:
            p=Path(td)/'bad.jsonl';p.write_bytes(b'{}')
            with self.assertRaises(ValueError):ThreatRegistry(p)
    def test_bad_id(self):
        with self.assertRaises(ValueError):ThreatRegistry().definition('CD-ATK-2001')

if __name__=='__main__':unittest.main(verbosity=2)
