"""Bounded reconnaissance fixtures using existing event/correlation/graph contracts.

This API accepts trusted fixture assembly inputs, not live/authenticated telemetry.
No production ingress adapter or runtime wiring is installed.
"""
from collections import OrderedDict,Counter
from dataclasses import dataclass
from datetime import datetime,timezone
import copy
import hashlib
import ipaddress
import json
import math
import threading

from agent.event import SecurityEvent
from agent.bus.event_bus import EventBus
from agent.core.event_bridge import SecurityEventBridge
from agent.correlation.engine import CorrelationEngine
from agent.attack_graph import AttackGraph
from agent.risk_engine import RiskEngine
from response_control.contracts import RECOVERY,ident
from threat_registry.catalog import ThreatRegistry

def require(condition,code):
    if not condition:raise ValueError(code)
def stamp(value):
    require(type(value) in (int,float) and math.isfinite(value),'TIME');return float(value)
def key(*parts):return hashlib.sha256(json.dumps(parts,separators=(',',':')).encode()).hexdigest()

@dataclass(frozen=True)
class SensorBinding:
    tenant_id:str
    sensor_id:str
    host_id:str
    epoch:str
    started_at:float
    def validate(self):
        for value in (self.tenant_id,self.sensor_id,self.host_id,self.epoch):ident(value)
        stamp(self.started_at)

@dataclass(frozen=True)
class FlowObservation:
    """Strict metadata-only synthetic flow. No raw packets or command lines."""
    data:dict
    @classmethod
    def parse(cls,value,binding,now,window):
        fields={'event_id','timestamp','tenant_id','sensor_id','host_id','epoch','source_ip','destination_ip','source_port','destination_port','protocol','connection_state','tcp_flags','direction','trust_level'}
        require(type(value) is dict and set(value)==fields,'FLOW_SCHEMA')
        require(len(json.dumps(value,allow_nan=False))<=2048,'FLOW_SIZE');v=copy.deepcopy(value)
        for field in ('event_id','tenant_id','sensor_id','host_id','epoch'):ident(v[field])
        require(all(v[k]==getattr(binding,k) for k in ('tenant_id','sensor_id','host_id','epoch')),'BINDING_MISMATCH')
        require(v['trust_level']=='SYNTHETIC','LIVE_INPUT_DISABLED')
        t=stamp(v['timestamp']);require(max(binding.started_at,now-window)<=t<=now+2,'STALE_OR_FUTURE_FLOW')
        for field in ('source_ip','destination_ip'):v[field]=str(ipaddress.ip_address(v[field]))
        require(v['protocol'] in {'TCP','UDP','ICMP'},'PROTOCOL')
        for field in ('source_port','destination_port'):
            require(v[field] is None if v['protocol']=='ICMP' else type(v[field]) is int and 0<=v[field]<=65535,'PORT')
        require(v['connection_state'] in {'ESTABLISHED','REFUSED','TIMEOUT','SYN_SENT','UNKNOWN'},'CONNECTION_STATE')
        require(type(v['tcp_flags']) is list and len(v['tcp_flags'])<=6 and set(v['tcp_flags'])<={'SYN','ACK','RST','FIN','PSH','URG'},'TCP_FLAGS')
        require(v['protocol']=='TCP' or not v['tcp_flags'],'FLAGS_PROTOCOL')
        require(v['direction'] in {'INBOUND','OUTBOUND','LATERAL'},'DIRECTION')
        return cls(v)
    def security_event(self):
        v=self.data
        return SecurityEvent('NETWORK_FLOW','INFO',v,'SyntheticNDR','Synthetic connection observation',event_id=v['event_id'],timestamp=datetime.fromtimestamp(v['timestamp'],timezone.utc).isoformat(),tenant_id=v['tenant_id'],sensor_id=v['sensor_id'],host_id=v['host_id'],provenance={'trust_level':'SYNTHETIC'},action='OBSERVE_ONLY')

class SyntheticNDR:
    def __init__(self,binding,*,clock,context=None,max_events=256,max_entities=32,max_seen=4096,window=300):
        require(isinstance(binding,SensorBinding),'BINDING');binding.validate()
        for value,limit in ((max_events,1024),(max_entities,128),(max_seen,8192),(window,600)):
            require(type(value) is int and 1<=value<=limit,'CONFIG_BOUND')
        self.binding=binding;self.clock=clock;self.max_events=max_events;self.max_entities=max_entities;self.max_seen=max_seen;self.window=window
        require(type(context or {}) is dict and len(context or {})<=64,'CONTEXT_BOUND')
        self.context={str(ipaddress.ip_address(k)):v for k,v in (context or {}).items()}
        require(set(self.context.values())<={'APPROVED_SCANNER','KNOWN_ADMIN_SECURITY'},'CONTEXT_CLASS')
        self.registry=ThreatRegistry();self._network=self.registry.network_definitions();self.lock=threading.RLock();self._events=[];self._seen=set();self._entities=OrderedDict()
        self.last_time=stamp(clock());require(self.last_time>=binding.started_at,'CLOCK')
        self.degraded=False;self.evictions=0;self.epoch_evictions=0;self.last_detection=None;self.last_incident=None;self.last_risk=None;self._pending=None;self._epochs={binding.epoch};self._detected_at=None
        self.bus=EventBus(max_size=32,security_reserve=8);self.correlation=CorrelationEngine(window_seconds=60)
        self.graph=AttackGraph(max_nodes=128,max_edges=256,ttl_seconds=300);self.risk=RiskEngine()
        self.bus.subscribe(self._correlate)
    def _correlate(self,event):
        require(isinstance(event,SecurityEvent) and event.verify_integrity() and event.tenant_id==self.binding.tenant_id,'EVENT_ADMISSION')
        require(self._pending is not None and event.integrity==self._pending,'UNADMITTED_BUS_INPUT');self._pending=None
        require(event.event_type=='NDR_RECON' and event.value.get('mode')=='SYNTHETIC','DETECTION_ADMISSION')
        detection=SecurityEventBridge.to_detection(event)
        # Existing CorrelationEngine prioritizes entity_id but does not tenant-scope it.
        # Derive it from verified payload here; never trust a supplied entity_id.
        detection['data']['entity_id']=key(event.tenant_id,event.value['source_ip'],self.binding.epoch,'NDR_RECON')
        incident=self.correlation.ingest(detection)
        if incident is None:return
        incident['tenant_id']=event.tenant_id;incident['evidence_refs']=list(event.value['evidence_refs'])
        incident['target_ids']=[key(event.tenant_id,event.value['source_ip'])]
        source=key(event.tenant_id,event.value['source_ip'])
        accepted=self.graph.add_node(source,'IP',attributes={'tenant_id':event.tenant_id,'synthetic':True})['accepted']
        for target in event.value['affected_entities']:
            target_id=key(event.tenant_id,target)
            accepted=self.graph.add_node(target_id,'IP',attributes={'tenant_id':event.tenant_id,'synthetic':True})['accepted'] and accepted
            accepted=self.graph.add_edge(source,target_id,'CONNECTS_TO',attributes={'synthetic':True,'scan_like':True})['accepted'] and accepted
        incident_added=self.graph.ingest_incident(incident).get('accepted') is True
        if incident_added:
            accepted=self.graph.add_edge('incident:'+incident['incident_id'],source,'OBSERVED_IN')['accepted'] and accepted
        self.degraded=self.degraded or not accepted or not incident_added
        self.last_incident=copy.deepcopy(incident);self.last_risk=self.risk.assess(self.graph,[incident])
    def observe(self,value,binding):
        with self.lock:
            try:
                require(binding==self.binding,'BINDING_MISMATCH');now=stamp(self.clock())
                require(now>=self.last_time and now<self.binding.started_at+3600,'CLOCK_OR_EPOCH_EXPIRED')
                flow=FlowObservation.parse(value,self.binding,now,self.window);v=flow.data
                identity=key(v['sensor_id'],v['epoch'],v['event_id'])
                require(identity not in self._seen,'REPLAY');require(len(self._seen)<self.max_seen,'REPLAY_RETENTION_FULL')
                self.last_time=now;self._seen.add(identity)
                self._events=[r for r in self._events if r['timestamp']>=now-self.window]
                active={r['source_ip'] for r in self._events}
                self._entities=OrderedDict((k,t) for k,t in self._entities.items() if k in active)
                if v['source_ip'] not in self._entities and len(self._entities)>=self.max_entities:
                    old,_=self._entities.popitem(last=False);self._events=[r for r in self._events if r['source_ip']!=old];self.evictions+=1;self.epoch_evictions+=1
                self._entities[v['source_ip']]=now;self._entities.move_to_end(v['source_ip'])
                if len(self._events)>=self.max_events:self._events.pop(0);self.evictions+=1;self.epoch_evictions+=1
                self._events.append(v)
                group=[r for r in self._events if r['source_ip']==v['source_ip'] and r['protocol'] in {'TCP','UDP'}]
                probe=[r for r in group if r['connection_state'] in {'REFUSED','TIMEOUT','SYN_SENT'}]
                by_host={host:{r['destination_port'] for r in probe if r['destination_ip']==host} for host in {r['destination_ip'] for r in probe}}
                by_port={port:{r['destination_ip'] for r in probe if r['destination_port']==port} for port in {r['destination_port'] for r in probe}}
                vertical=any(len(ports)>=4 for ports in by_host.values());horizontal=any(len(hosts)>=4 for hosts in by_port.values())
                multi=len(by_host)>=4 and len(by_port)>=2;families=[]
                if group and len(probe)/len(group)>=.75:
                    if vertical:families+=['PORT_SCAN','VERTICAL_PORT_SCAN']
                    if horizontal:families+=['HORIZONTAL_HOST_SCAN']
                    if multi:families+=['MULTI_HOST_RECON']
                if not families:return dict(status='OBSERVED',event=flow.security_event(),detection=None,executed=False)
                span=max(r['timestamp'] for r in probe)-min(r['timestamp'] for r in probe)
                if len([r for r in probe if r['timestamp']>=now-10])>=8:families.append('BURST_RECON')
                if span>=120:families.append('LOW_AND_SLOW_RECON')
                context=self.context.get(v['source_ip'],'UNKNOWN_EXTERNAL' if ipaddress.ip_address(v['source_ip']).is_global else 'UNKNOWN_INTERNAL')
                refs=[r['event_id'] for r in group][-8:];targets=sorted(by_host)[:16]
                supported={'NET.01.PORT_SCAN'} if vertical else set()
                if horizontal or multi:supported|={'NET.05.HOST_DISCOVERY','NET.06.SUBNET_SWEEP'}
                registry_ids=[r['id'] for r in self._network if r['selector_key'] in supported and r['context'] in {'single-host' if len(by_host)==1 else 'multi-host','low-and-slow' if 'LOW_AND_SLOW_RECON' in families else 'burst' if 'BURST_RECON' in families else 'internal-source' if context!='UNKNOWN_EXTERNAL' else 'external-source'}]
                details=dict(mode='SYNTHETIC',source_ip=v['source_ip'],families=families,context=context,evidence_refs=refs,evidence_classes=['SYNTHETIC_FLOW'],evidence_complete=len(group)<=8 and len(by_host)<=16 and self.epoch_evictions==0,affected_entities=targets,statistics=dict(events=len(group),probe_count=len(probe),hosts=len(by_host),ports=len(by_port),span_seconds=span,omitted_evidence=max(0,len(group)-8)),registry_ids=registry_ids,definition_status='DEFINED',authorization='NOT_GRANTED')
                event=SecurityEvent('NDR_RECON','LOW' if context in {'APPROVED_SCANNER','KNOWN_ADMIN_SECURITY'} else 'MEDIUM',details,'SyntheticNDR','Scan-like reconnaissance behavior',event_id='ndr-'+key(self.binding.epoch,v['event_id']),confidence=.65,tenant_id=v['tenant_id'],sensor_id=v['sensor_id'],host_id=v['host_id'],provenance={'trust_level':'SYNTHETIC'},action='OBSERVE_ONLY')
                self.last_incident=None;self.last_risk=None;self._pending=event.integrity
                if not self.bus.publish(event) or self.bus.dispatch_all(max_events=32)<=0:raise RuntimeError('BUS_UNAVAILABLE')
                self.last_detection=event;self._detected_at=now
                if self.last_incident is None or self.last_risk is None:raise RuntimeError('CORRELATION_UNAVAILABLE')
                return dict(status='DEGRADED' if self.degraded or self.epoch_evictions else 'DETECTED',event=flow.security_event(),detection=event,incident=copy.deepcopy(self.last_incident),executed=False)
            except (ValueError,TypeError,KeyError,OverflowError) as exc:
                self._pending=None
                if str(exc) in {'REPLAY_RETENTION_FULL','CLOCK_OR_EPOCH_EXPIRED'}:self.degraded=True
                return dict(status='DENIED',reason='INPUT_REPLAY_OR_CONTEXT_REJECTED',executed=False,detection=None)
            except Exception:self._pending=None;self.degraded=True;return dict(status='DEGRADED',reason='ANALYSIS_UNAVAILABLE',executed=False,detection=None)
    def proposal(self,intent_id,requester):
        """A complete simulation proposal still requires normal Response admission."""
        with self.lock:
            ident(intent_id);ident(requester);now=stamp(self.clock())
            require(self.last_detection is not None and not self.degraded and self.last_detection.verify_integrity(),'NO_DETECTION')
            d=self.last_detection.value;require(d['evidence_complete'] and now>=self.last_time and 0<=now-self._detected_at<=5 and now<self.binding.started_at+3600,'PARTIAL_OR_STALE_EVIDENCE')
            # Match the existing response fixture's incident-only risk context.
            # Graph-enriched analysis remains separate in last_risk; neither grants authority.
            assessment=self.risk.assess(AttackGraph(),[self.last_incident])['assessments'][0]
            return dict(intent_id=intent_id,incident_id=self.last_incident['incident_id'],tenant_id=self.binding.tenant_id,target_id=key(self.binding.tenant_id,d['source_ip']),target_type='network',action_type='NETWORK_LIMITED',request_source='OPERATOR',requested_by=requester,evidence_refs=list(d['evidence_refs']),risk_snapshot={k:assessment[k] for k in ('risk_score','risk_level')},policy_context=dict(policy_version='1.0',duration_seconds=60,recovery=copy.deepcopy(RECOVERY)),created_at=now,expires_at=now+60,idempotency_key=intent_id,mode='SIMULATE')
    def health(self):
        return dict(status='DEGRADED' if self.degraded or self.epoch_evictions else 'HEALTHY',events=len(self._events),entities=len(self._entities),replay_entries=len(self._seen),evictions=self.evictions,epoch_evictions=self.epoch_evictions,mode='SYNTHETIC',authority='NOT_GRANTED')
    def restart(self,binding):
        """Explicit trusted fixture epoch replacement; no automatic reset on bad input."""
        with self.lock:
            binding.validate();require(binding.tenant_id==self.binding.tenant_id and binding.sensor_id==self.binding.sensor_id and binding.host_id==self.binding.host_id and binding.epoch not in self._epochs and len(self._epochs)<32 and binding.started_at>=self.last_time,'RESTART_BINDING')
            self._epochs.add(binding.epoch)
            self.binding=binding;self._events=[];self._seen=set();self._entities.clear();self.last_time=binding.started_at
            self.last_detection=None;self.last_incident=None;self.last_risk=None;self._detected_at=None;self._pending=None;self.degraded=False;self.epoch_evictions=0
