"""Pinned Catalog v1.1 definitions; definition presence is never capability evidence."""
import copy
import hashlib
import json
from pathlib import Path

REGISTRY_SHA256='e490b548af65e6b07f0770e7ac46838238dfaad45b226d90a737c6c1943cf71a'

class ThreatRegistry:
    def __init__(self,path=None):
        path=Path(path) if path is not None else Path(__file__).with_name('catalog_v1_1.jsonl')
        if not path.is_file() or path.is_symlink() or path.stat().st_size>8*1024*1024:raise ValueError('REGISTRY_PATH_OR_BOUND')
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=REGISTRY_SHA256:raise ValueError('REGISTRY_PIN_MISMATCH')
        rows=[json.loads(line) for line in raw.splitlines() if line.strip()]
        if [r['id'] for r in rows]!=[f'CD-ATK-{i:04d}' for i in range(1,2001)]:raise ValueError('REGISTRY_IDENTITIES')
        for row in rows:
            if row['implementation_status']!='DEFINED' or row['final_risk']!='DYNAMIC_ONLY' or row['response_default']!='OBSERVE' or row['authorization_chain']!=['PolicyEngine','SafetyCore','IndependentVerifier']:
                raise ValueError('REGISTRY_AUTHORITY_OR_STATUS')
        # Store serialized definitions rather than expose mutable nested shared objects.
        self._rows=tuple(json.dumps(r,sort_keys=True) for r in rows)
    def definition(self,identity):
        if not isinstance(identity,str) or len(identity)!=11 or not identity.startswith('CD-ATK-') or not identity[7:].isdigit():raise ValueError('REGISTRY_ID')
        index=int(identity[7:])-1
        if not 0<=index<2000:raise ValueError('REGISTRY_ID')
        return json.loads(self._rows[index])
    def network_definitions(self):
        return tuple(self.definition(f'CD-ATK-{i:04d}') for i in range(1,101))
    def mapping(self):
        supported={'NET.01.PORT_SCAN','NET.05.HOST_DISCOVERY','NET.06.SUBNET_SWEEP'}
        return tuple(dict(id=r['id'],detector_family=r['detector_family'],selector=r['selector_key'],context=r['context'],required_telemetry=r['required_telemetry'],evidence_requirements=r['family_evidence_focus'],minimum_evidence_classes=r['minimum_evidence_classes'],false_positive_context=r['known_benign_contexts'],lifecycle_status='DEFINED',synthetic_relation='SCAN_LIKE_ONLY' if r['selector_key'] in supported else 'NOT_IMPLEMENTED') for r in self.network_definitions())
