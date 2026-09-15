from __future__ import annotations
import json, os, tempfile, time
from pathlib import Path
from agent.network.passive_inventory import PassiveNetworkInventory

PASS=0; FAIL=0
def check(cond,msg):
    global PASS,FAIL
    if cond: PASS+=1; print(f"PASS | {msg}")
    else: FAIL+=1; print(f"FAIL | {msg}")

class Provider:
    def collect(self):
        return {"interfaces":[],"active_networks":[{"interface":"Wi-Fi","interface_index":9,"local_ipv4":"10.0.0.2","prefix_length":24,"gateway":"10.0.0.1"}],"neighbors":[{"interface":"Wi-Fi","ip":"10.0.0.1","mac":"AA:BB:CC:DD:EE:01","state":"REACHABLE"}],"connections":[],"process_attribution":{}}

def main():
    with tempfile.TemporaryDirectory() as td:
        path=Path(td)/"network_trust.json"
        inv=PassiveNetworkInventory(provider=Provider(), trust_registry_path=path)
        a=inv.collect(); d=a["devices"][0]
        check(d["trust"]=="UNKNOWN","missing registry keeps peer UNKNOWN")
        check(a["trust_registry"]["authority"]=="NONE","trust registry grants no authority")
        check(a["trust_registry"]["auto_whitelist"] is False,"auto-whitelist remains disabled")
        path.write_text(json.dumps({"devices":{"mac:aa:bb:cc:dd:ee:01":{"status":"AUTHORIZED","label":"Lab gateway","evidence_type":"OPERATOR_APPROVED","evidence_ref":"LAB-001"}}}))
        os.utime(path,None); time.sleep(0.001)
        b=inv.collect(); d=b["devices"][0]
        check(d["trust"]=="AUTHORIZED","explicit matching rule is visible")
        check(d["trust_evidence"]["evidence_type"]=="OPERATOR_APPROVED","evidence type is retained")
        check(d["trust_evidence"]["evidence_ref"]=="LAB-001","bounded evidence reference is retained")
        check(d["trust_evidence"]["authorization"]=="NOT_GRANTED","trust evidence cannot authorize actions")
        check(b["trust_registry"]["rules_loaded"]==1,"runtime reports loaded rule count")
        path.write_text('{broken json')
        os.utime(path,None); time.sleep(0.001)
        c=inv.collect(); d=c["devices"][0]
        check(d["trust"]=="UNKNOWN","malformed current registry fails safe to UNKNOWN")
        check(c["trust_registry"]["failures"]>=1,"registry parse failure is observable")
        check(c["trust_registry"]["last_error"],"last registry error is retained")
        path.unlink()
        d2=inv.collect()["devices"][0]
        check(d2["trust"]=="UNKNOWN","deleted registry remains UNKNOWN")
        inv.close()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    raise SystemExit(0 if FAIL==0 else 1)
if __name__=='__main__': main()
