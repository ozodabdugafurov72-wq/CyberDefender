"use strict";
const byId=id=>document.getElementById(id);
const set=(id,value)=>{const node=byId(id);if(node)node.textContent=value??"—"};
const cell=(label,value)=>{const wrap=document.createElement("div"),name=document.createElement("span"),data=document.createElement("b");name.textContent=label;data.textContent=value??"—";wrap.append(name,data);return wrap};
function renderResponses(items){
  const root=byId("responseEvidence");if(!root)return;root.replaceChildren();
  if(!Array.isArray(items)||items.length===0){const empty=document.createElement("p");empty.className="muted";empty.textContent="No signed endpoint response evidence received.";root.appendChild(empty);set("responseStatus","NO VERIFIED EVIDENCE");return}
  items.slice(0,20).forEach(item=>{const row=document.createElement("article");row.className="response-row";
    const detections=Array.isArray(item.detection_types)?item.detection_types.join(", "):"UNKNOWN";
    row.append(cell("State",item.action_state),cell("Endpoint",item.endpoint_id),cell("Detection",detections),cell("Reason",item.policy_reason),cell("Risk",`${item.risk_level||"UNKNOWN"} · ${item.risk_score??"—"}`),cell("Measured response",`${Number(item.detection_to_response_ms).toFixed(3)} ms`),cell("Verification",item.verification_outcome),cell("SHA-256",item.target_sha256));root.appendChild(row)});
  set("responseStatus","VERIFIED · READ ONLY");
}
function renderFleet(items){
  const root=byId("fleetEvidence");if(!root)return;root.replaceChildren();
  if(!Array.isArray(items)||items.length===0){const empty=document.createElement("p");empty.className="muted";empty.textContent="No authenticated endpoint evidence received.";root.appendChild(empty);set("fleetEvidenceStatus","NO VERIFIED ENDPOINTS");return}
  items.slice(0,100).forEach(item=>{const row=document.createElement("article");row.className="response-row fleet-row";
    const observed=item.last_observed_at==null?"—":new Date(Number(item.last_observed_at)*1000).toLocaleString();
    const resources=item.status==="ONLINE"?`${Number(item.cpu_percent).toFixed(1)}% CPU · ${Number(item.memory_percent).toFixed(1)}% RAM`:"STALE · LIVE METRICS HIDDEN";
    row.append(cell("Endpoint",item.hostname),cell("Identity",item.endpoint_id),cell("Presence",item.status),cell("Health",item.health_state),cell("Service",item.service_state),cell("Resources",resources),cell("Runtime",item.runtime_version),cell("Last observed",observed),cell("Telemetry",item.telemetry_status));root.appendChild(row)});
  set("fleetEvidenceStatus","AUTHENTICATED · TENANT SCOPED");
}
function renderEvents(items){
  const root=byId("eventSummary");if(!root)return;root.replaceChildren();
  if(!Array.isArray(items)||items.length===0){const empty=document.createElement("p");empty.className="muted";empty.textContent="No authenticated security events received.";root.appendChild(empty);return}
  items.slice(0,64).forEach(item=>{const row=document.createElement("div");row.className="event-row";row.append(cell("Event",item.event_type),cell("Priority",item.priority),cell("Count",item.count));root.appendChild(row)});
}
async function loadState(){
  try{
    const response=await fetch("/api/v1/state",{credentials:"same-origin",headers:{"Accept":"application/json"}});
    if(response.status===401){location.assign("/login");return}
    if(!response.ok)throw new Error("state unavailable");
    const data=await response.json(),dist=data.distribution||{},summary=dist.summary||{},xdr=dist.xdr||{},security=data.security||{};
    set("distributionStatus",dist.status||"UNAVAILABLE");set("transport",dist.transport||"PRIVATE");
    set("endpoints",summary.endpoints_total);set("online",summary.online);set("offline",summary.offline);set("degraded",summary.degraded);set("critical",summary.critical);
    set("xdrStatus",xdr.status||"UNAVAILABLE");set("xdrSchema",xdr.schema&&xdr.schema_version?xdr.schema+" "+xdr.schema_version:"UNAVAILABLE");
    set("xdrSigned",xdr.signed_ingest===true?"ENFORCED":"UNAVAILABLE");set("xdrReplay",xdr.replay_protection===true?"ENFORCED":"UNAVAILABLE");
    set("xdrValidation",xdr.runtime_contract_validation===true?"ENFORCED":"UNAVAILABLE");
    set("responseTotal",summary.responses_total??0);set("responseQuarantined",summary.responses_quarantined??0);set("responseRestored",summary.responses_restored??0);
    set("responseLatency",summary.response_latency_ms_max==null?"—":`${Number(summary.response_latency_ms_max).toFixed(3)} ms`);renderResponses(dist.responses||[]);renderFleet(dist.endpoints||[]);renderEvents(dist.event_summary||[]);
    set("authGate",security.authentication||"UNAVAILABLE");set("mfaGate",security.mfa||"UNAVAILABLE");set("rbacGate",security.server_side_rbac||"UNAVAILABLE");
    set("csrfGate",security.csrf||"UNAVAILABLE");set("actionGate",security.privileged_actions||"UNAVAILABLE");
    set("trustGate",security.risk_is_authorization===false?"ENFORCED":"UNAVAILABLE");
    set("downloads",summary.downloads_completed);set("updated","Updated "+new Date().toLocaleTimeString());
  }catch(_){set("distributionStatus","UNAVAILABLE");set("responseStatus","UNAVAILABLE");set("fleetEvidenceStatus","UNAVAILABLE");set("updated","Private API unavailable")}
}
async function loadAudit(){
  const root=document.querySelector(".dashboard");if(!root||root.dataset.role!=="OWNER")return;
  const panel=byId("auditPanel");if(panel)panel.hidden=false;
  try{
    const response=await fetch("/api/v1/audit",{credentials:"same-origin",headers:{"Accept":"application/json"}});
    if(!response.ok)return;const data=await response.json(),target=byId("audit");if(!target)return;
    target.replaceChildren(...(data.events||[]).slice(0,20).map(event=>{
      const row=document.createElement("div");row.className="audit-row";
      [new Date(Number(event.occurred_at)*1000).toLocaleString(),event.actor,event.action,event.outcome].forEach(value=>{
        const cell=document.createElement("span");cell.textContent=value||"—";row.appendChild(cell);
      });return row;
    }));
  }catch(_){}
}
loadState();loadAudit();setInterval(loadState,30000);
