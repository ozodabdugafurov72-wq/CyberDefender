"use strict";
const byId=id=>document.getElementById(id);
const set=(id,value)=>{const node=byId(id);if(node)node.textContent=value??"—"};
async function loadState(){
  try{
    const response=await fetch("/api/v1/state",{credentials:"same-origin",headers:{"Accept":"application/json"}});
    if(response.status===401){location.assign("/login");return}
    if(!response.ok)throw new Error("state unavailable");
    const data=await response.json(),dist=data.distribution||{},summary=dist.summary||{};
    set("distributionStatus",dist.status||"UNAVAILABLE");set("transport",dist.transport||"PRIVATE");
    set("endpoints",summary.endpoints_total);set("online",summary.online);set("critical",summary.critical);
    set("downloads",summary.downloads_completed);set("updated","Updated "+new Date().toLocaleTimeString());
  }catch(_){set("distributionStatus","UNAVAILABLE");set("updated","Private API unavailable")}
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
