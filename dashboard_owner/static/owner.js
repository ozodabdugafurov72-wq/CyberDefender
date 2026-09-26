(() => {
  const REFRESH_MS = 1500;
  const $ = id => document.getElementById(id);
  const text = (id, value, fallback = "—") => {
    const e = $(id); if (e) e.textContent = value === null || value === undefined || value === "" ? fallback : String(value);
  };
  const n = (v, d = 1) => { const x = Number(v); return Number.isFinite(x) ? x.toFixed(d) : "—"; };
  const clamp = v => Math.max(0, Math.min(100, Number(v) || 0));
  const esc = v => String(v ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
  const asDate = v => {
    if (v == null || v === "") return null;
    const num = Number(v);
    if (Number.isFinite(num)) {
      const d = new Date(num > 1e12 ? num : num * 1000);
      return Number.isNaN(d.getTime()) ? null : d;
    }
    const d = new Date(String(v));
    return Number.isNaN(d.getTime()) ? null : d;
  };
  const ts = v => { const d = asDate(v); return d ? d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}) : "—"; };
  const dt = v => { const d = asDate(v); return d ? d.toLocaleString() : "—"; };
  const level = e => String(e?.severity ?? e?.level ?? e?.risk_level ?? "INFO").toUpperCase();
  const humanEvent = value => {
    const raw=String(value||"EVENT").trim();
    const known={
      HIGH_MEMORY_USAGE:"High Memory Usage", LOW_AVAILABLE_MEMORY:"Low Available Memory",
      HIGH_CPU_USAGE:"High CPU Usage", CPU_PRESSURE:"CPU Pressure", MEMORY_PRESSURE:"Memory Pressure",
      HIGH_PROCESS_COUNT:"High Process Count", PROCESS_COUNT_PRESSURE:"Process Count Pressure",
      RECOVERY:"Recovery", DETECTION:"Detection", HOST_SNAPSHOT:"Host Snapshot"
    };
    if(known[raw]) return known[raw];
    return raw.replaceAll("_"," ").replace(/\b\w/g,c=>c.toUpperCase());
  };
  const statusClass = s => {
    s=String(s||"").toUpperCase();
    if (["HEALTHY","SAFE","ACTIVE","OBSERVE","ANALYZE","DRY_RUN_ONLY","NO_REAL_WORLD_EFFECT","NORMAL","SYNCED","RUST_CANARY","PYTHON_ONLY","CLOSED","VERIFIED"].includes(s)) return "good";
    if (["DEGRADED","UNKNOWN","STALE","STANDBY","GUARDED","ELEVATED"].includes(s)) return "warn";
    return "bad";
  };

  let lastState = null;
  let selectedEndpointId = null;
  let lastFleet = null;
  // ENDPOINT_FLEET_SELECTOR_PATCH_v1
  let incidentTimer = null;
  let historyMode = false;

  function render(d){
    lastState = d;
    const rt=d.runtime||{}, obs=d.observation||{}, h=d.health||{}, fresh=d.runtime_freshness||{}, sum=d.incident_summary||{}, safety=h.safety_core||d.safety||{}, policy=h.policy_engine||{}, verifier=h.independent_verifier||{}, auth=h.authorization_gate||{}, gateway=h.action_gateway||{}, res=d.resource_state||{}, risk=d.risk_score;
    const securityCount=Number(sum.security_incidents||0), resourceCount=Number(sum.resource_incidents||0), total=(d.incidents||[]).length;
    text("connection",fresh.available?(fresh.stale?"STALE":"LIVE"):"OFFLINE");
    text("freshness",fresh.available?(fresh.stale?`${n(fresh.age_seconds)}s behind`:`${n(fresh.age_seconds)}s sync`):"runtime unavailable");
    text("posture",d.security_posture||"UNKNOWN"); text("postureScore",risk==null?"—":Math.round(risk)); text("postureNote",d.security_posture==="CLEAR"?"No active security incidents":"Security decision state");
    const ring=$("postureRing"); if(ring){const deg=clamp(risk)*3.6; ring.style.background=`conic-gradient(var(--accent) 0deg ${deg}deg,#15313b ${deg}deg 360deg)`;}
    text("threatPosture",d.threat_status||"UNKNOWN"); text("threatNote",`${securityCount} security incident${securityCount===1?"":"s"}`);
    text("resourcePosture",d.resource_posture||"UNKNOWN"); text("resourceNote",`${n(obs.memory_percent)}% memory utilization`);
    text("runtimeHealth",d.overall_status||"UNKNOWN"); text("runtimeMeta",`${rt.cycle_count??0} cycles · ${rt.component_failures??0} failures`);
    text("incidentTotal",total); text("incidentBreakdown",`${securityCount} security · ${resourceCount} resource`);
    text("admitted",rt.events_admitted??0); text("pipelineMeta",`${rt.events_created??0} created · ${rt.events_rejected??0} rejected`); text("navIncidents",total);
    text("safetyCore",String(safety.status||"UNKNOWN").toUpperCase()); text("safetyPill",String(safety.status||"UNKNOWN").toUpperCase());
    text("safeMode",safety.safe_mode?"SAFE MODE":(safety.shutdown_requested?"SHUTDOWN REQUESTED":"NORMAL"));
    text("policy",String(policy.status||"UNKNOWN").toUpperCase()); text("verifier",String(verifier.status||"UNKNOWN").toUpperCase());
    text("auth",auth.dry_run_only!==false?"DRY-RUN":"REVIEW"); text("gateway",gateway.real_world_effect===false?"NO EFFECT":"BLOCKED");
    text("securityIncidentCount",securityCount); text("resourceIncidentCount",resourceCount); text("criticalIncidentCount",sum.critical_security_incidents||0); text("incidentBadge",`${total} ACTIVE`);
    text("threatBig",d.threat_status||"UNKNOWN"); text("resourceBig",d.resource_posture||"UNKNOWN");
    setBar("cpu","cpuBar",obs.cpu_percent); setBar("memory","memoryBar",obs.memory_percent); setBar("disk","diskBar",obs.disk_percent);
    renderEndpointSurface(d,obs,res,rt); text("footerHost",d.endpoint?.hostname||"LOCAL ENDPOINT"); text("sequence",d.publisher?.sequence??"—"); text("updated",`UPDATED ${ts(d.publisher?.generated_at)}`);
    renderPipeline(d.security_chain||[]); if(!historyMode) renderLiveIncidents(d.incidents||[]); renderComponents(d.components||[]); renderApplications(d.process_inventory||[]); renderEvents(d.event_groups||[]); renderFleet(d.fleet||{}); renderSensorPlane(d.sensor_plane||{});
    const components=d.components||[], totalComponents=components.length;
    const nominalComponents=components.filter(x=>["HEALTHY","SAFE"].includes(String(x.status).toUpperCase())).length;
    const operationalComponents=components.filter(x=>["HEALTHY","SAFE"].includes(String(x.operational_status||x.status).toUpperCase())).length;
    text("componentHealth",`${operationalComponents}/${totalComponents} OPERATIONAL · ${nominalComponents}/${totalComponents} NOMINAL`);
  }

  function setBar(label,bar,value){ text(label,value==null?"—":`${n(value)}%`); const e=$(bar); if(e)e.style.width=`${clamp(value)}%`; }
  function renderPipeline(items){ const e=$("pipeline"); if(!e)return; e.innerHTML=(items||[]).slice(0,10).map(x=>{const s=String(x.status||"UNKNOWN").toUpperCase(); return `<div class="${statusClass(s)}"><span>${esc(x.name)}</span><b>${esc(s)}</b></div>`;}).join(""); }
  function classify(i){ const explicit=String(i?.incident_class||"").toLowerCase(); if(explicit) return explicit; const t=JSON.stringify(i||{}).toLowerCase(); return /(memory|resource|systemobserver|cpu|disk)/.test(t)?"resource":"security"; }

  function incidentRow(i){
    const type=classify(i), id=String(i.incident_id||i.id||i.key||"INCIDENT"), key=String(i.correlation_key||i.key||i.event_type||"security event"), score=i.risk_score??i.score??i.severity_score??"—";
    return `<button class="incident-row incident-open" type="button" data-incident-id="${esc(id)}"><span class="sev ${esc(type)}">${esc(type.toUpperCase())}</span><div><b>${esc(id)}</b><small>${esc(key)}</small></div><span class="score">${esc(score)}</span><span class="time">${esc(ts(i.updated_at??i.created_at??i.timestamp))}</span></button>`;
  }
  function renderLiveIncidents(items){
    const e=$("incidentList"); if(!e)return;
    if(!items.length){e.innerHTML=`<div class="incident-row"><span class="sev">NONE</span><div><b>No active incidents</b><small>Priority queue is clear. SQL history remains searchable.</small></div><span>—</span><span>—</span></div>`;return;}
    e.innerHTML=items.slice(0,8).map(incidentRow).join("");
  }
  function renderQueriedIncidents(items){
    const e=$("incidentList"); if(!e)return;
    if(!items.length){e.innerHTML=`<div class="incident-row"><span class="sev">NONE</span><div><b>No matching incidents</b><small>Try a different search or filter.</small></div><span>—</span><span>—</span></div>`;return;}
    e.innerHTML=items.map(incidentRow).join("");
  }
  function renderComponents(items){ const e=$("components"); if(!e)return; e.innerHTML=items.map(x=>{const s=String(x.status||"UNKNOWN").toUpperCase();return `<div class="comp ${statusClass(s)}"><span>${esc(x.name)}</span><b>${esc(s)}</b></div>`;}).join(""); }
  function renderApplications(items){
    const e=$("applications"); if(!e)return;
    if(!items.length){e.innerHTML=`<div class="app-row app-empty"><div><b>No application inventory yet</b><small>Waiting for the authoritative Python ProcessSensor.</small></div><span>—</span><span>—</span><span>—</span><span>—</span></div>`;return;}
    e.innerHTML=items.slice(0,18).map(x=>`<div class="app-row"><div><b>${esc(x.display_name||"Unknown Process")}</b><small>${esc(x.technical_name||"unknown")} · PID ${esc((x.pids||[]).slice(0,3).join(", ")||"—")}</small></div><span>${esc(x.processes||1)}×</span><span>${esc(n(x.memory_percent,2))}%</span><span>${esc(n(x.cpu_percent,2))}%</span><span class="app-user">${esc(x.username||"SYSTEM / unknown")}</span></div>`).join("");
  }
  function renderEvents(items){ const e=$("events"); if(!e)return; if(!items.length){e.innerHTML=`<div class="evidence-row"><div><b>No evidence events</b><small>Runtime evidence stream is empty.</small></div><span>INFO</span><span>0</span><span class="last">—</span></div>`;return;} e.innerHTML=items.slice(0,18).map(x=>{const raw=String(x.kind||"EVENT"), l=String(x.level||"INFO").toLowerCase();return `<div class="evidence-row"><div><b>${esc(humanEvent(raw))}</b><small>${esc(x.detail||"Runtime evidence")} · code: ${esc(raw)}</small></div><span class="level ${esc(l)}">${esc(String(x.level||"INFO").toUpperCase())}</span><span class="occ">${esc(x.count)}×</span><span class="last">${esc(ts(x.last))}</span></div>`;}).join(""); }

  function renderSensorPlane(sp){
    const c=sp?.canary||{}, ipc=sp?.ipc||{}, p=sp?.parity||{}, ne=sp?.native_enrichment||{};
    text("processAuthorityMode",sp.mode||"PYTHON_ONLY"); text("processAuthoritySensor",sp.authoritative_sensor||"ProcessSensor"); text("processGraphHealth",sp.process_graph_status||"UNKNOWN");
    text("rustPrimaryLock",sp.primary_lock||"CLOSED"); text("sensorPlaneBadge",`${sp.authoritative_sensor||"ProcessSensor"} PRIMARY`); text("navCanary",c.enabled?(c.status==="HEALTHY"?"✓":"!"):"—");
    text("rustCanaryStatus",c.status||"DISABLED"); text("rustCanaryReadiness",c.candidate_ready?"readiness gate PASS":(c.readiness_reason||"non-authoritative"));
    text("rustIpcStatus",ipc.status||"—"); text("rustIpcMeta",`PID ${ipc.sensor_pid??"—"} · gen ${ipc.generation??"—"} · ${ipc.restart_count??0} restart`);
    text("rustCanarySamples",c.sample_count??0); text("rustCanarySampleMeta",`${c.failure_count??0} failures · ${c.last_sample_latency_ms==null?"—":`${n(c.last_sample_latency_ms,2)} ms`}`);
    text("rustParityCommon",p.common_processes??"—"); text("rustParityVerdict",p.verdict||"NO SAMPLE");
    text("rustIdentityDiff",p.identity_disagreements??"—"); text("rustParentDiff",p.parent_disagreements??"—"); text("rustNameDiff",p.canonical_name_conflicts??"—");
    const parity=(field)=>{const f=p[field]||{};return f.mismatches==null?"—":`${f.matches??0}/${(Number(f.matches)||0)+(Number(f.mismatches)||0)} · Δ${f.mismatches??0}`};
    const cov=(field)=>{const f=ne[field]||{}, r=Number(f.coverage_rate);return Number.isFinite(r)?`${f.collected??0}/${f.total??0} · ${(r*100).toFixed(1)}%`:"—"};
    text("rustExeParity",parity("exe")); text("rustUserParity",parity("username")); text("rustCmdParity",parity("cmdline"));
    text("rustSidCoverage",cov("sid")); text("rustSessionCoverage",cov("session_id")); text("rustIntegrityCoverage",cov("integrity_level"));
  }


  function fleetEndpointCandidates(d){
    const fleet=d?.fleet||{};
    const endpoints=Array.isArray(fleet?.endpoints)?fleet.endpoints:[];
    const localId=String(d?.endpoint?.endpoint_id||"");
    const localHost=String(d?.endpoint?.hostname||"").toUpperCase();

    return endpoints.filter(x=>{
      const id=String(x?.endpoint_id||"");
      const host=String(x?.hostname||"").toUpperCase();

      return id &&
             id!==localId &&
             host!==localHost;
    });
  }

  function endpointLiveStatus(endpoint,fleet){
    const threshold=Number(fleet?.online_after_seconds??90);
    const lastSeen=Number(endpoint?.last_seen||0);
    const age=lastSeen>0 ? (Date.now()/1000-lastSeen) : Infinity;

    if(!Number.isFinite(age) || age>threshold){
      return "OFFLINE";
    }

    return String(endpoint?.health_state||"UNKNOWN").toUpperCase();
  }

  function setEndpointLabels(labels){
    const cells=document.querySelectorAll(".endpoint-top > div");

    labels.forEach((label,index)=>{
      const element=cells[index]?.querySelector("span");
      if(element) element.textContent=label;
    });
  }

  function ensureEndpointSelector(){
    let selector=$("endpointSelector");

    if(selector) return selector;

    const top=document.querySelector(".endpoint-panel .endpoint-top");

    if(!top) return null;

    selector=document.createElement("div");
    selector.id="endpointSelector";
    selector.className="endpoint-controls";
    selector.style.marginBottom="14px";

    top.parentNode.insertBefore(selector,top);

    return selector;
  }

  function renderEndpointSurface(d,obs,res,rt){
    const fleet=d?.fleet||{};
    const endpoints=fleetEndpointCandidates(d);
    const selector=ensureEndpointSelector();

    if(endpoints.length){
      const stillExists=endpoints.some(
        x=>String(x.endpoint_id)===String(selectedEndpointId)
      );

      if(!stillExists){
        selectedEndpointId=String(endpoints[0].endpoint_id);
      }

      const selected=endpoints.find(
        x=>String(x.endpoint_id)===String(selectedEndpointId)
      ) || endpoints[0];

      const selectedStatus=endpointLiveStatus(selected,fleet);

      if(selector){
        selector.innerHTML=endpoints.map(endpoint=>{
          const id=String(endpoint.endpoint_id||"");
          const status=endpointLiveStatus(endpoint,fleet);
          const active=id===String(selectedEndpointId);

          const activeStyle=active
            ? ' style="border-color:#35d6c2;box-shadow:0 0 0 1px #35d6c2 inset"'
            : "";

          return `<button type="button"${activeStyle} data-fleet-endpoint="${esc(id)}">${esc(endpoint.hostname||id)} · ${esc(status)}</button>`;
        }).join("");

        selector.querySelectorAll("[data-fleet-endpoint]").forEach(button=>{
          button.addEventListener("click",()=>{
            selectedEndpointId=button.dataset.fleetEndpoint||null;
            renderEndpointSurface(d,obs,res,rt);
          });
        });
      }

      setEndpointLabels([
        "HOST",
        "SERVICE",
        "VERSION",
        "LAST SEEN"
      ]);

      text("endpointState",selectedStatus);
      text("host",selected.hostname||selected.endpoint_id||"ENDPOINT");
      text("processes",selected.service_state||"UNKNOWN");
      text("availableMemory",selected.runtime_version||"—");
      text("cycles",ts(selected.last_seen));

      return;
    }

    if(selector){
      selector.innerHTML='<button type="button" disabled>NO REMOTE ENDPOINTS</button>';
    }

    selectedEndpointId=null;

    setEndpointLabels([
      "HOST",
      "PROCESSES",
      "AVAILABLE MEMORY",
      "CYCLES"
    ]);

    text("endpointState",res.status||"UNKNOWN");
    text("processes",obs.process_count??"—");
    text(
      "availableMemory",
      res.available_memory_mb!=null
        ? `${n(res.available_memory_mb)} MB`
        : "—"
    );
    text("cycles",rt.cycle_count??"—");
    text("host",d.endpoint?.hostname||"LOCAL ENDPOINT");
  }

  function selectedRemoteEndpoint(){
    const endpoints=Array.isArray(lastFleet?.endpoints)
      ? lastFleet.endpoints
      : [];

    return endpoints.find(
      x=>String(x.endpoint_id)===String(selectedEndpointId)
    ) || null;
  }

  function renderFleet(fleet){
    lastFleet=fleet||{};
    const summary=fleet?.summary||{}, endpoints=Array.isArray(fleet?.endpoints)?fleet.endpoints:[];
    text("fleetStatus",String(fleet?.status||"UNAVAILABLE").toUpperCase());
    text("fleetDownloads",summary.downloads_completed??0); text("fleetInstalled",summary.installed??0);
    text("fleetOnline",summary.online??0); text("fleetOffline",summary.offline??0);
    text("fleetDegraded",summary.degraded??0); text("fleetPending",Number(summary.pending||0)+Number(summary.install_failed||0));
    text("navFleet",summary.online??0);
    const e=$("fleetList"); if(!e)return;
    if(!endpoints.length){e.innerHTML=`<div class="fleet-row"><b>No fleet telemetry yet</b><span>—</span><span>—</span><span>—</span><span>—</span><span>—</span></div>`;return;}
    e.innerHTML=endpoints.slice(0,100).map(x=>`<div class="fleet-row"><b>${esc(x.hostname||x.endpoint_id||"endpoint")}</b><span>${esc(x.install_state||"UNKNOWN")}</span><span class="${statusClass(x.health_state)}">${esc(x.health_state||"UNKNOWN")}</span><span>${esc(x.service_state||"UNKNOWN")}</span><span>${esc(x.runtime_version||"—")}</span><span>${esc(ts(x.last_seen))}</span></div>`).join("");
  }

  function toast(action, message="Dry-run control surface only. No OS action was executed."){
    text("toastTitle",String(action).toUpperCase()); text("toastText",message); const e=$("toast"); e.classList.add("show"); clearTimeout(window.__toast); window.__toast=setTimeout(()=>e.classList.remove("show"),3200);
  }

  function openDrawer(title, eyebrow, html){
    text("drawerTitle",title); text("drawerEyebrow",eyebrow);
    const body=$("drawerBody"); if(body) body.innerHTML=html;
    const drawer=$("opsDrawer"), bg=$("drawerBackdrop");
    if(bg) bg.hidden=false; if(drawer){drawer.classList.add("open"); drawer.setAttribute("aria-hidden","false");}
  }
  function closeDrawer(){ const drawer=$("opsDrawer"), bg=$("drawerBackdrop"); if(drawer){drawer.classList.remove("open"); drawer.setAttribute("aria-hidden","true");} if(bg) bg.hidden=true; }

  async function openIncident(id){
    openDrawer("Loading incident…","INCIDENT DRILL-DOWN",`<div class="drawer-empty">Querying read-only structured history…</div>`);
    try{
      const r=await fetch(`/owner/api/incidents/${encodeURIComponent(id)}`,{cache:"no-store"}); if(!r.ok) throw new Error("not found");
      const d=await r.json(), i=d.incident||{}, evidence=i.evidence_timeline||[];
      const timeline=evidence.length?evidence.map(ev=>{const p=ev.payload||{}, msg=p.message||p.description||p.type||"Evidence observation"; return `<div class="timeline-row"><span class="timeline-dot ${esc(String(ev.severity||"INFO").toLowerCase())}"></span><div><b>${esc(ev.event_type||p.type||"DETECTION")}</b><small>${esc(msg)}</small><em>${esc(ev.source||p.source||"unknown")} · ${esc(dt(ev.observed_at))}</em></div><strong>${esc(String(ev.severity||p.severity||"INFO").toUpperCase())}</strong></div>`;}).join(""):`<div class="drawer-empty">No retained evidence rows for this incident.</div>`;
      const sources=(i.sources||[]).join(" · ")||"—", signals=(i.signal_types||[]).join(" · ")||"—", family=i.incident_family||"—";
      const html=`<div class="detail-grid"><div><span>CLASS</span><b>${esc(i.incident_class||"SECURITY")}</b></div><div><span>SEVERITY</span><b>${esc(i.severity||"INFO")}</b></div><div><span>RISK</span><b>${esc(i.risk_score??"—")}</b></div><div><span>OCCURRENCES</span><b>${esc(i.event_count??0)}</b></div><div><span>RETAINED EVIDENCE</span><b>${esc(evidence.length)}</b></div><div><span>FAMILY</span><b>${esc(family)}</b></div></div><div class="detail-block"><span>INCIDENT ID</span><b>${esc(i.incident_id||id)}</b><small>${esc(i.correlation_key||"—")}</small></div><div class="detail-block"><span>CORRELATED SOURCES</span><b>${esc(sources)}</b><small>${esc(signals)}</small></div><div class="detail-block"><span>EVIDENCE TIMELINE · CHRONOLOGICAL · READ ONLY</span><div class="timeline">${timeline}</div></div><div class="safety-banner">Structured SQL is a non-authoritative read model. Investigation cannot grant response authorization.</div>`;
      openDrawer(i.incident_id||id,"INCIDENT DRILL-DOWN",html);
    }catch{ openDrawer("Incident unavailable","INCIDENT DRILL-DOWN",`<div class="drawer-empty">Structured incident history is unavailable or the incident was pruned.</div>`); }
  }

  async function openEndpoint(){
    const remote=selectedRemoteEndpoint();

    if(remote){
      const fleet=lastFleet||{};
      const status=endpointLiveStatus(remote,fleet);

      const html=`
        <div class="detail-grid">
          <div><span>HOST</span><b>${esc(remote.hostname||"—")}</b></div>
          <div><span>HEALTH</span><b>${esc(status)}</b></div>
          <div><span>INSTALL</span><b>${esc(remote.install_state||"UNKNOWN")}</b></div>
          <div><span>SERVICE</span><b>${esc(remote.service_state||"UNKNOWN")}</b></div>
          <div><span>RUNTIME</span><b>${esc(remote.runtime_version||"—")}</b></div>
          <div><span>RESOURCE</span><b>${esc(remote.resource_state||"—")}</b></div>
          <div><span>FIRST SEEN</span><b>${esc(dt(remote.first_seen))}</b></div>
          <div><span>LAST SEEN</span><b>${esc(dt(remote.last_seen))}</b></div>
        </div>

        <div class="detail-block">
          <span>ENDPOINT ID</span>
          <b>${esc(remote.endpoint_id||"—")}</b>
          <small>${remote.last_error ? esc(remote.last_error) : "No reported endpoint error"}</small>
        </div>

        <div class="safety-banner">
          Remote endpoint telemetry is read-only.
          Endpoint selection does not grant privileged execution authority.
        </div>`;

      openDrawer(
        remote.hostname||"Endpoint",
        "FLEET ENDPOINT DETAILS",
        html
      );

      return;
    }
    openDrawer("Loading endpoint…","ENDPOINT DETAILS",`<div class="drawer-empty">Reading local structured endpoint state…</div>`);
    try{
      const r=await fetch('/owner/api/endpoint',{cache:'no-store'}); if(!r.ok) throw new Error(); const d=await r.json(), e=d.endpoint||{}, decisions=e.recent_decisions||[];
      const rows=decisions.length?decisions.map(x=>`<div class="decision-history"><div><b>${esc(x.risk_level||"INFO")} · ${esc(x.policy_outcome||"—")}</b><small>${esc(x.recommendation||"No recommendation")}</small></div><span>${esc(x.verification_outcome||"—")}</span><em>${esc(x.occurrence_count||1)}× · ${esc(dt(x.last_seen))}</em></div>`).join(''):`<div class="drawer-empty">No decision history yet.</div>`;
      const html=`<div class="detail-grid"><div><span>HOST</span><b>${esc(e.hostname||"—")}</b></div><div><span>RUNTIME</span><b>${esc(e.runtime_version||"—")}</b></div><div><span>STATE</span><b>${esc(e.runtime_status||"—")}</b></div><div><span>RESOURCE</span><b>${esc(e.resource_state||"—")}</b></div><div><span>CPU</span><b>${esc(n(e.cpu_percent))}%</b></div><div><span>MEMORY</span><b>${esc(n(e.memory_percent))}%</b></div><div><span>PROCESSES</span><b>${esc(e.process_count??"—")}</b></div><div><span>LAST CYCLE</span><b>${esc(e.last_cycle??"—")}</b></div></div><div class="detail-block"><span>RECENT POLICY / VERIFICATION HISTORY</span><div class="history-list">${rows}</div></div><div class="safety-banner">Endpoint details are read-only. No dashboard path reaches the operating system.</div>`;
      openDrawer(e.hostname||"Endpoint","ENDPOINT DETAILS",html);
    }catch{ openDrawer("Endpoint unavailable","ENDPOINT DETAILS",`<div class="drawer-empty">Structured endpoint state is not available yet. Keep the agent running for at least one cycle.</div>`); }
  }

  async function openDemoScenario(){
    openDrawer("Building safe scenario…","CRITICAL THREAT SIMULATION",`<div class="drawer-empty">Generating synthetic telemetry only…</div>`);
    try{
      const r=await fetch('/owner/api/demo/critical-threat',{cache:'no-store'}); if(!r.ok) throw new Error(); const d=await r.json();
      const timeline=(d.timeline||[]).map(x=>`<div class="timeline-row"><span class="timeline-dot ${esc(String(x.severity||"INFO").toLowerCase())}"></span><div><b>${esc(x.event_type)}</b><small>${esc(x.message)}</small><em>+${esc(x.offset_seconds)}s · SYNTHETIC</em></div><strong>${esc(x.severity)}</strong></div>`).join('');
      const actions=(d.response_simulation?.actions||[]).map(x=>`<div class="plan-row"><span>${esc(x.action)}</span><b>${esc(x.status)}</b></div>`).join('');
      const recovery=(d.recovery_plan?.phases||[]).map((x,idx)=>`<div class="plan-row"><span>${idx+1}. ${esc(x)}</span><b>PLANNED</b></div>`).join('');
      const html=`<div class="synthetic-banner"><b>PRESENTATION-SAFE SYNTHETIC THREAT</b><span>No malware payload · no system commands · no privileged execution</span><a class="demo-artifact-link" href="/owner/static/demo/CyberDefender_Presentation_Threat.cdtest" download>Download harmless demo artifact</a></div><div class="detail-grid"><div><span>RISK</span><b>${esc(d.risk?.score??"—")}/100</b></div><div><span>LEVEL</span><b>${esc(d.risk?.level||"—")}</b></div><div><span>POLICY</span><b>${esc(d.policy?.outcome||"—")}</b></div><div><span>AUTHORIZATION</span><b>${esc(d.policy?.authorization||"—")}</b></div></div><div class="detail-block"><span>BEHAVIOR CHAIN</span><div class="timeline">${timeline}</div></div><div class="detail-block"><span>SAFE RESPONSE SIMULATION</span>${actions}</div><div class="detail-block"><span>RECOVERY PLAN</span>${recovery}</div><div class="safety-banner">Independent Verification: ${esc(d.verification?.outcome||"—")} · Authorization remains ${esc(d.verification?.authorization||"NOT_GRANTED")} · Real-world effect: BLOCKED.</div>`;
      openDrawer(d.name||"Critical Threat Simulation","P0.8 · SAFE DEMO SCENARIO",html);
    }catch{ openDrawer("Scenario unavailable","CRITICAL THREAT SIMULATION",`<div class="drawer-empty">Demo scenario service unavailable.</div>`); }
  }

  async function loadIncidentHistory(){
    historyMode = true;
    const q=encodeURIComponent($("incidentSearch")?.value||""), severity=encodeURIComponent($("incidentSeverity")?.value||""), cls=encodeURIComponent($("incidentClass")?.value||"");
    try{ const r=await fetch(`/owner/api/incidents?q=${q}&severity=${severity}&class=${cls}&limit=50`,{cache:"no-store"}); if(!r.ok) throw new Error(); const d=await r.json(); if(d.status==="OK") renderQueriedIncidents(d.incidents||[]); }
    catch{ if(lastState) renderLiveIncidents(lastState.incidents||[]); }
  }

  async function refresh(){ try{const r=await fetch("/owner/api/state",{cache:"no-store"}); if(!r.ok)throw new Error(); render(await r.json());}catch{ text("connection","OFFLINE"); text("freshness","runtime state unavailable"); text("runtimeHealth","AGENT_OFFLINE"); } }
  function clock(){ text("clock",new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"})); }

  document.querySelectorAll(".nav").forEach(b=>b.addEventListener("click",()=>{document.getElementById(b.dataset.target)?.scrollIntoView({behavior:"smooth",block:"start"});document.querySelectorAll(".nav").forEach(x=>x.classList.remove("active"));b.classList.add("active");}));
  document.addEventListener('click', e=>{
    const incident=e.target.closest?.('[data-incident-id]'); if(incident){ openIncident(incident.dataset.incidentId); return; }
    const action=e.target.closest?.('[data-action]')?.dataset?.action; if(!action) return;
    if(action==='demo-critical-threat'){ openDemoScenario(); return; }
    if(action==='endpoint-investigation'){ openEndpoint(); return; }
    if(action==='incident-investigation'){ document.getElementById('incidents')?.scrollIntoView({behavior:'smooth'}); loadIncidentHistory(); return; }
    if(action==='review-decision'){ document.getElementById('decision')?.scrollIntoView({behavior:'smooth'}); return; }
    toast(action);
  });
  $("drawerClose")?.addEventListener("click",closeDrawer); $("drawerBackdrop")?.addEventListener("click",closeDrawer);
  document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDrawer();});
  $("incidentRefresh")?.addEventListener("click",loadIncidentHistory);
  $("incidentSeverity")?.addEventListener("change",loadIncidentHistory); $("incidentClass")?.addEventListener("change",loadIncidentHistory);
  $("incidentSearch")?.addEventListener("input",()=>{clearTimeout(incidentTimer);incidentTimer=setTimeout(loadIncidentHistory,250);});

  setInterval(clock,1000); clock(); refresh(); setInterval(refresh,REFRESH_MS);
})();
