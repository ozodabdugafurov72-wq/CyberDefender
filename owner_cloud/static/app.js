"use strict";

const byId = id => document.getElementById(id);
const text = (id, value) => { const node = byId(id); if (node) node.textContent = value ?? "—"; };
const stamp = value => value == null ? "—" : new Date(Number(value) * 1000).toLocaleString();
const number = value => Number.isInteger(value) ? value.toLocaleString() : "—";
const status = (id, value, tone = "neutral") => {
  const node = byId(id); if (!node) return;
  node.textContent = value; node.className = `status ${tone}`;
};
const empty = message => { const p = document.createElement("p"); p.className = "empty"; p.textContent = message; return p; };
const tag = (value, tone = "neutral") => { const span = document.createElement("span"); span.className = `tag ${tone}`; span.textContent = value ?? "—"; return span; };
const toneFor = value => ({HEALTHY:"good",ONLINE:"good",RUNNING:"good",AVAILABLE:"good",SUCCESS:"good",CRITICAL:"danger",BLOCKED:"danger",DENIED:"danger",DEGRADED:"warn",HIGH:"warn",OFFLINE:"muted",STALE:"muted",UNKNOWN:"muted",UNAVAILABLE:"muted",REVOKED:"danger"}[value] || "neutral");

function table(headers, rows) {
  const wrap = document.createElement("div"); wrap.className = "data-table";
  const head = document.createElement("div"); head.className = "data-row data-head";
  headers.forEach(value => { const cell = document.createElement("span"); cell.textContent = value; head.appendChild(cell); });
  wrap.appendChild(head);
  rows.forEach(cells => { const row = document.createElement("div"); row.className = "data-row"; cells.forEach(value => { const cell = document.createElement("span"); if (value instanceof Node) cell.appendChild(value); else cell.textContent = value ?? "—"; row.appendChild(cell); }); wrap.appendChild(row); });
  return wrap;
}

function renderFleet(items) {
  const root = byId("fleetEvidence"); root.replaceChildren();
  if (!items.length) { root.appendChild(empty("No registered endpoints in the authenticated tenant scope.")); status("fleetEvidenceStatus", "NO ENDPOINTS", "muted"); return; }
  const rows = items.map(item => [item.hostname, tag(item.status, toneFor(item.status)), tag(item.health_state, toneFor(item.health_state)), item.service_state, item.runtime_version, item.status === "ONLINE" ? `${Number(item.cpu_percent).toFixed(1)}% / ${Number(item.memory_percent).toFixed(1)}%` : "stale · hidden", stamp(item.last_verified_heartbeat)]);
  root.appendChild(table(["Endpoint", "Presence", "Health", "Service", "Runtime", "CPU / RAM", "Last verified"], rows));
  status("fleetEvidenceStatus", "AUTHENTICATED", "good");
}

function renderEventSummary(items) {
  const root = byId("eventSummary"); root.replaceChildren();
  if (!items.length) { root.appendChild(empty("No signed security events received for this tenant.")); return; }
  items.forEach(item => { const row = document.createElement("div"); row.className = "event-card"; const top = document.createElement("div"); top.append(tag(item.priority, toneFor(item.priority))); const count = document.createElement("b"); count.textContent = number(item.count); top.appendChild(count); const name = document.createElement("span"); name.textContent = item.event_type; row.append(top, name); root.appendChild(row); });
}

function totalFor(items, type) { return items.filter(item => item.event_type === type).reduce((sum, item) => sum + Number(item.count || 0), 0); }

function renderRecentEvents(items, available) {
  const root = byId("recentEvents"); root.replaceChildren();
  if (!available) { root.appendChild(empty("Unavailable: the authenticated fleet API does not expose event investigation metadata.")); status("investigationStatus", "UNAVAILABLE", "muted"); return; }
  if (!items.length) { root.appendChild(empty("No event evidence has been received for this tenant.")); status("investigationStatus", "NO EVENTS", "muted"); return; }
  const rows = items.map(item => [stamp(item.received_at), tag(item.priority, toneFor(item.priority)), item.event_type, item.endpoint_id, item.event_id]);
  root.appendChild(table(["Received", "Priority", "Type", "Endpoint ID", "Event ID"], rows));
  status("investigationStatus", "READ ONLY", "good");
}

function renderDiagnostics(items, available) {
  const root = byId("diagnosticsTable"); root.replaceChildren();
  if (!available) { root.appendChild(empty("Unavailable: spool and ACK fields are not exposed by the authenticated fleet API.")); status("diagnosticsStatus", "UNAVAILABLE", "muted"); return; }
  if (!items.length) { root.appendChild(empty("No endpoint diagnostics available.")); status("diagnosticsStatus", "NO ENDPOINTS", "muted"); return; }
  const rows = items.map(item => [item.hostname, tag(item.spool_status, toneFor(item.spool_status)), number(item.spool_pending), item.spool_bytes == null ? "—" : `${Number(item.spool_bytes).toLocaleString()} B`, number(item.accepted_through), item.component_failures == null ? "—" : number(item.component_failures)]);
  root.appendChild(table(["Endpoint", "Spool", "Pending", "Spool bytes", "ACK accepted through", "Component failures"], rows));
  status("diagnosticsStatus", "TRUSTED HEARTBEAT", "good");
}

function renderVersions(items) {
  const root = byId("versions"); root.replaceChildren();
  const counts = new Map(); items.forEach(item => counts.set(item.runtime_version, (counts.get(item.runtime_version) || 0) + 1));
  if (!counts.size) { root.appendChild(empty("No installed runtime versions reported.")); return; }
  [...counts.entries()].sort((a,b) => b[1] - a[1]).forEach(([version, count]) => { const row = document.createElement("div"); const name = document.createElement("b"); name.textContent = version; const value = document.createElement("span"); value.textContent = `${count} endpoint${count === 1 ? "" : "s"}`; row.append(name, value); root.appendChild(row); });
}

function renderXdr(xdr) {
  status("xdrStatus", xdr.status || "UNAVAILABLE", toneFor(xdr.status));
  text("xdrSchema", xdr.schema && xdr.schema_version ? `${xdr.schema} ${xdr.schema_version}` : "UNAVAILABLE");
  text("xdrSigned", xdr.signed_ingest === true ? "ENFORCED" : "UNAVAILABLE");
  text("xdrReplay", xdr.replay_protection === true ? "ENFORCED" : "UNAVAILABLE");
  text("xdrValidation", xdr.runtime_contract_validation === true ? "ENFORCED" : "UNAVAILABLE");
}

function renderResponses(items, summary, available) {
  const root = byId("responseEvidence"); root.replaceChildren();
  if (!available) { root.appendChild(empty("Unavailable: this tenant fleet API does not expose signed response evidence.")); status("responseStatus", "UNAVAILABLE", "muted"); return; }
  text("responseTotal", number(summary.responses_total)); text("responseQuarantined", number(summary.responses_quarantined)); text("responseRestored", number(summary.responses_restored)); text("responseLatency", summary.response_latency_ms_max == null ? "—" : `${Number(summary.response_latency_ms_max).toFixed(3)} ms`);
  if (!items.length) { root.appendChild(empty("No signed response evidence received.")); status("responseStatus", "NO EVIDENCE", "muted"); return; }
  root.appendChild(table(["State","Endpoint","Risk","Verification","Evidence"], items.map(item => [tag(item.action_state,toneFor(item.action_state)),item.endpoint_id,item.risk_level,item.verification_outcome,item.evidence_id])));
  status("responseStatus", "VERIFIED · READ ONLY", "good");
}

function renderIntegrations(integrations) {
  [["sensor_plane","sensorPlane","sensorReason"],["process_graph","processGraph","processReason"],["persistence_detail","persistenceDetail","persistenceReason"]].forEach(([key,id,reasonId]) => { const item = integrations[key] || {}; text(id, item.status || "UNAVAILABLE"); text(reasonId, item.reason || ""); const node = byId(id); if (node) node.className = toneFor(item.status); });
  const quarantine = integrations.quarantine_detail || {};
  const value = quarantine.status || "UNAVAILABLE"; status("quarantineStatus", value, value === "EVENT_METADATA_ONLY" ? "warn" : toneFor(value));
  text("quarantineMessage", value === "EVENT_METADATA_ONLY" ? "Signed quarantine event metadata is visible below; item status and vault detail remain unavailable because no authenticated quarantine-detail API is exposed." : "Unavailable: no authenticated quarantine-detail API is exposed.");
}

function unavailable(reason) {
  const global = byId("globalState"); global.className = "notice error"; global.textContent = `Fleet data unavailable · ${reason || "UPSTREAM_UNAVAILABLE"}`;
  ["fleetEvidenceStatus","investigationStatus","diagnosticsStatus","correlationStatus","quarantineStatus"].forEach(id => status(id,"UNAVAILABLE","muted"));
  ["fleetEvidence","recentEvents","diagnosticsTable"].forEach(id => { const root = byId(id); if (root) root.replaceChildren(empty("Authenticated fleet data is currently unavailable.")); });
}

function renderSecurity(security) {
  text("authGate", security?.authentication || "UNAVAILABLE"); text("mfaGate", security?.mfa || "UNAVAILABLE"); text("rbacGate", security?.server_side_rbac || "UNAVAILABLE"); text("csrfGate", security?.csrf || "UNAVAILABLE"); text("actionGate", security?.privileged_actions || "UNAVAILABLE"); text("trustGate", security?.risk_is_authorization === false ? "ENFORCED" : "UNAVAILABLE");
}

async function loadSession() {
  const response = await fetch("/api/v1/session", {credentials:"same-origin", headers:{Accept:"application/json"}});
  if (response.status === 401) { location.assign("/login"); return; }
  if (!response.ok) throw new Error("session unavailable");
  const session = await response.json(); text("sessionExpiry", stamp(session.expires_at));
}

async function loadState() {
  const root = document.querySelector(".dashboard");
  try {
    const response = await fetch(root.dataset.stateUrl, {credentials:"same-origin", headers:{Accept:"application/json"}});
    if (response.status === 401) { location.assign("/login"); return; }
    if (!response.ok) throw new Error(response.status === 403 ? "ROLE_FORBIDDEN" : "STATE_REQUEST_FAILED");
    const data = await response.json(), dist = data.distribution || {}, summary = dist.summary || {}, items = Array.isArray(dist.endpoints) ? dist.endpoints : [], events = Array.isArray(dist.event_summary) ? dist.event_summary : [], capabilities = dist.capabilities || {};
    if (dist.status !== "HEALTHY") { unavailable(dist.reason); renderIntegrations(data.integrations || {}); renderXdr({}); renderResponses([], {}, false); renderSecurity(data.security || {}); return; }
    const global = byId("globalState"); global.className = "notice success"; global.textContent = `Authenticated tenant fleet · ${dist.tenant_id || "legacy scope"} · ${data.mode}`;
    text("endpoints", number(summary.endpoints_total)); text("online", number(summary.online)); text("offline", number(summary.offline)); text("degraded", number(summary.degraded)); text("critical", number(summary.critical)); text("unknown", number(items.filter(item => item.health_state === "UNKNOWN").length));
    text("generatedAt", stamp(dist.generated_at)); text("freshnessWindow", dist.generated_at == null ? "legacy API" : `${Math.round(Number(dist.online_after_seconds || 0))} seconds`); text("transport", dist.transport || "UNAVAILABLE");
    renderFleet(items); renderEventSummary(events); renderRecentEvents(Array.isArray(dist.recent_events) ? dist.recent_events : [], capabilities.event_investigation === true); renderDiagnostics(items, capabilities.endpoint_diagnostics === true); renderVersions(items); renderIntegrations(data.integrations || {}); renderXdr(dist.xdr || {}); renderResponses(Array.isArray(dist.responses) ? dist.responses : [], summary, capabilities.response_evidence === true);
    text("detectionCount", number(totalFor(events,"DETECTION"))); text("incidentCount", number(totalFor(events,"INCIDENT"))); text("graphCount", number(totalFor(events,"ATTACK_GRAPH"))); text("riskCount", number(totalFor(events,"RISK"))); status("correlationStatus", "SIGNED SUMMARY", "good");
    renderSecurity(data.security || {});
  } catch (error) { unavailable(error.message); }
}

async function loadAudit() {
  const root = document.querySelector(".dashboard"); if (root?.dataset.role !== "OWNER") return;
  const target = byId("audit");
  try {
    const response = await fetch("/api/v1/audit", {credentials:"same-origin", headers:{Accept:"application/json"}});
    if (!response.ok) throw new Error("AUDIT_UNAVAILABLE");
    const data = await response.json(), events = Array.isArray(data.events) ? data.events : []; target.replaceChildren();
    if (!events.length) target.appendChild(empty("No audited access events recorded.")); else target.appendChild(table(["Time","Actor","Role","Action","Outcome"], events.slice(0,100).map(event => [stamp(event.occurred_at),event.actor,event.role,event.action,tag(event.outcome,toneFor(event.outcome))])));
    status("auditStatus", "OWNER ONLY", "good");
  } catch (_) { target.replaceChildren(empty("Owner audit is currently unavailable.")); status("auditStatus","UNAVAILABLE","muted"); }
}

Promise.allSettled([loadSession(), loadState(), loadAudit()]);
setInterval(loadState, 30000);
