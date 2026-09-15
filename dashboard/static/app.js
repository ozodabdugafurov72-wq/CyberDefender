/* CyberDefender Monitor — Dashboard Runtime UI v5
 * Reference-driven monitoring dashboard.
 *
 * Rules:
 *  - Read-only client. Never controls the agent.
 *  - Runtime snapshot is the source of truth.
 *  - No fake telemetry.
 *  - Resource charts use live samples collected while the dashboard is open.
 *  - Event Log uses real server events and client-side pagination.
 */

(() => {
    "use strict";

    const REFRESH_MS = 2000;
    const HISTORY_LIMIT = 120;
    const EVENT_PAGE_SIZE = 10;

    const history = {
        timestamps: [],
        cpu: [],
        memory: [],
        disk: [],
        upload: [],
        download: []
    };

  let refreshInFlight = false;
  let firstAgentSeenAt = null;
  let lastKnownUptimeSeconds = null;
    let latestEvents = [];
    let latestData = {};
    let eventPage = 1;

    const $ = (id) => document.getElementById(id);

    function numberOrNull(value) {
        const n = Number(value);
        return Number.isFinite(n) ? n : null;
    }

    function setText(id, value, fallback = "--") {
        const el = $(id);
        if (!el) return;
        el.textContent =
            value === undefined || value === null || value === ""
                ? fallback
                : String(value);
    }

    function formatNumber(value, digits = 1) {
        const n = numberOrNull(value);
        return n === null ? "--" : n.toFixed(digits);
    }

    function parseTimestamp(value) {
        if (value === undefined || value === null || value === "") {
            return null;
        }

        if (typeof value === "number") {
            if (!Number.isFinite(value)) return null;
            if (value > 100000000000000) return value / 1000000;
            if (value > 100000000000) return value / 1000;
            if (value > 10000000000) return value / 1000;
            return value;
        }

        const text = String(value).trim();
        if (!text) return null;

        const numeric = Number(text);
        if (Number.isFinite(numeric)) {
            return parseTimestamp(numeric);
        }

        const normalized = text.includes(" ") && !text.includes("T")
            ? text.replace(" ", "T")
            : text;

        const parsed = Date.parse(normalized);
        if (!Number.isNaN(parsed)) {
            return parsed / 1000;
        }

        return null;
    }

    function formatTime(timestamp) {
        const seconds = parseTimestamp(timestamp);
        if (seconds === null) return "--:--:--";

        const d = new Date(seconds * 1000);
        if (Number.isNaN(d.getTime())) return "--:--:--";

        return d.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    }

    function eventTimestamp(event) {
        if (!event || typeof event !== "object") return null;

        const candidates = [
            event.timestamp,
            event.event_timestamp,
            event.event_time,
            event.time,
            event.created_at,
            event.generated_at
        ];

        for (const candidate of candidates) {
            const parsed = parseTimestamp(candidate);
            if (parsed !== null) return parsed;
        }

        return null;
    }

    function eventName(event) {
        if (!event || typeof event !== "object") return "UNKNOWN_EVENT";

        return String(
            event.event_type ??
            event.type ??
            event.name ??
            event.event ??
            "UNKNOWN_EVENT"
        );
    }

    function eventDetails(event) {
        if (!event || typeof event !== "object") return "-";

        return String(
            event.details ??
            event.message ??
            event.description ??
            event.reason ??
            event.detail ??
            "-"
        );
    }

    function eventLevel(event) {
        if (!event || typeof event !== "object") return "INFO";

        return String(
            event.level ??
            event.severity ??
            event.risk_level ??
            "INFO"
        ).toUpperCase();
    }

    function eventSource(event) {
        if (!event || typeof event !== "object") return "-";

        return String(
            event.source ??
            event.component ??
            event.origin ??
            "-"
        );
    }

    function severityClass(level) {
        const value = String(level || "INFO").toLowerCase();

        if (value.includes("critical") || value.includes("high")) {
            return "high";
        }

        if (value.includes("medium") || value.includes("warning")) {
            return "medium";
        }

        if (value.includes("low")) {
            return "low";
        }

        return "info";
    }

    function escapeHTML(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function pushHistory(observation) {
        const timestamp = Date.now();

        history.timestamps.push(timestamp);
        history.cpu.push(numberOrNull(observation?.cpu_percent));
        history.memory.push(numberOrNull(observation?.memory_percent));
        history.disk.push(numberOrNull(observation?.disk_percent));
        history.upload.push(numberOrNull(observation?.network_upload_mbps));
        history.download.push(numberOrNull(observation?.network_download_mbps));

        while (history.timestamps.length > HISTORY_LIMIT) {
            history.timestamps.shift();
            history.cpu.shift();
            history.memory.shift();
            history.disk.shift();
            history.upload.shift();
            history.download.shift();
        }
    }

    function drawLineChart(canvasId, values, stroke, maxValue = 100) {
        const canvas = $(canvasId);
        if (!canvas) return;

        const rect = canvas.getBoundingClientRect();
        const width = Math.max(120, Math.floor(rect.width || canvas.clientWidth || 220));
        const height = Math.max(45, Math.floor(rect.height || canvas.clientHeight || 52));

        const dpr = window.devicePixelRatio || 1;
        canvas.width = width * dpr;
        canvas.height = height * dpr;

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);

        ctx.strokeStyle = "rgba(60, 91, 106, .25)";
        ctx.lineWidth = 1;

        for (let i = 1; i < 4; i++) {
            const y = (height / 4) * i;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }

        const valid = values
            .map(numberOrNull)
            .filter((v) => v !== null);

        if (valid.length < 2) return;

        const step = width / Math.max(1, values.length - 1);

        ctx.strokeStyle = stroke;
        ctx.lineWidth = 1.5;
        ctx.beginPath();

        let started = false;

        values.forEach((value, index) => {
            const n = numberOrNull(value);
            if (n === null) return;

            const x = index * step;
            const normalized = Math.max(0, Math.min(1, n / maxValue));
            const y = height - normalized * (height - 4) - 2;

            if (!started) {
                ctx.moveTo(x, y);
                started = true;
            } else {
                ctx.lineTo(x, y);
            }
        });

        ctx.stroke();
    }

    function drawNetworkChart() {
        const canvas = $("networkChart");
        if (!canvas) return;

        const rect = canvas.getBoundingClientRect();

        const width = Math.max(
            120,
            Math.floor(
                rect.width ||
                canvas.clientWidth ||
                220
            )
        );

        const height = Math.max(
            45,
            Math.floor(
                rect.height ||
                canvas.clientHeight ||
                52
            )
        );

        const dpr =
            window.devicePixelRatio || 1;

        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        ctx.setTransform(
            dpr,
            0,
            0,
            dpr,
            0,
            0
        );

        ctx.clearRect(
            0,
            0,
            width,
            height
        );

        ctx.strokeStyle =
            "rgba(60, 91, 106, .25)";
        ctx.lineWidth = 1;

        for (let i = 1; i < 4; i++) {
            const y =
                (height / 4) * i;

            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }

        const upload =
            history.upload.map(numberOrNull);

        const download =
            history.download.map(numberOrNull);

        const valid = [
            ...upload.filter(
                (value) => value !== null
            ),
            ...download.filter(
                (value) => value !== null
            )
        ];

        if (valid.length < 2) return;

        const maxValue = Math.max(
            1,
            Math.ceil(
                Math.max(...valid) * 2
            ) / 2
        );

        const drawSeries = (
            values,
            stroke
        ) => {
            const step =
                width /
                Math.max(
                    1,
                    values.length - 1
                );

            let started = false;

            ctx.beginPath();

            values.forEach(
                (value, index) => {
                    if (value === null) {
                        started = false;
                        return;
                    }

                    const x =
                        index * step;

                    const normalized =
                        Math.max(
                            0,
                            Math.min(
                                1,
                                value /
                                maxValue
                            )
                        );

                    const y =
                        height -
                        normalized *
                            (height - 4) -
                        2;

                    if (!started) {
                        ctx.moveTo(x, y);
                        started = true;
                    } else {
                        ctx.lineTo(x, y);
                    }
                }
            );

            ctx.strokeStyle = stroke;
            ctx.lineWidth = 1.5;
            ctx.stroke();
        };

        drawSeries(
            upload,
            "#00baff"
        );

        drawSeries(
            download,
            "#a35cff"
        );
    }

    function drawResourceCharts() {
        drawLineChart(
            "cpuChart",
            history.cpu,
            "#00baff",
            100
        );

        drawLineChart(
            "memoryChart",
            history.memory,
            "#a35cff",
            100
        );

        drawLineChart(
            "diskChart",
            history.disk,
            "#00df91",
            100
        );

        drawNetworkChart();
    }

    function setResource(id, value) {
        const n = numberOrNull(value);
        setText(id, n === null ? "--" : `${n.toFixed(1)}%`);

        const bar = $(`${id}Bar`);
        if (bar) {
            const width = n === null ? 0 : Math.max(0, Math.min(100, n));
            bar.style.width = `${width}%`;
        }
    }

    function renderRuntime(data) {
        latestData = data || {};
        window.__cdRuntime = data || {};
        const runtime = data?.runtime || {};
        const health = data?.health?.runtime || {};
        const observation = data?.observation || {};
        const freshness = data?.runtime_freshness || {};

        const isFresh =
            freshness.available === true &&
            freshness.stale !== true;

        const runtimeRunning =
            runtime.running === true;

        let status;

        if (!freshness.available) {
            status = "NO SIGNAL";
        } else if (freshness.stale) {
            status = "STALE";
        } else if (!runtimeRunning) {
            status = "STOPPED";
        } else {
            status = String(
                data?.status ||
                health?.status ||
                "HEALTHY"
            ).toUpperCase();
        }

        setText(
            "systemStatus",
            status
        );

        setText(
            "footerStatus",
            runtimeRunning && isFresh
                ? "READ-ONLY MONITOR"
                : status
        );

        document.documentElement.dataset.runtimeStatus =
            status.toLowerCase().replace(/\s+/g, "-");

        const agentStatus =
            !freshness.available
                ? "OFFLINE"
                : freshness.stale
                    ? "STALE"
                    : runtime.running === false
                        ? "STOPPED"
                        : "ACTIVE";

        setText("agentStatus", agentStatus);

        setText(
            "runtimeVersion",
            runtime.version ?? health.version
        );

        setText(
            "cycleCount",
            runtime.cycle_count ?? health.cycle_count
        );

        setText(
            "eventCreated",
            runtime.events_created
        );

        setText(
            "eventAdmitted",
            runtime.events_admitted
        );

        setText(
            "eventAcked",
            runtime.events_acked
        );

        setText(
            "runtimeFreshness",
            freshness.available
                ? freshness.stale
                    ? "STALE"
                    : `${formatNumber(freshness.age_seconds, 1)}s ago`
                : "NO SIGNAL"
        );

        setResource("cpu", observation.cpu_percent);
        setResource("memory", observation.memory_percent);
        setResource("disk", observation.disk_percent);

        const upload = numberOrNull(observation.network_upload_mbps);
        const download = numberOrNull(observation.network_download_mbps);

        setText(
            "networkOut",
            upload === null ? "--" : `↑ ${upload.toFixed(3)} Mbps`
        );

        setText(
            "networkIn",
            download === null ? "--" : `↓ ${download.toFixed(3)} Mbps`
        );

        setText(
            "processCount",
            observation.process_count
        );

        if (isFresh) {
            pushHistory(observation);
        }

        renderKpis(data);
        renderProcesses(observation.top_processes);
        renderEndpointHealth(data);
        renderAlerts(data);
        renderEvents(data.events || []);
        drawResourceCharts();
        drawAlertsChart(data.events || []);
       renderUptime(data);
    }

    function renderKpis(data) {
        const alerts = data?.alerts && typeof data.alerts === "object"
            ? data.alerts
            : {};

        const incidents = Array.isArray(data?.incidents)
            ? data.incidents.filter(Boolean)
            : [];

        // Prefer backend-provided alert counts. If the backend does not
        // provide severity buckets yet, derive them from real incidents.
        const incidentSeverity = (incident) => {
            const severity = String(
                incident?.severity ?? incident?.level ?? ""
            ).toUpperCase();

            if (["CRITICAL", "HIGH"].includes(severity)) return "high";
            if (["MEDIUM", "WARNING"].includes(severity)) return "medium";
            if (["LOW", "INFO"].includes(severity)) return "low";

            const risk = numberOrNull(
                incident?.risk ?? incident?.risk_score
            );

            if (risk !== null) {
                if (risk >= 70) return "high";
                if (risk >= 30) return "medium";
                return "low";
            }

            return null;
        };

        const derived = { high: 0, medium: 0, low: 0 };
        for (const incident of incidents) {
            const bucket = incidentSeverity(incident);
            if (bucket) derived[bucket] += 1;
        }

        // When incidents are present, their authoritative severity must
        // win over legacy/coarse alert buckets from the API.
        // This prevents CRITICAL incidents (risk 60 in the current
        // CorrelationEngine model) from being displayed as MEDIUM RISK
        // merely because an older alerts.medium field is still present.
        const hasIncidentSeverity = incidents.length > 0;

        const high = hasIncidentSeverity
            ? derived.high
            : (numberOrNull(alerts.high) ?? 0);
        const medium = hasIncidentSeverity
            ? derived.medium
            : (numberOrNull(alerts.medium) ?? 0);
        const low = hasIncidentSeverity
            ? derived.low
            : (numberOrNull(alerts.low) ?? 0);

        const backendTotal = numberOrNull(alerts.total);
        const total = incidents.length > 0
            ? incidents.length
            : (backendTotal ?? (high + medium + low));

        setText("totalAlerts", total, "0");
        setText("highAlerts", high, "0");
        setText("mediumAlerts", medium, "0");
        setText("lowAlerts", low, "0");

        // Keep the small KPI captions truthful instead of showing a
        // misleading fixed message when no historical comparison exists.
        setText(
            "totalAlertsMeta",
            total > 0 ? `${total} detected in current window` : "No active alerts"
        );
        setText(
            "highAlertsMeta",
            high > 0 ? `${high} high-risk alert${high === 1 ? "" : "s"}` : "No high-risk alerts"
        );
        setText(
            "mediumAlertsMeta",
            medium > 0 ? `${medium} medium-risk alert${medium === 1 ? "" : "s"}` : "No medium-risk alerts"
        );
        setText(
            "lowAlertsMeta",
            low > 0 ? `${low} low-risk alert${low === 1 ? "" : "s"}` : "Normal activity"
        );

        setText("incidentNavCount", incidents.length, "0");

        setText(
            "navAlertCount",
            total,
            "0"
        );

        const explicitEndpointTotal =
            numberOrNull(data?.endpoints?.total) ??
            numberOrNull(data?.system?.endpoints);

        const endpointTotal =
            explicitEndpointTotal !== null
                ? explicitEndpointTotal
                : (data?.runtime?.running === true ? 1 : 0);

        setText("endpointCount", endpointTotal, "0");
        setText("endpointNavCount", endpointTotal, "0");

        setText(
            "endpointMeta",
            endpointTotal > 0
                ? `${endpointTotal} Active`
                : "No endpoints"
        );

        setText(
            "notificationCount",
            total,
            "0"
        );
    }

    function renderProcesses(processes) {
        const container = $("processList");
        if (!container) return;

        if (!Array.isArray(processes) || processes.length === 0) {
            container.innerHTML =
                '<div class="cd-empty-state">No process telemetry available</div>';
            return;
        }

const sorted = [...processes]
    .filter(
        (p) =>
            p &&
            typeof p === "object" &&
            Number(p.pid) !== 0 &&
            String(p.name || "").toLowerCase() !==
                "system idle process"
    )
    .sort(
        (a, b) =>
            (numberOrNull(b.cpu_percent) ?? -1) -
            (numberOrNull(a.cpu_percent) ?? -1)
    )
    .slice(0, 5);
     
     
     
     
            const maxCpu = Math.max(
            1,
            ...sorted.map(
                (p) => numberOrNull(p.cpu_percent) ?? 0
            )
        );

        container.innerHTML = sorted.map((process) => {
            const name = escapeHTML(
                process.name ?? `PID ${process.pid ?? "-"}`
            );

            const cpu = numberOrNull(process.cpu_percent);
            const memory = numberOrNull(process.memory_percent);

            const width = cpu === null
                ? 0
                : Math.max(
                    2,
                    Math.min(100, (cpu / maxCpu) * 100)
                );

            return `
                <div class="cd-process-row">
                    <div class="cd-process-icon">${processIcon(process.name)}</div>
                    <div class="cd-process-body">
                        <div class="cd-process-top">
                            <strong>${name}</strong>
                            <span>
                                CPU ${cpu === null ? "--" : cpu.toFixed(1)}%
                                <small>MEM ${memory === null ? "--" : memory.toFixed(1)}%</small>
                            </span>
                        </div>
                        <div class="cd-process-bar">
                            <span style="width:${width}%"></span>
                        </div>
                    </div>
                </div>
            `;
        }).join("");
    }

    function processIcon(name) {
        const value = String(name || "").toLowerCase();

        if (value.includes("python")) return "🐍";
        if (value.includes("chrome")) return "🌐";
        if (value.includes("explorer")) return "📁";
        if (value.includes("code")) return "⌘";
        if (value.includes("defender")) return "🛡";
        return "▣";
    }

    function renderEndpointHealth(data) {
        const freshness = data?.runtime_freshness || {};
        const runtime = data?.runtime || {};
        const healthy =
            freshness.available === true &&
            freshness.stale !== true &&
            runtime.running !== false;

        const percent = healthy ? 100 : 0;

        setText("healthPercent", `${percent}%`);
        setText("healthLabel", healthy ? "HEALTHY" : "OFFLINE");

        setText(
            "lastCheck",
            freshness.available
                ? formatTime(
                    (Date.now() / 1000) -
                    (numberOrNull(freshness.age_seconds) ?? 0)
                )
                : "--:--:--"
        );

        const checks = document.querySelectorAll(
            ".cd-health-checks b"
        );

        checks.forEach((check) => {
            check.textContent = healthy ? "✓" : "!";
            check.classList.toggle("health-failed", !healthy);
        });
    }

function renderUptime(data) {
    const runtime = data?.runtime || {};

    let startedAt = numberOrNull(
        runtime.started_at
    );

    // ---------------------------------------------------------
    // No authoritative start time
    // ---------------------------------------------------------
    if (startedAt === null) {

        if (
            lastKnownUptimeSeconds !== null
        ) {
            renderUptimeSeconds(
                lastKnownUptimeSeconds
            );
        } else {
            setText(
                "uptime",
                "--:--:--"
            );
        }

        return;
    }

    // ---------------------------------------------------------
    // Runtime timestamp is Unix seconds.
    // ---------------------------------------------------------
    if (startedAt < 100000000000) {
        startedAt *= 1000;
    }

    // ---------------------------------------------------------
    // AGENT RUNNING
    // ---------------------------------------------------------
    if (runtime.running === true) {

        const elapsedSeconds = Math.max(
            0,
            Math.floor(
                (Date.now() - startedAt) / 1000
            )
        );

        lastKnownUptimeSeconds =
            elapsedSeconds;

        renderUptimeSeconds(
            elapsedSeconds
        );

        return;
    }

    // ---------------------------------------------------------
    // AGENT STOPPED
    //
    // Never reset uptime to zero.
    // Keep the last authoritative observed uptime.
    // ---------------------------------------------------------
    if (
        lastKnownUptimeSeconds !== null
    ) {
        renderUptimeSeconds(
            lastKnownUptimeSeconds
        );
    } else {

        // If this browser opened after shutdown,
        // use the last completed cycle as the
        // best available runtime endpoint.
        const completedAt =
            numberOrNull(
                runtime.last_cycle_completed
            );

        if (
            completedAt !== null
        ) {

            let completedMs =
                completedAt;

            if (
                completedMs <
                100000000000
            ) {
                completedMs *= 1000;
            }

            const elapsedSeconds =
                Math.max(
                    0,
                    Math.floor(
                        (
                            completedMs -
                            startedAt
                        ) / 1000
                    )
                );

            lastKnownUptimeSeconds =
                elapsedSeconds;

            renderUptimeSeconds(
                elapsedSeconds
            );

        } else {

            setText(
                "uptime",
                "--:--:--"
            );
        }
    }
}


function renderUptimeSeconds(
    elapsedSeconds
) {

    const safeSeconds = Math.max(
        0,
        Math.floor(
            Number(
                elapsedSeconds
            ) || 0
        )
    );

    const days = Math.floor(
        safeSeconds / 86400
    );

    const hours = Math.floor(
        (safeSeconds % 86400) / 3600
    );

    const minutes = Math.floor(
        (safeSeconds % 3600) / 60
    );

    const seconds =
        safeSeconds % 60;

    const clock =
        `${String(hours).padStart(2, "0")}:` +
        `${String(minutes).padStart(2, "0")}:` +
        `${String(seconds).padStart(2, "0")}`;

    setText(
        "uptime",
        days > 0
            ? `${days}d ${clock}`
            : clock
    );
}
    function renderAlerts(data) {
        const container = $("latestAlerts");
        if (!container) return;

        const incidents = Array.isArray(data?.incidents)
            ? data.incidents
            : [];

        const events = Array.isArray(data?.events)
            ? data.events
            : [];

        const source = incidents.length
            ? incidents
            : events;

        if (!source.length) {
            container.innerHTML =
                '<div class="cd-empty-state">No alerts available</div>';
            return;
        }

        container.innerHTML = source
            .slice(0, 5)
            .map((item) => {
                const level = eventLevel(item);
                const cls = severityClass(level);
                const title = escapeHTML(
                    item.event_type ??
                    item.name ??
                    item.type ??
                    "Security Event"
                );

                const detail = escapeHTML(
                    item.details ??
                    item.message ??
                    item.description ??
                    item.reason ??
                    (
                        item.risk_score !== undefined
                            ? `Risk score: ${item.risk_score}`
                            : "-"
                    )
                );

                return `
                    <div class="cd-alert-row">
                        <div class="cd-alert-severity ${cls}">
                            <i></i>${escapeHTML(level)}
                        </div>
                        <div class="cd-alert-body">
                            <strong>${title}</strong>
                            <span>${detail}</span>
                        </div>
                        <time>${formatTime(eventTimestamp(item))}</time>
                    </div>
                `;
            })
            .join("");
    }

    function getEventsFromData(events) {
        if (!Array.isArray(events)) return [];

        return events
            .filter(
                (event) =>
                    event &&
                    typeof event === "object"
            )
            .sort(
                (a, b) =>
                    (eventTimestamp(b) ?? 0) -
                    (eventTimestamp(a) ?? 0)
            );
    }

    function renderEvents(events) {
        latestEvents = getEventsFromData(events);

        const table = $("events");
        if (!table) return;

        const totalPages = Math.max(
            1,
            Math.ceil(latestEvents.length / EVENT_PAGE_SIZE)
        );

        eventPage = Math.min(
            Math.max(1, eventPage),
            totalPages
        );

        const start =
            (eventPage - 1) * EVENT_PAGE_SIZE;

        const visible =
            latestEvents.slice(
                start,
                start + EVENT_PAGE_SIZE
            );

        if (!visible.length) {
            table.innerHTML = `
                <tr>
                    <td colspan="5" class="cd-empty-cell">
                        No events available
                    </td>
                </tr>
            `;
        } else {
            table.innerHTML = visible.map((event) => {
                const level = eventLevel(event);
                const cls = severityClass(level);

                return `
                    <tr>
                        <td>${formatTime(eventTimestamp(event))}</td>
                        <td>${escapeHTML(eventName(event))}</td>
                        <td title="${escapeHTML(eventDetails(event))}">
                            ${escapeHTML(eventDetails(event))}
                        </td>
                        <td class="level-${cls}">
                            ${escapeHTML(level)}
                        </td>
                        <td>${escapeHTML(eventSource(event))}</td>
                    </tr>
                `;
            }).join("");
        }

        setText(
            "eventCount",
            `${latestEvents.length} events`,
            "0 events"
        );

        renderPagination(
            latestEvents.length,
            totalPages
        );
    }

    function renderPagination(total, totalPages) {
        let footer = document.querySelector(
            ".cd-event-pagination"
        );

        if (!footer) {
            const panel = document.querySelector(
                ".cd-events"
            );

            if (!panel) return;

            footer = document.createElement("div");
            footer.className = "cd-event-pagination";
            panel.appendChild(footer);
        }

        if (total === 0) {
            footer.innerHTML = "";
            return;
        }

        const start =
            (eventPage - 1) * EVENT_PAGE_SIZE + 1;

        const end =
            Math.min(
                total,
                eventPage * EVENT_PAGE_SIZE
            );

        footer.innerHTML = `
            <span class="cd-page-info">
                Showing ${start}-${end} of ${total}
            </span>

            <div class="cd-page-controls">
                <button
                    type="button"
                    data-page-action="prev"
                    ${eventPage <= 1 ? "disabled" : ""}
                >‹</button>

                ${Array.from(
                    { length: totalPages },
                    (_, index) => {
                        const page = index + 1;
                        return `
                            <button
                                type="button"
                                data-page="${page}"
                                class="${page === eventPage ? "active" : ""}"
                            >${page}</button>
                        `;
                    }
                ).join("")}

                <button
                    type="button"
                    data-page-action="next"
                    ${eventPage >= totalPages ? "disabled" : ""}
                >›</button>
            </div>

            <span class="cd-page-size">
                ${EVENT_PAGE_SIZE}/page
            </span>
        `;

        footer
            .querySelectorAll("button[data-page]")
            .forEach((button) => {
                button.addEventListener(
                    "click",
                    () => {
                        eventPage =
                            Number(button.dataset.page) || 1;
                        renderEvents(latestEvents);
                    }
                );
            });

        const prev = footer.querySelector(
            '[data-page-action="prev"]'
        );

        const next = footer.querySelector(
            '[data-page-action="next"]'
        );

        prev?.addEventListener("click", () => {
            if (eventPage > 1) {
                eventPage -= 1;
                renderEvents(latestEvents);
            }
        });

        next?.addEventListener("click", () => {
            if (eventPage < totalPages) {
                eventPage += 1;
                renderEvents(latestEvents);
            }
        });
    }

    function updateAlertXAxis(nowMs) {
        const labels =
            document.querySelectorAll(
                "#alertXAxis span"
            );

        if (!labels.length) return;

        const now =
            new Date(nowMs);

        labels.forEach(
            (label, index) => {
                const hoursAgo =
                    24 - (index * 4);

                const point =
                    new Date(
                        now.getTime() -
                        hoursAgo *
                        3600000
                    );

                label.textContent =
                    point.toLocaleTimeString(
                        [],
                        {
                            hour: "2-digit",
                            minute: "2-digit"
                        }
                    );
            }
        );

        labels[
            labels.length - 1
        ].textContent =
            now.toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit"
                }
            );
    }

    function drawAlertsChart(events) {
        const canvas = $("alertsChart");
        if (!canvas) return;

        const rect = canvas.getBoundingClientRect();
        const width = Math.max(
            300,
            Math.floor(rect.width || canvas.clientWidth || 600)
        );
        const height = Math.max(
            110,
            Math.floor(rect.height || canvas.clientHeight || 150)
        );

        const dpr = window.devicePixelRatio || 1;

        canvas.width = width * dpr;
        canvas.height = height * dpr;

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);

        const now = Date.now();

        updateAlertXAxis(now);

        const buckets = Array.from(
            { length: 24 },
            () => ({
                high: 0,
                medium: 0,
                low: 0
            })
        );

        for (const event of events || []) {
            const timestamp = eventTimestamp(event);
            if (timestamp === null) continue;

            const ms =
                timestamp < 10000000000
                    ? timestamp * 1000
                    : timestamp;

            const ageHours =
                (now - ms) / 3600000;

            if (ageHours < 0 || ageHours >= 24) continue;

            const index =
                23 - Math.floor(ageHours);

            const level =
                severityClass(eventLevel(event));

            if (level === "high") buckets[index].high += 1;
            else if (level === "medium") buckets[index].medium += 1;
            else if (level === "low") buckets[index].low += 1;
        }

        const series = {
            high: buckets.map((b) => b.high),
            medium: buckets.map((b) => b.medium),
            low: buckets.map((b) => b.low)
        };

        const maxObserved = Math.max(
            1,
            ...series.high,
            ...series.medium,
            ...series.low
        );

        const maxY = Math.max(
            10,
            Math.ceil(maxObserved / 10) * 10
        );

        const pad = {
            left: 32,
            right: 8,
            top: 8,
            bottom: 20
        };

        const chartW =
            width - pad.left - pad.right;

        const chartH =
            height - pad.top - pad.bottom;

        for (let tick = 0; tick <= 3; tick++) {
            const value =
                (maxY / 3) * tick;

            const y =
                pad.top +
                chartH -
                (value / maxY) * chartH;

            ctx.strokeStyle =
                "rgba(61, 89, 103, .30)";
            ctx.lineWidth = 1;

            ctx.beginPath();
            ctx.moveTo(pad.left, y);
            ctx.lineTo(width - pad.right, y);
            ctx.stroke();
        }

        const drawSeries = (values, stroke, fill) => {
            const points = values.map(
                (value, index) => ({
                    x:
                        pad.left +
                        (chartW / (values.length - 1)) *
                        index,
                    y:
                        pad.top +
                        chartH -
                        (value / maxY) * chartH
                })
            );

            ctx.beginPath();
            points.forEach((p, index) => {
                if (index === 0) ctx.moveTo(p.x, p.y);
                else ctx.lineTo(p.x, p.y);
            });

            ctx.lineTo(
                points[points.length - 1].x,
                pad.top + chartH
            );
            ctx.lineTo(
                points[0].x,
                pad.top + chartH
            );
            ctx.closePath();

            ctx.fillStyle = fill;
            ctx.fill();

            ctx.beginPath();

            points.forEach((p, index) => {
                if (index === 0) ctx.moveTo(p.x, p.y);
                else ctx.lineTo(p.x, p.y);
            });

            ctx.strokeStyle = stroke;
            ctx.lineWidth = 1.7;
            ctx.stroke();
        };

        drawSeries(
            series.low,
            "#00df91",
            "rgba(0,223,145,.10)"
        );

        drawSeries(
            series.medium,
            "#ffad1c",
            "rgba(255,173,28,.09)"
        );

        drawSeries(
            series.high,
            "#ff4054",
            "rgba(255,64,84,.10)"
        );
    }

    function updateClock() {
        const now = new Date();

        setText(
            "clock",
            now.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            })
        );

        setText(
            "date",
            now.toLocaleDateString([], {
                year: "numeric",
                month: "2-digit",
                day: "2-digit"
            })
        );
    }

    async function refreshDashboard() {
        if (refreshInFlight) return;

        refreshInFlight = true;

        try {
            const response = await fetch(
                "/api/status",
                {
                    cache: "no-store",
                    credentials: "same-origin"
                }
            );

            if (response.status === 401) {
                window.location.href = "/login";
                return;
            }

            if (!response.ok) {
                throw new Error(
                    `HTTP ${response.status}`
                );
            }

            const data = await response.json();

            renderRuntime(data);

        } catch (error) {
            setText("systemStatus", "NO SIGNAL");
            setText("agentStatus", "OFFLINE");
            setText("healthPercent", "0%");
            setText("healthLabel", "OFFLINE");
            setText("footerStatus", "NO SIGNAL");

            document.documentElement.dataset.runtimeStatus =
                "no-signal";

            console.error(
                "CyberDefender dashboard refresh failure:",
                error
            );
        } finally {
            refreshInFlight = false;
        }
    }


    // =========================================================
    // SEE ALL / READ-ONLY DETAIL MODALS
    // =========================================================

    function ensureDetailModal() {
        let modal = document.getElementById("cdDetailModal");
        if (modal) return modal;

        modal = document.createElement("div");
        modal.id = "cdDetailModal";
        modal.className = "cd-detail-modal";
        modal.setAttribute("aria-hidden", "true");

        modal.innerHTML = `
            <div class="cd-detail-backdrop" data-modal-close></div>
            <section class="cd-detail-dialog"
                     role="dialog"
                     aria-modal="true"
                     aria-labelledby="cdDetailModalTitle">
                <header class="cd-detail-header">
                    <div>
                        <div class="cd-detail-kicker">CYBERDEFENDER MONITOR</div>
                        <h2 id="cdDetailModalTitle">Details</h2>
                    </div>
                    <button type="button"
                            class="cd-detail-close"
                            aria-label="Close"
                            data-modal-close>×</button>
                </header>
                <div class="cd-detail-body" id="cdDetailModalBody"></div>
            </section>
        `;

        document.body.appendChild(modal);

        modal.addEventListener("click", (event) => {
            if (event.target.closest("[data-modal-close]")) {
                closeDetailModal();
            }
        });

        return modal;
    }

    function openDetailModal(title, bodyHTML) {
        const modal = ensureDetailModal();
        const titleNode = document.getElementById("cdDetailModalTitle");
        const bodyNode = document.getElementById("cdDetailModalBody");

        if (titleNode) titleNode.textContent = title;
        if (bodyNode) bodyNode.innerHTML = bodyHTML;

        modal.classList.add("is-open");
        modal.setAttribute("aria-hidden", "false");
        document.body.classList.add("cd-modal-open");

        const closeButton = modal.querySelector(".cd-detail-close");
        if (closeButton) closeButton.focus();
    }

    function closeDetailModal() {
        const modal = document.getElementById("cdDetailModal");
        if (!modal) return;

        modal.classList.remove("is-open");
        modal.setAttribute("aria-hidden", "true");
        document.body.classList.remove("cd-modal-open");
    }

    function modalEmpty(message) {
        return `<div class="cd-modal-empty">${escapeHTML(message)}</div>`;
    }

    function modalTable(headers, rows) {
        if (!rows.length) return modalEmpty("No data available.");

        return `
            <div class="cd-modal-table-wrap">
                <table class="cd-modal-table">
                    <thead>
                        <tr>
                            ${headers.map((h) => `<th>${escapeHTML(h)}</th>`).join("")}
                        </tr>
                    </thead>
                    <tbody>
                        ${rows.join("")}
                    </tbody>
                </table>
            </div>
        `;
    }

    function openAllAlerts() {
        const incidents = Array.isArray(latestData?.incidents)
            ? latestData.incidents
            : [];

        const events = Array.isArray(latestData?.events)
            ? latestData.events
            : [];

        const source = incidents.length ? incidents : events;

        const rows = source.map((item) => {
            const severity = String(
                item?.severity ||
                item?.level ||
                "INFO"
            ).toUpperCase();

            const risk = item?.risk_score ?? item?.risk ?? "--";
            const id =
                item?.incident_id ||
                item?.id ||
                item?.event_id ||
                "--";
            const key =
                item?.correlation_key ||
                item?.key ||
                item?.type ||
                "--";
            const count =
                item?.event_count ??
                item?.events_count ??
                "--";
            const time = formatEventTime(item);

            return `
                <tr>
                    <td>${escapeHTML(time)}</td>
                    <td><span class="cd-modal-severity ${severity.toLowerCase()}">${escapeHTML(severity)}</span></td>
                    <td>${escapeHTML(id)}</td>
                    <td>${escapeHTML(key)}</td>
                    <td>${escapeHTML(String(risk))}</td>
                    <td>${escapeHTML(String(count))}</td>
                </tr>
            `;
        });

        openDetailModal(
            "All Alerts & Incidents",
            `
                <div class="cd-modal-summary">
                    <span>${source.length} records</span>
                    <span>Read-only forensic view</span>
                </div>
                ${modalTable(
                    ["TIME", "LEVEL", "ID", "TYPE / KEY", "RISK", "EVENTS"],
                    rows
                )}
            `
        );
    }

    function openAllProcesses() {
        const observation = latestData?.observation || {};
        const processes = Array.isArray(observation?.top_processes)
            ? observation.top_processes
            : [];

        const sorted = [...processes]
            .filter((p) => p && typeof p === "object")
            .sort(
                (a, b) =>
                    (numberOrNull(b.cpu_percent) ?? -1) -
                    (numberOrNull(a.cpu_percent) ?? -1)
            );

        const rows = sorted.map((process) => `
            <tr>
                <td>${escapeHTML(String(process.pid ?? "--"))}</td>
                <td>${escapeHTML(String(process.name ?? "--"))}</td>
                <td>${escapeHTML(
                    numberOrNull(process.cpu_percent) === null
                        ? "--"
                        : `${numberOrNull(process.cpu_percent).toFixed(1)}%`
                )}</td>
                <td>${escapeHTML(
                    numberOrNull(process.memory_percent) === null
                        ? "--"
                        : `${numberOrNull(process.memory_percent).toFixed(1)}%`
                )}</td>
                <td>${escapeHTML(String(
                    process.parent_pid ??
                    process.ppid ??
                    "--"
                ))}</td>
            </tr>
        `);

        openDetailModal(
            "All Processes",
            `
                <div class="cd-modal-summary">
                    <span>${sorted.length} processes</span>
                    <span>Sorted by CPU usage</span>
                </div>
                ${modalTable(
                    ["PID", "PROCESS", "CPU", "MEMORY", "PARENT PID"],
                    rows
                )}
            `
        );
    }

    function openAllEvents() {
        const events = Array.isArray(latestData?.events)
            ? latestData.events
            : [];

        const rows = events.map((event) => {
            const level = String(
                event?.severity ||
                event?.level ||
                "INFO"
            ).toUpperCase();

            return `
                <tr>
                    <td>${escapeHTML(formatEventTime(event))}</td>
                    <td>${escapeHTML(
                        String(
                            event?.event_type ||
                            event?.type ||
                            event?.name ||
                            "--"
                        )
                    )}</td>
                    <td>${escapeHTML(
                        String(
                            event?.message ||
                            event?.details ||
                            event?.description ||
                            "--"
                        )
                    )}</td>
                    <td><span class="cd-modal-severity ${level.toLowerCase()}">${escapeHTML(level)}</span></td>
                    <td>${escapeHTML(
                        String(
                            event?.source ||
                            event?.component ||
                            "--"
                        )
                    )}</td>
                </tr>
            `;
        });

        openDetailModal(
            "All Security Events",
            `
                <div class="cd-modal-summary">
                    <span>${events.length} events in current API snapshot</span>
                    <span>Read-only telemetry</span>
                </div>
                ${modalTable(
                    ["TIME", "EVENT", "DETAILS", "LEVEL", "SOURCE"],
                    rows
                )}
            `
        );
    }

    function formatEventTime(event) {
        // Use the same timestamp normalization as the main Event Log.
        // This prevents "--:--:--" when the backend uses event_timestamp,
        // event_time, or generated_at instead of timestamp.
        const raw =
            event?.timestamp ??
            event?.event_timestamp ??
            event?.event_time ??
            event?.created_at ??
            event?.generated_at ??
            event?.time ??
            event?.ts;

        const parsedSeconds = parseTimestamp(raw);
        if (parsedSeconds !== null) {
            return formatTime(parsedSeconds);
        }

        if (typeof raw === "string" && raw.trim()) {
            return raw.trim();
        }

        return "--:--:--";
    }

    function handleSeeAllButton(button) {
        if (!button) return;

        const panel = button.closest(".cd-panel");
        const panelId = String(panel?.id || "").toLowerCase();
        const panelClass = String(panel?.className || "").toLowerCase();
        const buttonText = String(button.textContent || "").trim().toLowerCase();

        // Explicit IDs are preferred. Class/text fallbacks keep See All
        // working if the HTML layout is changed without touching this file.
        if (
            panelId === "latest" ||
            panelClass.includes("latest") ||
            panelClass.includes("alert")
        ) {
            openAllAlerts();
            return;
        }

        if (
            panelId === "processes" ||
            panelClass.includes("process")
        ) {
            openAllProcesses();
            return;
        }

        if (
            panelId === "logs" ||
            panelClass.includes("log") ||
            panelClass.includes("event") ||
            buttonText === "see all events"
        ) {
            openAllEvents();
        }
    }

    function bindSeeAllButtons() {
        document.querySelectorAll(".cd-see-all").forEach((button) => {
            if (button.dataset.bound === "true") return;

            button.dataset.bound = "true";
            button.setAttribute("role", "button");
            button.setAttribute("tabindex", "0");

            button.addEventListener("click", () => {
                handleSeeAllButton(button);
            });

            button.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    handleSeeAllButton(button);
                }
            });
        });
    }

    // Delegated fallback for buttons recreated by another UI script.
    document.addEventListener("click", (event) => {
        const button = event.target.closest?.(".cd-see-all");
        if (!button || button.dataset.bound === "true") return;
        handleSeeAllButton(button);
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeDetailModal();
        }
    });

    window.addEventListener(
        "resize",
        () => {
            drawResourceCharts();
            drawAlertsChart(latestEvents);
        }
    );

    updateClock();

    setInterval(
        updateClock,
        1000
    );

    setInterval(
        () => renderUptime(window.__cdRuntime || {}),
        1000
    );

    bindSeeAllButtons();

    refreshDashboard();

    setInterval(
        refreshDashboard,
        REFRESH_MS
    );
})();
