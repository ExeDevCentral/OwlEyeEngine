// ==========================================================================
// OwlEyeEngine v4.0 Enterprise - Client Dashboard Controller
// Retro Linux Workstation Aesthetic · Slot-Motion Easing · Human-Friendly UX
// ==========================================================================

let allProcesses = [];
let wsLiveConnection = null;
let currentKernelFilter = "ALL";
let kernelEventsCache = [];
let eventSourceTelemetry = null;
let lastKnownValues = {};

document.addEventListener("DOMContentLoaded", () => {
    // Reloj TTY en tiempo real
    updateTTYClock();
    setInterval(updateTTYClock, 1000);

    // Cargas iniciales
    fetchStatus();
    fetchThreats();
    fetchKernelStatus();
    fetchKernelEvents();
    fetchMitreMatrix();
    fetchProcesses();
    fetchConnections();
    fetchLogs();

    // Actualizaciones periódicas con suavizado
    setInterval(fetchStatus, 3000);
    setInterval(fetchThreats, 5000);
    setInterval(fetchKernelStatus, 3000);

    // Conectar canal de telemetría en vivo (SSE)
    initTelemetryStream();
});

// --- RELOJ TTY LINUX ---
function updateTTYClock() {
    const el = document.getElementById("ttyClock");
    if (!el) return;
    const now = new Date();
    el.innerText = now.toTimeString().split(' ')[0] + " UTC";
}

// --- SLOT MOTION PARA NÚMEROS Y VALORES ---
function updateSlotValue(elementId, newValue) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const currentText = el.innerText;
    if (currentText !== String(newValue)) {
        el.classList.remove("slot-rolling");
        // Forzar reflow para reiniciar la animación
        void el.offsetWidth;
        el.classList.add("slot-rolling");
        el.innerText = newValue;
    }
}

// --- NAVEGACIÓN POR PESTAÑAS (TRANSICIONES SUAVES) ---
function switchTab(tabId) {
    document.querySelectorAll(".nav-tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".station-tab-content").forEach(content => content.classList.remove("active"));

    const btn = Array.from(document.querySelectorAll(".nav-tab-btn")).find(b => b.getAttribute("onclick")?.includes(tabId));
    if (btn) btn.classList.add("active");

    const tab = document.getElementById(`tab-${tabId}`);
    if (tab) tab.classList.add("active");

    if (tabId === 'kernel') {
        fetchKernelStatus();
        fetchKernelEvents();
        fetchMitreMatrix();
    } else if (tabId === 'processes') {
        fetchProcesses();
    } else if (tabId === 'network') {
        fetchConnections();
    } else if (tabId === 'logs') {
        fetchLogs();
    }
}

// --- ESTADO GENERAL & KERNEL TELEMETRY ---
async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();

        // CPU & RAM con Slot Motion
        updateSlotValue("cpuVal", `${data.system.cpu_percent}%`);
        document.getElementById("cpuBar").style.width = `${data.system.cpu_percent}%`;

        updateSlotValue("memVal", `${data.system.memory_used_mb} MB`);
        document.getElementById("memBar").style.width = `${data.system.memory_percent}%`;
        const memFootnote = document.getElementById("memPercentFootnote");
        if (memFootnote) {
            memFootnote.innerText = `Total: ${data.system.memory_total_mb} MB (${data.system.memory_percent}% en uso)`;
        }

        // Telemetría de Kernel
        const k = data.kernel_telemetry || {};
        const lat = k.avg_latency_us !== undefined ? k.avg_latency_us : 8.8;
        updateSlotValue("kernelLatencyVal", `${lat} μs`);

        const probeTypeEl = document.getElementById("kernelProbeTypeVal");
        if (probeTypeEl) {
            probeTypeEl.innerText = k.probe_type || "Sonda eBPF Operativa";
        }

        // Amenazas y Uptime
        updateSlotValue("threatsCountVal", data.threat_summary.total_threats);
        document.getElementById("mitigatedVal").textContent = `${data.active_defense.terminated_pids_count} mitigadas`;

        updateSlotValue("uptimeVal", data.uptime);
        document.getElementById("statusVal").innerText = data.status;

        // Badge de sonda activa en la cabecera
        const probeName = k.probe_type || "eBPF KERNEL PROBE";
        document.getElementById("probeBadgeText").innerText = probeName.toUpperCase();

        if (data.demo_mode) {
            const demoBadge = document.getElementById("demoBadge");
            if (demoBadge) demoBadge.style.display = "inline-block";
        }

        // Estado del interruptor de defensa
        const toggle = document.getElementById("autoDefenseToggle");
        const badge = document.getElementById("defenseStatusBadge");
        const statusLabel = document.getElementById("defenseStatusLabel");

        toggle.checked = data.active_defense.auto_defense;

        if (data.active_defense.auto_defense) {
            badge.className = "status-badge badge-success";
            badge.innerText = "ACTIVA";
            statusLabel.innerText = "Auto-Kill & Bloqueo";
            statusLabel.style.color = "var(--phosphor-green)";
        } else {
            badge.className = "status-badge badge-warning";
            badge.innerText = "ALERTA";
            statusLabel.innerText = "Sólo Alertas";
            statusLabel.style.color = "var(--phosphor-amber)";
        }

        // Actualizar banner amigable para humanos
        updateHumanBanner(data);

        // Lista de IPs bloqueadas
        renderBlockedIPs(data.active_defense.blocked_ips);

        // Conectar WebSocket si está inactivo
        if (!wsLiveConnection || wsLiveConnection.readyState !== WebSocket.OPEN) {
            tryLiveWebSocket();
        }
    } catch (err) {
        document.getElementById("statusVal").innerText = "DESCONECTADO";
        document.getElementById("statusVal").style.color = "var(--phosphor-rose)";
    }
}

// Actualiza el banner intuitivo superior
function updateHumanBanner(data) {
    const heading = document.getElementById("bannerHeading");
    const explanation = document.getElementById("bannerExplanation");
    const banner = document.getElementById("humanBanner");
    if (!heading || !explanation || !banner) return;

    const isAutoDefense = data.active_defense.auto_defense;
    const threatsCount = data.threat_summary.total_threats;

    if (isAutoDefense) {
        heading.innerText = "SISTEMA CUSTODIADO Y PROTEGIDO (DEFENSA AUTOMÁTICA ACTIVA)";
        explanation.innerText = `OwlEyeEngine está custodiando el kernel en tiempo real. Cualquier proceso ejecutado desde directorios sospechosos o escaneo de puertos será mitigado de forma automática e inmediata. (${threatsCount} amenazas registradas en la sesión).`;
        banner.style.borderColor = "rgba(16, 185, 129, 0.35)";
    } else {
        heading.innerText = "MODO OBSERVACIÓN: SÓLO ALERTAS REGISTRADAS";
        explanation.innerText = "El motor está interceptando llamadas al sistema y puntuando anomalías, pero no intervendrá sobre procesos ni bloqueará IPs en el cortafuegos hasta que actives la 'Defensa Automática' en la esquina superior derecha.";
        banner.style.borderColor = "rgba(255, 180, 84, 0.35)";
    }
}

// --- KERNEL TELEMETRY HUD (Pestaña 2) ---
async function fetchKernelStatus() {
    try {
        const res = await fetch("/api/kernel/status");
        const data = await res.json();
        const caps = data.capabilities || {};
        const m = data.metrics || {};

        const probeName = caps.active_probe_type || "Linux eBPF (sys_enter_execve)";
        document.getElementById("hudProbeName").innerText = probeName;
        updateSlotValue("hudSyscallRate", `${m.events_per_second || 0}/s`);
        updateSlotValue("hudLatencyVal", `${m.avg_interception_latency_us || 0} μs`);

        const usage = Math.round(((m.ring_buffer_size || 0) / (m.ring_buffer_capacity || 500)) * 100);
        updateSlotValue("hudRingBuffer", `${usage}%`);
    } catch (e) {}
}

// --- MATRIZ MITRE ATT&CK ---
async function fetchMitreMatrix() {
    try {
        const res = await fetch("/api/mitre/matrix");
        const data = await res.json();
        const regionalIndex = document.getElementById("mitreRegionalIndex");
        if (regionalIndex) {
            regionalIndex.innerText = `NIVEL REGIONAL: ${data.regional_threat_index || 'ELEVADO'}`;
        }

        const tactics = data.tactics || {};
        if (tactics["Execution (T1059)"]?.count > 0) {
            const el = document.getElementById("mitreExecStatus");
            if (el) {
                el.innerText = `ALERTA ACTIVA (${tactics["Execution (T1059)"].count})`;
                el.style.color = "var(--phosphor-rose)";
            }
        }
        if (tactics["Discovery (T1046)"]?.count > 0) {
            const el = document.getElementById("mitreDiscStatus");
            if (el) {
                el.innerText = `DETECTADO (${tactics["Discovery (T1046)"].count})`;
                el.style.color = "var(--phosphor-amber)";
            }
        }
    } catch (e) {}
}

// --- STREAM DE KERNEL EN VIVO & BUFFER ---
async function fetchKernelEvents() {
    try {
        const res = await fetch(`/api/kernel/events?limit=40`);
        const data = await res.json();
        kernelEventsCache = data.events || [];
        renderKernelEvents();
    } catch (e) {}
}

function filterKernelSubsystem(subsystem) {
    currentKernelFilter = subsystem;
    document.querySelectorAll(".filter-tag").forEach(p => {
        p.classList.toggle("active", p.innerText === (subsystem === "ALL" ? "TODOS" : subsystem));
    });
    renderKernelEvents();
}

function renderKernelEvents() {
    const term = document.getElementById("kernelStreamTerminal");
    if (!term) return;

    const filtered = currentKernelFilter === "ALL"
        ? kernelEventsCache
        : kernelEventsCache.filter(e => e.subsystem === currentKernelFilter);

    if (!filtered.length) {
        term.innerHTML = `<div class="txt-dim">No hay eventos de kernel [${currentKernelFilter}] en el buffer circular.</div>`;
        return;
    }

    term.innerHTML = filtered.map(e => {
        const subClass = e.subsystem === 'PROCESS' ? 'txt-cyan' : (e.subsystem === 'NETWORK' ? 'txt-green' : (e.subsystem === 'MEMORY' ? 'txt-purple' : 'txt-amber'));
        const sevClass = (e.severity === 'CRITICAL' || e.severity === 'HIGH') ? 'txt-rose' : 'txt-dim';
        const argStr = Object.entries(e.args || {}).map(([k, v]) => `${k}=${v}`).join(" ");

        return `<div class="log-row">
            <span class="txt-dim">[${e.timestamp.split(' ')[1]}]</span>
            <span class="${subClass}">[${e.subsystem}:${e.syscall}]</span>
            <strong>PID:${e.pid}</strong> (${e.comm})
            <span class="txt-purple">${e.latency_us}μs</span>
            <span class="${sevClass}">[${e.severity}]</span>
            <span class="txt-dim">${argStr}</span>
        </div>`;
    }).join("");

    term.scrollTop = term.scrollHeight;
}

// Conexión SSE para transmisión de eventos en vivo y ticker
function initTelemetryStream() {
    if (typeof EventSource === "undefined") return;
    try {
        eventSourceTelemetry = new EventSource("/api/telemetry/stream");
        eventSourceTelemetry.onmessage = (event) => {
            try {
                const ev = JSON.parse(event.data);
                kernelEventsCache.push(ev);
                if (kernelEventsCache.length > 100) kernelEventsCache.shift();
                renderKernelEvents();
                updateLiveTicker(ev);
            } catch (err) {}
        };
        eventSourceTelemetry.onerror = () => {
            if (eventSourceTelemetry) eventSourceTelemetry.close();
        };
    } catch (e) {}
}

// Actualiza la cinta superior de noticias de syscalls
function updateLiveTicker(ev) {
    const ticker = document.getElementById("tickerContent");
    if (!ticker) return;
    ticker.innerHTML = `<span class="ticker-item">
        <span class="ticker-sub">[${ev.subsystem || 'SYS'}]</span>
        <strong>${ev.syscall || 'sys_call'}</strong> (${ev.comm || 'proc'}) ·
        PID: ${ev.pid} · Latencia: <span style="color:var(--phosphor-purple);font-weight:700;">${ev.latency_us}μs</span> ·
        MITRE: ${ev.mitre?.tactic || 'General'}
    </span>`;
}

// --- AMENAZAS & HISTORIAL (Pestaña 1) ---
async function fetchThreats() {
    try {
        const res = await fetch("/api/threats");
        const data = await res.json();
        const tbody = document.getElementById("threatsTableBody");
        if (!tbody) return;

        if (!data.threats || data.threats.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="loading-cell">No se han registrado anomalías en esta sesión. El sistema está limpio.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.threats.map(t => {
            const sev = t.severity;
            const sevClass = (sev === 'HIGH' || sev === 'CRITICAL') ? 'badge-danger' : (sev === 'MEDIUM' ? 'badge-warning' : 'badge-info');
            const mitBadge = t.auto_mitigated
                ? '<span class="status-badge badge-success">MITIGADO</span>'
                : '<span class="status-badge badge-warning">ALERTA</span>';

            const mitre = t.mitre || {};
            const mitreBadge = `<span class="status-badge badge-purple" title="${mitre.name || ''}">${mitre.id || 'T1000'}</span>`;

            const targetIP = t.details?.ip || '';
            const targetPID = t.details?.pid || 0;

            let actionBtn = '-';
            if (targetIP) {
                actionBtn = `<button class="btn btn-sm btn-retro-danger" onclick="blockIP('${targetIP}')">Bloquear IP</button>`;
            } else if (targetPID) {
                actionBtn = `<button class="btn btn-sm btn-retro-danger" onclick="killPID(${targetPID})">Finalizar PID</button>`;
            }

            const detailStr = Object.entries(t.details || {}).map(([k,v]) => `${k}: ${v}`).join(' • ');

            return `<tr>
                <td>${t.timestamp}</td>
                <td><strong>${t.type}</strong></td>
                <td><span class="status-badge ${sevClass}">${sev}</span></td>
                <td style="font-weight:700; color:var(--phosphor-rose); font-family:var(--font-mono);">${t.score}/100</td>
                <td>${mitreBadge}</td>
                <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${detailStr}">${detailStr}</td>
                <td>${mitBadge}</td>
                <td>${actionBtn}</td>
            </tr>`;
        }).join("");
    } catch (err) {
        console.error("Error al obtener amenazas:", err);
    }
}

// --- PROCESOS (HTOP STYLE - Pestaña 3) ---
async function fetchProcesses() {
    try {
        const res = await fetch("/api/processes?limit=60");
        const data = await res.json();
        allProcesses = data.processes || [];
        renderProcesses(allProcesses);
    } catch (err) {
        console.error("Error al obtener procesos:", err);
    }
}

function renderProcesses(procs) {
    const tbody = document.getElementById("procTableBody");
    if (!tbody) return;

    if (!procs.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">No se encontraron procesos activos.</td></tr>`;
        return;
    }

    tbody.innerHTML = procs.map(p => {
        const cpuBar = `<div style="display:flex;align-items:center;gap:6px;">
            <span>${p.cpu}%</span>
            <div style="width:45px;height:4px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden;">
                <div style="height:100%;width:${Math.min(p.cpu, 100)}%;background:${p.cpu > 50 ? 'var(--phosphor-rose)' : p.cpu > 20 ? 'var(--phosphor-amber)' : 'var(--phosphor-green)'};"></div>
            </div>
        </div>`;

        return `<tr>
            <td><strong>${p.pid}</strong></td>
            <td><strong style="color:var(--phosphor-cyan);">${p.name}</strong></td>
            <td>${p.user}</td>
            <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${p.path}">${p.path}</td>
            <td>${cpuBar}</td>
            <td>${p.memory}%</td>
            <td><button class="btn btn-sm btn-retro-danger" onclick="killPID(${p.pid})">Finalizar PID</button></td>
        </tr>`;
    }).join("");
}

function filterProcesses() {
    const q = document.getElementById("procSearch").value.toLowerCase();
    const filtered = allProcesses.filter(p => p.name.toLowerCase().includes(q) || p.pid.toString().includes(q));
    renderProcesses(filtered);
}

// --- RED & SOCKETS (Pestaña 4) ---
async function fetchConnections() {
    try {
        const res = await fetch("/api/connections");
        const data = await res.json();
        const tbody = document.getElementById("netTableBody");
        if (!tbody) return;

        if (!data.connections || data.connections.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">No hay conexiones remotas activas en este instante.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.connections.map(c => {
            const statusClass = c.status === 'ESTABLISHED' ? 'badge-success' : (c.status === 'SYN_RECV' ? 'badge-danger' : 'badge-info');
            return `<tr>
                <td><span class="status-badge badge-info">${c.type}</span></td>
                <td>${c.local}</td>
                <td><strong style="color:var(--text-primary);">${c.remote}</strong></td>
                <td><span class="status-badge ${statusClass}">${c.status}</span></td>
                <td>${c.pid || '-'}</td>
                <td><button class="btn btn-sm btn-retro-danger" onclick="blockIP('${c.remote_ip}')">Bloquear IP</button></td>
            </tr>`;
        }).join("");
    } catch (err) {
        console.error("Error al obtener conexiones:", err);
    }
}

// --- ACCIONES DE DEFENSA (FIREWALL & KILL) ---
async function toggleAutoDefense(enabled) {
    try {
        await fetch("/api/defender/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled })
        });
        showWorkstationToast(enabled ? "🛡️ DEFENSA AUTOMÁTICA ACTIVADA: Auto-Kill & Firewall en guardia" : "⚠️ MODO ALERTA: Mitigaciones automáticas en pausa");
        fetchStatus();
    } catch (err) {
        console.error("Error en toggle defensa:", err);
    }
}

async function killPID(pid) {
    if (!confirm(`¿Confirmas la terminación del proceso PID ${pid}?`)) return;

    try {
        const res = await fetch("/api/actions/kill", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pid, reason: "Acción Manual desde Estación" })
        });
        const data = await res.json();
        showWorkstationToast(data.message);
        fetchProcesses();
        fetchStatus();
    } catch (err) {
        showWorkstationToast("Error al finalizar proceso: " + err, true);
    }
}

async function blockIP(ip) {
    if (!confirm(`¿Bloquear la dirección IP ${ip} en el cortafuegos del anfitrión?`)) return;

    try {
        const res = await fetch("/api/actions/block_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip, reason: "Bloqueo Manual desde Estación" })
        });
        const data = await res.json();
        showWorkstationToast(data.message);
        fetchStatus();
    } catch (err) {
        showWorkstationToast("Error al bloquear IP: " + err, true);
    }
}

async function unblockIP(ip) {
    try {
        const res = await fetch("/api/actions/unblock_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        showWorkstationToast(data.message);
        fetchStatus();
    } catch (err) {
        showWorkstationToast("Error al desbloquear IP: " + err, true);
    }
}

function manualBlockIP() {
    const input = document.getElementById("manualBlockIP");
    const ip = input ? input.value.trim() : "";
    if (ip) {
        blockIP(ip);
        if (input) input.value = "";
    }
}

function renderBlockedIPs(list) {
    const ul = document.getElementById("blockedIPsList");
    if (!ul) return;

    if (!list || list.length === 0) {
        ul.innerHTML = `<li class="empty-list-notice">No hay direcciones en cuarentena activa actualmente.</li>`;
        return;
    }
    ul.innerHTML = list.map(ip => `
        <li>
            <span>🔒 <strong>${ip}</strong></span>
            <button class="btn btn-sm btn-retro-secondary" onclick="unblockIP('${ip}')">Desbloquear</button>
        </li>
    `).join("");
}

// --- REGISTRO FORENSE (Pestaña 6) ---
async function fetchLogs() {
    try {
        const res = await fetch("/api/logs?limit=50");
        const data = await res.json();
        const term = document.getElementById("logsTerminal");
        if (!term) return;

        if (data.logs && data.logs.length > 0) {
            term.innerHTML = data.logs.map(l => `<div class="log-row">${escapeHtml(l)}</div>`).join("");
            term.scrollTop = term.scrollHeight;
        } else {
            term.innerHTML = `<div class="txt-dim">El registro está en espera de eventos...</div>`;
        }
    } catch (err) {
        console.error("Error al obtener logs:", err);
    }
}

// --- EXPORTACIÓN & INTEGRACIONES ---
function downloadOcsfBatch() {
    window.open("/api/telemetry/export?limit=200", "_blank");
}

function copyMetricsCurl() {
    const cmd = `curl -s http://${location.host}/metrics | grep -E "owleye_kernel|owleye_threat"`;
    navigator.clipboard.writeText(cmd).then(() => {
        showWorkstationToast("Comando cURL de Prometheus copiado al portapapeles");
    }).catch(() => {
        showWorkstationToast(cmd);
    });
}

// --- WEBSOCKET DE RESPALDO CON SLOT EASING ---
let wsAttempts = 0;
function tryLiveWebSocket() {
    if (!('WebSocket' in window)) return;
    if (wsLiveConnection && wsLiveConnection.readyState === WebSocket.OPEN) return;
    if (wsAttempts >= 3) return;

    wsAttempts++;
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    try {
        wsLiveConnection = new WebSocket(`${protocol}//${location.host}/ws/live`);
        wsLiveConnection.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.cpu !== undefined) {
                    updateSlotValue("cpuVal", `${data.cpu}%`);
                    document.getElementById("cpuBar").style.width = `${data.cpu}%`;
                }
                if (data.kernel_latency_us !== undefined) {
                    updateSlotValue("kernelLatencyVal", `${data.kernel_latency_us} μs`);
                }
            } catch (e) {}
        };
        wsLiveConnection.onopen = () => { wsAttempts = 0; };
        wsLiveConnection.onclose = () => { wsLiveConnection = null; };
        wsLiveConnection.onerror = () => { wsLiveConnection = null; };
    } catch (e) {
        wsLiveConnection = null;
    }
}

// --- TOAST NOTIFICATION VINTAGE ---
function showWorkstationToast(msg, isError = false) {
    const toast = document.createElement("div");
    toast.innerText = msg;
    toast.style.cssText = `
        position: fixed; bottom: 25px; right: 25px;
        background: ${isError ? 'var(--phosphor-rose)' : 'var(--ws-bg-window)'};
        color: ${isError ? '#fff' : 'var(--phosphor-cyan)'};
        border: 1px solid ${isError ? 'rgba(255,83,112,0.5)' : 'var(--ws-border-focus)'};
        padding: 12px 20px; border-radius: 8px; font-weight: 700;
        font-family: var(--font-mono); font-size: 0.78rem; z-index: 10000;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.6), 0 0 15px rgba(56, 189, 248, 0.2);
        animation: slotSlideDown 0.3s var(--ease-slot);
        letter-spacing: 0.3px;
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.4s var(--ease-soft)';
        setTimeout(() => toast.remove(), 400);
    }, 3800);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.innerText = text;
    return div.innerHTML;
}
