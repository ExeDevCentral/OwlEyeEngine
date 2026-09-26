"""
OwlEyeEngine - Enterprise Cyber Security Dashboard & Telemetry API (v4.0 Enterprise)
Provides:
  - Prometheus / OpenMetrics scraping endpoint (/metrics)
  - Kernel-level eBPF & Syscall Telemetry APIs (/api/kernel/status, /api/kernel/events)
  - OCSF / SIEM Telemetry batch export (/api/telemetry/export)
  - MITRE ATT&CK regional matrix aggregation (/api/mitre/matrix)
  - Real-time WebSockets & SSE live streaming (/ws/live, /ws/telemetry, /api/telemetry/stream)
  - Active Defense & Quarantine endpoints
"""

import os
import time
import psutil
import datetime
import asyncio
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from kernel_telemetry import KernelTelemetryEngine
from telemetry_engine import TelemetryEngine

DEMO_MODE = os.getenv("OWLEYE_DEMO_MODE", "false").lower() == "true"

app = FastAPI(
    title="OwlEyeEngine Enterprise - Kernel Telemetry & Active Defense",
    version="4.0.0",
    docs_url="/api/docs" if DEMO_MODE else None,
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State Container
CORE_STATE: Dict[str, Any] = {
    "logger": None,
    "alerter": None,
    "proc_mon": None,
    "net_mon": None,
    "analyzer": None,
    "defender": None,
    "kernel_engine": None,
    "telemetry_engine": None,
    "start_time": time.time()
}

ws_live_clients: List[WebSocket] = []
ws_telemetry_clients: List[WebSocket] = []

def init_app_state(
    logger=None,
    alerter=None,
    proc_mon=None,
    net_mon=None,
    analyzer=None,
    defender=None,
    kernel_engine=None,
    telemetry_engine=None
):
    CORE_STATE["logger"] = logger
    CORE_STATE["alerter"] = alerter
    CORE_STATE["proc_mon"] = proc_mon
    CORE_STATE["net_mon"] = net_mon
    CORE_STATE["analyzer"] = analyzer
    CORE_STATE["defender"] = defender
    CORE_STATE["start_time"] = time.time()

    # Initialize kernel & telemetry engines if not provided
    if kernel_engine is None:
        kernel_engine = KernelTelemetryEngine(demo_mode=DEMO_MODE)
        kernel_engine.start()
    CORE_STATE["kernel_engine"] = kernel_engine

    if telemetry_engine is None:
        telemetry_engine = TelemetryEngine(
            kernel_engine=kernel_engine,
            analyzer=analyzer,
            defender=defender
        )
    CORE_STATE["telemetry_engine"] = telemetry_engine

# Auto-initialize fallback engines on startup if not initialized
if CORE_STATE["kernel_engine"] is None:
    _k = KernelTelemetryEngine(demo_mode=DEMO_MODE)
    _k.start()
    CORE_STATE["kernel_engine"] = _k
    CORE_STATE["telemetry_engine"] = TelemetryEngine(kernel_engine=_k)

class KillProcessRequest(BaseModel):
    pid: int
    reason: str = "Manual Admin Termination"

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual Admin Block"

class ToggleDefenseRequest(BaseModel):
    enabled: bool

# --- DEMO DATA GENERATORS ---

def _demo_status():
    import random
    cpu = round(random.uniform(3, 18), 1)
    mem_pct = round(random.uniform(35, 62), 1)
    mem_used = round(psutil.virtual_memory().total / (1024*1024) * mem_pct / 100, 1)
    mem_total = round(psutil.virtual_memory().total / (1024*1024), 1)
    uptime_s = int(time.time() - CORE_STATE["start_time"])
    
    k_engine: KernelTelemetryEngine = CORE_STATE["kernel_engine"]
    k_status = k_engine.get_kernel_status() if k_engine else {
        "status": "ONLINE",
        "capabilities": {"active_probe_type": "DEMO_KERNEL_EMULATOR (v4.0 eBPF)"},
        "metrics": {"events_per_second": 3.4, "avg_interception_latency_us": 8.5}
    }

    return {
        "engine": "OwlEyeEngine v4.0 Enterprise Edition",
        "status": "OPERATIONAL",
        "uptime": str(datetime.timedelta(seconds=uptime_s)),
        "demo_mode": True,
        "system": {
            "cpu_percent": cpu,
            "memory_percent": mem_pct,
            "memory_used_mb": mem_used,
            "memory_total_mb": mem_total
        },
        "kernel_telemetry": {
            "probe_type": k_status["capabilities"]["active_probe_type"],
            "status": k_status["status"],
            "events_per_second": k_status["metrics"].get("events_per_second", 4.2),
            "avg_latency_us": k_status["metrics"].get("avg_interception_latency_us", 9.1),
            "total_events": k_status["metrics"].get("total_events_captured", 128),
            "ring_buffer_usage_pct": round((k_status["metrics"].get("ring_buffer_size", 42) / 500) * 100, 1)
        },
        "active_defense": {
            "auto_defense": True,
            "backend": "Linux nftables & eBPF",
            "blocked_ips_count": 4,
            "terminated_pids_count": 3,
            "blocked_ips": ["45.33.32.156", "185.220.101.42", "198.51.100.7", "103.251.167.20"]
        },
        "threat_summary": {
            "total_threats": 8,
            "recent_count": 4,
            "max_severity": "CRITICAL"
        }
    }

def _demo_threats():
    return {
        "threats": [
            {
                "id": "THREAT-1725300001000",
                "timestamp": "2026-09-26 14:32:01",
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "score": 85,
                "mitre": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
                "details": {"ip": "45.33.32.156", "connections_in_window": 14, "entry_point": "Network:45.33.32.156 -> LocalPort:22"},
                "auto_mitigated": True
            },
            {
                "id": "THREAT-1725300002000",
                "timestamp": "2026-09-26 14:30:14",
                "type": "SUSPICIOUS_PATH_EXECUTION",
                "severity": "CRITICAL",
                "score": 94,
                "mitre": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
                "details": {"name": "dropper.elf", "pid": 4921, "user": "root", "path": "/tmp/.hidden/dropper.elf", "kernel_probe": "sys_enter_execve"},
                "auto_mitigated": True
            },
            {
                "id": "THREAT-1725300003000",
                "timestamp": "2026-09-26 14:28:55",
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "score": 78,
                "mitre": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
                "details": {"ip": "185.220.101.42", "connections_in_window": 8, "entry_point": "Network:185.220.101.42 -> LocalPort:443"},
                "auto_mitigated": True
            },
            {
                "id": "THREAT-1725300004000",
                "timestamp": "2026-09-26 14:25:10",
                "type": "SUSPICIOUS_PATH_EXECUTION",
                "severity": "MEDIUM",
                "score": 65,
                "mitre": {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion"},
                "details": {"name": "miner.py", "pid": 3102, "user": "www-data", "path": "/var/tmp/miner.py"},
                "auto_mitigated": False
            },
            {
                "id": "THREAT-1725300005000",
                "timestamp": "2026-09-26 14:20:33",
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "score": 88,
                "mitre": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
                "details": {"ip": "198.51.100.7", "connections_in_window": 19, "entry_point": "Network:198.51.100.7 -> LocalPort:3306"},
                "auto_mitigated": True
            }
        ]
    }

def _demo_processes():
    import random
    procs = [
        {"pid": 1, "name": "systemd", "user": "root", "path": "/lib/systemd/systemd", "cpu": 0.0, "memory": 0.3},
        {"pid": 234, "name": "nginx", "user": "www-data", "path": "/usr/sbin/nginx", "cpu": 1.2, "memory": 0.8},
        {"pid": 567, "name": "python3", "user": "root", "path": "/usr/bin/python3", "cpu": 3.4, "memory": 2.1},
        {"pid": 891, "name": "sshd", "user": "root", "path": "/usr/sbin/sshd", "cpu": 0.1, "memory": 0.4},
        {"pid": 1023, "name": "mysqld", "user": "mysql", "path": "/usr/sbin/mysqld", "cpu": 5.7, "memory": 8.3},
        {"pid": 1456, "name": "node", "user": "deploy", "path": "/usr/local/bin/node", "cpu": 2.1, "memory": 3.5},
        {"pid": 1789, "name": "docker-proxy", "user": "root", "path": "/usr/bin/docker-proxy", "cpu": 0.3, "memory": 1.2},
        {"pid": 2012, "name": "containerd", "user": "root", "path": "/usr/bin/containerd", "cpu": 0.8, "memory": 1.5},
    ]
    for p in procs:
        p["cpu"] = round(random.uniform(0.1, 7.5), 1)
        p["memory"] = round(random.uniform(0.2, 4.8), 1)
    return {"count": len(procs), "processes": procs}

def _demo_connections():
    return {
        "count": 5,
        "connections": [
            {"fd": 12, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:8000", "remote": "192.168.1.50:54321", "remote_ip": "192.168.1.50", "remote_port": 54321, "status": "ESTABLISHED", "pid": 567},
            {"fd": 14, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:443", "remote": "10.0.0.15:8080", "remote_ip": "10.0.0.15", "remote_port": 8080, "status": "ESTABLISHED", "pid": 234},
            {"fd": 18, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:3306", "remote": "172.16.0.5:49152", "remote_ip": "172.16.0.5", "remote_port": 49152, "status": "ESTABLISHED", "pid": 1023},
            {"fd": 22, "family": "IPv4", "type": "TCP", "local": "0.0.0.0:22", "remote": "45.33.32.156:1337", "remote_ip": "45.33.32.156", "remote_port": 1337, "status": "SYN_RECV", "pid": 891},
            {"fd": 25, "family": "IPv6", "type": "TCP", "local": ":::8080", "remote": "203.0.113.42:22", "remote_ip": "203.0.113.42", "remote_port": 22, "status": "ESTABLISHED", "pid": 567},
        ]
    }

def _demo_logs():
    return {
        "logs": [
            "[2026-09-26 14:32:01] EVENT: KERNEL_EBPF | WHAT: sys_enter_execve | COMM: dropper.elf | INTERCEPT_LATENCY: 6μs",
            "[2026-09-26 14:32:01] EVENT: SECURITY_HEURISTIC | WHAT: PORT_SCAN | WHERE: 45.33.32.156 | MITRE: T1046",
            "[2026-09-26 14:30:14] EVENT: SECURITY_HEURISTIC | WHAT: SUSPICIOUS_PATH_EXECUTION | WHERE: dropper.elf | MITRE: T1059",
            "[2026-09-26 14:28:55] EVENT: ACTIVE_DEFENSE | WHAT: PROCESS_KILLED | WHERE: PID: 4921 (dropper.elf) | MITRE: M1042",
            "[2026-09-26 14:25:10] EVENT: ACTIVE_DEFENSE | WHAT: IP_BLOCKED | WHERE: 45.33.32.156 | BACKEND: Linux nftables",
            "[2026-09-26 14:20:33] EVENT: TELEMETRY_STREAM | WHAT: Prometheus /metrics scraped by Regional SOC",
            "[2026-09-26 14:15:00] EVENT: PROCESS_NEW | WHAT: Name: nginx | PID: 234 | WHERE: /usr/sbin/nginx",
        ]
    }

# --- PROMETHEUS METRICS SCRAPING ENDPOINT ---

@app.get("/metrics", response_class=PlainTextResponse)
def get_prometheus_metrics():
    """
    Standard Prometheus / OpenMetrics scraping target for Grafana, Datadog, Prometheus.
    """
    t_engine: TelemetryEngine = CORE_STATE.get("telemetry_engine")
    if t_engine:
        return t_engine.generate_prometheus_metrics()
    
    # Fallback if uninitialized
    t_engine = TelemetryEngine(kernel_engine=CORE_STATE.get("kernel_engine"))
    return t_engine.generate_prometheus_metrics()

# --- KERNEL TELEMETRY ENDPOINTS ---

@app.get("/api/kernel/status")
def get_kernel_status():
    """
    Reports kernel probe capabilities, eBPF status, events/sec, and intercept latency.
    """
    k_engine: KernelTelemetryEngine = CORE_STATE.get("kernel_engine")
    if not k_engine:
        return {"status": "UNAVAILABLE", "message": "Kernel engine not loaded"}
    return k_engine.get_kernel_status()

@app.get("/api/kernel/events")
def get_kernel_events(limit: int = 50, subsystem: Optional[str] = None):
    """
    Returns recent kernel intercepted syscalls from ring buffer.
    """
    k_engine: KernelTelemetryEngine = CORE_STATE.get("kernel_engine")
    if not k_engine:
        return {"events": []}
    return {
        "count": len(k_engine.ring_buffer),
        "events": k_engine.get_recent_events(limit=limit, subsystem=subsystem)
    }

# --- ENTERPRISE TELEMETRY ENDPOINTS ---

@app.get("/api/telemetry/status")
def get_telemetry_status():
    """
    Health check of the enterprise telemetry pipeline.
    """
    t_engine: TelemetryEngine = CORE_STATE.get("telemetry_engine")
    k_engine: KernelTelemetryEngine = CORE_STATE.get("kernel_engine")
    return {
        "status": "HEALTHY",
        "engine_version": "4.0.0-enterprise",
        "subscribers_connected": len(t_engine.subscribers) if t_engine else 0,
        "queue_size": len(t_engine.telemetry_queue) if t_engine else 0,
        "prometheus_available": True,
        "kernel_probe": k_engine.capabilities["active_probe_type"] if k_engine else "UNKNOWN"
    }

@app.get("/api/telemetry/export")
def export_telemetry_batch(limit: int = 100):
    """
    Exports OCSF-compliant JSON telemetry batch for enterprise SIEM ingestion.
    """
    t_engine: TelemetryEngine = CORE_STATE.get("telemetry_engine")
    if not t_engine:
        return {"error": "Telemetry engine offline"}
    return t_engine.export_ocsf_batch(limit=limit)

@app.get("/api/mitre/matrix")
def get_mitre_matrix():
    """
    Aggregates threat detections mapped to MITRE ATT&CK Matrix.
    """
    analyzer = CORE_STATE.get("analyzer")
    threats = (analyzer.threat_history if (analyzer and analyzer.threat_history) else _demo_threats()["threats"])

    tactics = {
        "Execution (T1059)": {"count": 0, "severity": "NONE"},
        "Discovery (T1046)": {"count": 0, "severity": "NONE"},
        "Command and Control (T1071)": {"count": 0, "severity": "NONE"},
        "Defense Evasion (T1036)": {"count": 0, "severity": "NONE"},
        "Privilege Escalation (T1068)": {"count": 0, "severity": "NONE"}
    }

    for t in threats:
        mitre = t.get("mitre", {})
        tac = mitre.get("tactic", "")
        tech = mitre.get("id", "")
        key = f"{tac} ({tech})"
        if key in tactics:
            tactics[key]["count"] += 1
            tactics[key]["severity"] = t.get("severity", "MEDIUM")

    return {
        "framework": "MITRE ATT&CK Enterprise v14",
        "regional_threat_index": "ELEVATED",
        "tactics": tactics
    }

@app.get("/api/telemetry/stream")
async def sse_telemetry_stream():
    """
    Server-Sent Events (SSE) live kernel & security telemetry stream.
    """
    k_engine: KernelTelemetryEngine = CORE_STATE.get("kernel_engine")
    
    async def event_generator():
        last_event_id = None
        while True:
            if k_engine and k_engine.ring_buffer:
                latest = k_engine.ring_buffer[-1]
                if latest.event_id != last_event_id:
                    last_event_id = latest.event_id
                    data = latest.to_dict()
                    import json
                    yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# --- CORE API ROUTES ---

@app.get("/api/status")
def get_status():
    if DEMO_MODE:
        return _demo_status()

    uptime_seconds = int(time.time() - CORE_STATE["start_time"])
    uptime_str = str(datetime.timedelta(seconds=uptime_seconds))
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    defender = CORE_STATE.get("defender")
    analyzer = CORE_STATE.get("analyzer")
    k_engine: KernelTelemetryEngine = CORE_STATE.get("kernel_engine")
    k_status = k_engine.get_kernel_status() if k_engine else {}

    return {
        "engine": "OwlEyeEngine v4.0 Enterprise Edition",
        "status": "OPERATIONAL",
        "uptime": uptime_str,
        "demo_mode": False,
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": mem.percent,
            "memory_used_mb": round(mem.used / (1024 * 1024), 1),
            "memory_total_mb": round(mem.total / (1024 * 1024), 1)
        },
        "kernel_telemetry": {
            "probe_type": k_status.get("capabilities", {}).get("active_probe_type", "STANDBY"),
            "status": k_status.get("status", "STANDBY"),
            "events_per_second": k_status.get("metrics", {}).get("events_per_second", 0.0),
            "avg_latency_us": k_status.get("metrics", {}).get("avg_interception_latency_us", 0.0),
            "total_events": k_status.get("metrics", {}).get("total_events_captured", 0),
            "ring_buffer_usage_pct": round((k_status.get("metrics", {}).get("ring_buffer_size", 0) / 500) * 100, 1)
        },
        "active_defense": {
            "auto_defense": defender.auto_defense if defender else False,
            "backend": getattr(defender, "linux_fw_backend", "Windows Firewall"),
            "blocked_ips_count": len(defender.blocked_ips) if defender else 0,
            "terminated_pids_count": len(defender.terminated_pids) if defender else 0,
            "blocked_ips": list(defender.blocked_ips) if defender else []
        },
        "threat_summary": {
            "total_threats": len(analyzer.threat_history) if analyzer else 0,
            "recent_count": len(analyzer.get_recent_threats(10)) if analyzer else 0
        }
    }

@app.get("/api/processes")
def get_processes(limit: int = 50):
    if DEMO_MODE:
        return _demo_processes()

    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            procs.append({
                "pid": info['pid'],
                "name": info['name'] or "Unknown",
                "user": info['username'] or "N/A",
                "path": info['exe'] or "Unknown",
                "cpu": round(info['cpu_percent'] or 0.0, 1),
                "memory": round(info['memory_percent'] or 0.0, 1)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: (x['cpu'], x['memory']), reverse=True)
    return {"count": len(procs), "processes": procs[:limit]}

@app.get("/api/connections")
def get_connections():
    if DEMO_MODE:
        return _demo_connections()

    conns = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.raddr:
                conns.append({
                    "fd": c.fd,
                    "family": "IPv4" if c.family == 2 else "IPv6",
                    "type": "TCP" if c.type == 1 else "UDP",
                    "local": f"{c.laddr.ip}:{c.laddr.port}",
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    "remote_ip": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "status": c.status,
                    "pid": c.pid
                })
    except Exception:
        pass

    return {"count": len(conns), "connections": conns}

@app.get("/api/threats")
def get_threats(limit: int = 50):
    if DEMO_MODE:
        return _demo_threats()

    analyzer = CORE_STATE.get("analyzer")
    if not analyzer:
        return {"threats": []}
    return {"threats": analyzer.get_recent_threats(limit)}

@app.get("/api/logs")
def get_logs(limit: int = 50):
    if DEMO_MODE:
        return _demo_logs()

    logger = CORE_STATE.get("logger")
    if not logger:
        return {"logs": []}
    return {"logs": logger.get_recent_logs(limit)}

@app.post("/api/defender/toggle")
def toggle_defense(req: ToggleDefenseRequest):
    if DEMO_MODE:
        return {"success": True, "auto_defense": req.enabled}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    defender.set_auto_defense(req.enabled)
    return {"success": True, "auto_defense": defender.auto_defense}

@app.post("/api/actions/kill")
def action_kill(req: KillProcessRequest):
    if DEMO_MODE:
        return {"success": True, "message": f"[DEMO] Process PID {req.pid} terminated.", "pid": req.pid, "name": "demo_process"}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    return defender.kill_process(req.pid, reason=req.reason)

@app.post("/api/actions/block_ip")
def action_block_ip(req: BlockIPRequest):
    if DEMO_MODE:
        return {"success": True, "message": f"[DEMO] IP {req.ip} blocked in firewall."}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    return defender.block_ip(req.ip, reason=req.reason)

@app.post("/api/actions/unblock_ip")
def action_unblock_ip(req: BlockIPRequest):
    if DEMO_MODE:
        return {"success": True, "message": f"[DEMO] IP {req.ip} unblocked."}

    defender = CORE_STATE.get("defender")
    if not defender:
        raise HTTPException(status_code=500, detail="Defender not initialized")
    return defender.unblock_ip(req.ip)

@app.get("/api/quarantine/list")
def get_quarantine_list():
    from quarantine_manager import QuarantineVault
    vault = QuarantineVault()
    return {"count": len(vault.list_quarantined_items()), "items": vault.list_quarantined_items()}

# --- WEBSOCKETS ---

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    ws_live_clients.append(websocket)
    try:
        while True:
            if DEMO_MODE:
                data = _demo_status()
            else:
                uptime_s = int(time.time() - CORE_STATE["start_time"])
                k_engine = CORE_STATE.get("kernel_engine")
                k_stat = k_engine.get_kernel_status() if k_engine else {}
                data = {
                    "cpu": psutil.cpu_percent(interval=None),
                    "memory": psutil.virtual_memory().percent,
                    "uptime": str(datetime.timedelta(seconds=uptime_s)),
                    "kernel_events_sec": k_stat.get("metrics", {}).get("events_per_second", 0),
                    "kernel_latency_us": k_stat.get("metrics", {}).get("avg_interception_latency_us", 0)
                }
            await websocket.send_json(data)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        if websocket in ws_live_clients:
            ws_live_clients.remove(websocket)
    except Exception:
        if websocket in ws_live_clients:
            ws_live_clients.remove(websocket)

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    ws_telemetry_clients.append(websocket)
    k_engine: KernelTelemetryEngine = CORE_STATE.get("kernel_engine")
    try:
        last_id = None
        while True:
            if k_engine and k_engine.ring_buffer:
                latest = k_engine.ring_buffer[-1]
                if latest.event_id != last_id:
                    last_id = latest.event_id
                    await websocket.send_json(latest.to_dict())
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        if websocket in ws_telemetry_clients:
            ws_telemetry_clients.remove(websocket)
    except Exception:
        if websocket in ws_telemetry_clients:
            ws_telemetry_clients.remove(websocket)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dashboard_dir = os.path.join(BASE_DIR, "dashboard_app")
landing_dir = os.path.join(BASE_DIR, "landing_page")

if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

if os.path.exists(landing_dir):
    app.mount("/landing", StaticFiles(directory=landing_dir), name="landing-static")

def _read_html(directory, filename="index.html"):
    index_file = os.path.join(directory, filename)
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>OwlEyeEngine Enterprise Online</h1>"

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": "4.0.0-enterprise",
        "kernel_probe": CORE_STATE.get("kernel_engine", {}).capabilities.get("active_probe_type", "STANDBY") if CORE_STATE.get("kernel_engine") else "STANDBY"
    }

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    return _read_html(dashboard_dir)

@app.get("/", response_class=HTMLResponse)
def serve_root():
    if os.path.exists(landing_dir):
        return _read_html(landing_dir)
    return serve_dashboard()

def run_server(host="0.0.0.0", port=8000):
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_server()
