"""
OwlEyeEngine - Enterprise Telemetry Pipeline & Exporter (v4.0 Enterprise)
Provides:
  - Prometheus / OpenMetrics scraping format (/metrics)
  - Real-Time Telemetry Event Bus (SSE & WebSocket streams)
  - OCSF / ECS-compliant JSON telemetry export for SIEM (Splunk, Elastic, Wazuh)
  - System performance and kernel health aggregation
"""

import time
import json
import psutil
from typing import Dict, List, Any, Optional
from collections import deque

class TelemetryEngine:
    """
    Central Telemetry Ingestion, Transformation, and Metrics Pipeline.
    """
    def __init__(self, kernel_engine=None, analyzer=None, defender=None, max_queue: int = 1000):
        self.kernel_engine = kernel_engine
        self.analyzer = analyzer
        self.defender = defender
        self.telemetry_queue = deque(maxlen=max_queue)
        self.start_time = time.time()
        self.subscribers = [] # Queues or callbacks for live streaming

    def record_telemetry_event(self, event_type: str, payload: Dict[str, Any], severity: str = "INFO"):
        """
        Ingests a standardized security telemetry record.
        """
        record = {
            "telemetry_id": f"TEL-{int(time.time()*1000)}-{len(self.telemetry_queue):04d}",
            "schema_version": "1.1.0-ocsf",
            "timestamp": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "class_uid": 1001, # Process / Security Activity
            "type": event_type,
            "severity": severity,
            "data": payload
        }
        self.telemetry_queue.append(record)

        # Notify any active live subscribers
        dead_subs = []
        for sub in self.subscribers:
            try:
                sub(record)
            except Exception:
                dead_subs.append(sub)
        for d in dead_subs:
            if d in self.subscribers:
                self.subscribers.remove(d)

        return record

    def subscribe(self, callback):
        """Adds live listener callback for new telemetry records."""
        if callback not in self.subscribers:
            self.subscribers.append(callback)

    def unsubscribe(self, callback):
        if callback in self.subscribers:
            self.subscribers.remove(callback)

    def get_recent_telemetry(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self.telemetry_queue)[-limit:]

    def export_ocsf_batch(self, limit: int = 100) -> Dict[str, Any]:
        """
        Exports telemetry batch compatible with Open Cybersecurity Schema Framework (OCSF)
        for regional SOC / SIEM ingestion.
        """
        records = list(self.telemetry_queue)[-limit:]
        return {
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "OwlEyeEngine Enterprise",
                    "vendor_name": "ExeDevCentral",
                    "version": "4.0.0"
                },
                "total_records": len(records),
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            },
            "events": records
        }

    def generate_prometheus_metrics(self) -> str:
        """
        Renders real-time OpenMetrics / Prometheus exposition format.
        Scraped by Prometheus, VictoriaMetrics, Datadog, or Grafana Agent.
        """
        cpu_pct = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        uptime_seconds = int(time.time() - self.start_time)

        # Kernel metrics
        k_status = self.kernel_engine.get_kernel_status() if self.kernel_engine else {}
        k_metrics = k_status.get("metrics", {})
        k_total_events = k_metrics.get("total_events_captured", 0)
        k_rate = k_metrics.get("events_per_second", 0.0)
        k_latency = k_metrics.get("avg_interception_latency_us", 0.0)
        k_dropped = k_metrics.get("dropped_events", 0)
        k_subsystems = k_metrics.get("subsystem_counts", {})

        # Defender & Analyzer metrics
        blocked_ips = len(self.defender.blocked_ips) if self.defender else 0
        killed_pids = len(self.defender.terminated_pids) if self.defender else 0
        auto_defense_val = 1 if (self.defender and self.defender.auto_defense) else 0

        threat_count = len(self.analyzer.threat_history) if self.analyzer else 0
        recent_threats = self.analyzer.get_recent_threats(10) if self.analyzer else []
        max_threat_score = max([t.get("score", 0) for t in recent_threats], default=0)

        total_procs = len(psutil.pids())

        lines = [
            "# HELP owleye_engine_uptime_seconds Total runtime of OwlEyeEngine in seconds",
            "# TYPE owleye_engine_uptime_seconds counter",
            f"owleye_engine_uptime_seconds {uptime_seconds}",
            "",
            "# HELP owleye_system_cpu_percent System CPU usage percent",
            "# TYPE owleye_system_cpu_percent gauge",
            f"owleye_system_cpu_percent {cpu_pct:.1f}",
            "",
            "# HELP owleye_system_memory_used_bytes Used system memory in bytes",
            "# TYPE owleye_system_memory_used_bytes gauge",
            f"owleye_system_memory_used_bytes {mem.used}",
            "",
            "# HELP owleye_system_memory_total_bytes Total system memory in bytes",
            "# TYPE owleye_system_memory_total_bytes gauge",
            f"owleye_system_memory_total_bytes {mem.total}",
            "",
            "# HELP owleye_system_processes_count Number of active OS processes",
            "# TYPE owleye_system_processes_count gauge",
            f"owleye_system_processes_count {total_procs}",
            "",
            "# HELP owleye_kernel_events_total Total kernel level syscall events intercepted",
            "# TYPE owleye_kernel_events_total counter",
            f'owleye_kernel_events_total{{status="intercepted"}} {k_total_events}',
            f'owleye_kernel_events_total{{status="dropped"}} {k_dropped}',
            "",
            "# HELP owleye_kernel_events_rate_per_sec Instantaneous kernel events per second",
            "# TYPE owleye_kernel_events_rate_per_sec gauge",
            f"owleye_kernel_events_rate_per_sec {k_rate:.1f}",
            "",
            "# HELP owleye_kernel_interception_latency_us Average kernel hook latency in microseconds",
            "# TYPE owleye_kernel_interception_latency_us gauge",
            f"owleye_kernel_interception_latency_us {k_latency:.1f}",
            "",
            "# HELP owleye_threat_score Highest active threat score (0-100)",
            "# TYPE owleye_threat_score gauge",
            f"owleye_threat_score {max_threat_score}",
            "",
            "# HELP owleye_threats_total Total detected threat anomalies",
            "# TYPE owleye_threats_total counter",
            f"owleye_threats_total {threat_count}",
            "",
            "# HELP owleye_active_mitigations_total Total active mitigations executed",
            "# TYPE owleye_active_mitigations_total counter",
            f'owleye_active_mitigations_total{{action="kill_process"}} {killed_pids}',
            f'owleye_active_mitigations_total{{action="block_ip"}} {blocked_ips}',
            "",
            "# HELP owleye_active_defense_mode Whether active defense is enabled (1) or alert-only (0)",
            "# TYPE owleye_active_defense_mode gauge",
            f"owleye_active_defense_mode {auto_defense_val}"
        ]

        # Add subsystem counts
        for sub, count in k_subsystems.items():
            lines.append(f'owleye_kernel_subsystem_events_total{{subsystem="{sub.lower()}"}} {count}')

        lines.append("")
        return "\n".join(lines)


if __name__ == "__main__":
    from kernel_telemetry import KernelTelemetryEngine
    k = KernelTelemetryEngine(demo_mode=True)
    k.start()
    t = TelemetryEngine(kernel_engine=k)
    time.sleep(2)
    print(t.generate_prometheus_metrics())
    k.stop()
