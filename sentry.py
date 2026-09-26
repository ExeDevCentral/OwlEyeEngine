"""
OwlEyeEngine - Central Security Core Orchestrator (v4.0 Enterprise)
Integrates:
  - Kernel-level eBPF & Syscall Telemetry
  - Real-time Process & Network monitors
  - Active Defender (Firewall & Auto-Kill)
  - Heuristic Threat Analyzer with MITRE ATT&CK mapping
  - Enterprise Telemetry Pipeline & Prometheus Exporter
  - Fast-API Cyberpunk Web Dashboard
"""

import time
import sys
import os
import signal
import threading
from hidden_logger import HiddenLogger
from process_monitor import ProcessMonitor
from network_monitor import NetworkMonitor
from alert_system import AlertSystem
from heuristic_analyzer import HeuristicAnalyzer
from active_defender import ActiveDefender
from kernel_telemetry import KernelTelemetryEngine
from telemetry_engine import TelemetryEngine
import web_dashboard

BANNER = r"""
    ^...^
   / o o \   OwlEyeEngine v4.0 - Enterprise Edition
   |  Y  |   Kernel Telemetry, eBPF & Active Defense
    V v V    "Zero-latency kernel vision, automated regional defense."
"""

def start_dashboard_thread(logger, alerter, proc_mon, net_mon, analyzer, defender, kernel_engine, telemetry_engine, port=8000):
    web_dashboard.init_app_state(
        logger=logger,
        alerter=alerter,
        proc_mon=proc_mon,
        net_mon=net_mon,
        analyzer=analyzer,
        defender=defender,
        kernel_engine=kernel_engine,
        telemetry_engine=telemetry_engine
    )
    print(f"[+] Web Dashboard & Telemetry API active on http://0.0.0.0:{port}")
    print(f"[+] Prometheus Metrics Scrape endpoint: http://0.0.0.0:{port}/metrics")
    thread = threading.Thread(
        target=web_dashboard.run_server,
        kwargs={"host": "0.0.0.0", "port": port},
        daemon=True
    )
    thread.start()
    return thread

def main():
    demo_mode = os.getenv("OWLEYE_DEMO_MODE", "false").lower() == "true"

    print(BANNER)
    print(f"[*] Operation Mode: {'DEMO / REGIONAL PRESENTATION' if demo_mode else 'LIVE PRODUCTION (Kernel Hooks Active)'}")
    print("[*] Initializing OwlEye v4.0 Enterprise Security Core...")

    # Initialize Kernel Telemetry Engine first
    kernel_engine = KernelTelemetryEngine(demo_mode=demo_mode)
    kernel_engine.start()
    k_probe = kernel_engine.capabilities.get("active_probe_type", "UNKNOWN")
    print(f"[+] Kernel Probe Subsystem: {k_probe}")

    # Core Security Components
    logger = HiddenLogger() if not demo_mode else None
    alerter = AlertSystem() if not demo_mode else None
    proc_mon = ProcessMonitor() if not demo_mode else None
    net_mon = NetworkMonitor() if not demo_mode else None

    # Telemetry Pipeline
    telemetry_engine = TelemetryEngine(kernel_engine=kernel_engine)

    # Active Defender & Heuristic Analyzer with Telemetry integration
    defender = ActiveDefender(auto_defense=False, logger=logger, telemetry_engine=telemetry_engine) if not demo_mode else None
    analyzer = HeuristicAnalyzer(logger, alerter, defender=defender, telemetry_engine=telemetry_engine) if not demo_mode else None

    # Link back to telemetry pipeline
    telemetry_engine.defender = defender
    telemetry_engine.analyzer = analyzer

    dashboard_port = int(os.getenv("OWLEYE_PORT", 8000))
    start_dashboard_thread(
        logger, alerter, proc_mon, net_mon, analyzer, defender,
        kernel_engine, telemetry_engine, port=dashboard_port
    )

    print(f"\n[+] OwlEye Engine actively monitoring system anomalies, kernel syscalls & network traffic.")
    print(f"[+] Dashboard: http://localhost:{dashboard_port}/dashboard")
    print(f"[+] Landing Page: http://localhost:{dashboard_port}/")
    print(f"[+] Prometheus Exporter: http://localhost:{dashboard_port}/metrics\n")

    if demo_mode:
        print("[*] Running in DEMO / PRESENTATION mode. Simulated high-fidelity kernel streams active.")
        print("[*] Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[*] OwlEye Enterprise Agent stopping cleanly...")
            kernel_engine.stop()
            sys.exit(0)
        return

    def shutdown(sig, frame):
        print("\n[*] OwlEye Enterprise Agent stopping cleanly...")
        kernel_engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            # Check processes
            new_procs = proc_mon.check_new_processes()
            for p in new_procs:
                if logger:
                    logger.log_event(
                        "PROCESS_NEW",
                        f"Name: {p['name']} | PID: {p['pid']}",
                        p['path'],
                        f"User: {p['user']}"
                    )
                print(f"[!] New process: {p['name']} (PID: {p['pid']})")
                analyzer.analyze_process_launch(p)

            # Check network connections
            new_conns = net_mon.check_new_connections()
            if new_conns:
                analyzer.analyze_connections(new_conns)
                for c in new_conns:
                    if logger:
                        logger.log_event(
                            "NETWORK_ENTRY",
                            f"Remote: {c['remote']}",
                            f"Local: {c['local']}",
                            c['entry_point']
                        )
                    print(f"[!] New connection from: {c['remote']}")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[*] OwlEye Enterprise Agent stopping cleanly...")
        kernel_engine.stop()
        sys.exit(0)
    except Exception as e:
        if logger:
            logger.log_event("SYSTEM_ERROR", str(e), "sentry.py", "Critical Fail")
        print(f"[X] Engine Error: {e}")
        kernel_engine.stop()

if __name__ == "__main__":
    main()
