import time
import sys
import os
from hidden_logger import HiddenLogger
from process_monitor import ProcessMonitor
from network_monitor import NetworkMonitor
from alert_system import AlertSystem
from heuristic_analyzer import HeuristicAnalyzer

def main():
    print("""
    ^...^
   / o o \\
   |  Y  |  OwlEyeEngine - Silent Monitor
    V v V   Phase 2 Operational
    """)
    print("Monitoring system for changes and heuristic anomalies.")
    
    logger = HiddenLogger()
    alerter = AlertSystem() # Will look for SENTRY_TELEGRAM_TOKEN/CHAT_ID
    proc_mon = ProcessMonitor()
    net_mon = NetworkMonitor()
    analyzer = HeuristicAnalyzer(logger, alerter)
    
    try:
        while True:
            # 1. Check Processes (htop style + Heuristics)
            new_procs = proc_mon.check_new_processes()
            for p in new_procs:
                logger.log_event(
                    "PROCESS_NEW", 
                    f"Name: {p['name']} | PID: {p['pid']}", 
                    p['path'], 
                    f"User: {p['user']}"
                )
                print(f"[!] Logged new process: {p['name']}")
                analyzer.analyze_process_launch(p)

            # 2. Check Network (Cisco context + Heuristics)
            new_conns = net_mon.check_new_connections()
            if new_conns:
                analyzer.analyze_connections(new_conns)
                for c in new_conns:
                    logger.log_event(
                        "NETWORK_ENTRY",
                        f"Remote: {c['remote']}",
                        f"Local: {c['local']}",
                        c['entry_point']
                    )
                    print(f"[!] Logged new connection from: {c['remote']}")

            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nSentry Agent stopping...")
        sys.exit(0)
    except Exception as e:
        logger.log_event("CRITICAL_ERROR", str(e), "Main Loop", "System")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
