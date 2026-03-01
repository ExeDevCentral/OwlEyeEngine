import time
from collections import defaultdict

class HeuristicAnalyzer:
    def __init__(self, logger, alerter):
        self.logger = logger
        self.alerter = alerter
        self.ip_connection_counts = defaultdict(list) # IP -> list of timestamps
        self.port_scan_threshold = 5 # connections to different ports in a short time
        self.time_window = 60 # seconds
        self.known_ips = {"127.0.0.1"}

    def analyze_connections(self, new_connections):
        """
        Analyze connection patterns for anomalies like port scanning.
        """
        for conn in new_connections:
            remote_ip = conn['remote'].split(':')[0]
            if remote_ip in self.known_ips:
                continue
                
            current_time = time.time()
            self.ip_connection_counts[remote_ip].append(current_time)
            
            # Clean up old timestamps
            self.ip_connection_counts[remote_ip] = [
                t for t in self.ip_connection_counts[remote_ip] 
                if current_time - t < self.time_window
            ]
            
            # Check for high frequency (potential scan)
            if len(self.ip_connection_counts[remote_ip]) >= self.port_scan_threshold:
                alert_msg = (
                    f"POTENTIAL SCAN DETECTED!\n"
                    f"Source IP: {remote_ip}\n"
                    f"Activity: {len(self.ip_connection_counts[remote_ip])} connections in {self.time_window}s"
                )
                self.logger.log_event("SECURITY_HEURISTIC", "PORT_SCAN", remote_ip, "Heuristic Motor")
                self.alerter.send_alert(alert_msg)
                print(f"[!!!] {alert_msg}")
                # Reset count to avoid alert spamming for a bit
                self.ip_connection_counts[remote_ip] = []

    def analyze_process_launch(self, process_info):
        """
        Analyze process launches for unusual behavior.
        """
        # Example: Alert if a process launches from a temporary or hidden directory
        path = process_info['path'].lower()
        suspicious_paths = ['temp', 'tmp', 'appdata\\local\\temp', 'hidden']
        
        is_suspicious = any(sp in path for sp in suspicious_paths)
        if is_suspicious:
            alert_msg = (
                f"SUSPICIOUS PROCESS PATH!\n"
                f"Name: {process_info['name']}\n"
                f"User: {process_info['user']}\n"
                f"Path: {process_info['path']}"
            )
            self.logger.log_event("SECURITY_HEURISTIC", "SUSPICIOUS_PATH", process_info['name'], "Process Monitor")
            self.alerter.send_alert(alert_msg)
            print(f"[!!!] {alert_msg}")
