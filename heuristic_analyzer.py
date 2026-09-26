"""
OwlEyeEngine - Production Behavioral Heuristic Analyzer (v4.0 Enterprise)
Provides real-world security analysis:
  - Command-line argument inspection (Encoded PowerShell, Reverse Shells, Credential Dumps)
  - Process Lineage & Ancestry Correlation (Web servers or Office spawning shells)
  - Execution from temporary/hidden paths
  - Port scanning threshold detection
  - Direct mapping to MITRE ATT&CK Matrix & Quarantine triggering
"""

import time
import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any

MITRE_TECHNIQUES = {
    "PORT_SCAN": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery"
    },
    "SUSPICIOUS_PATH_EXECUTION": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution"
    },
    "SUSPICIOUS_CMDLINE_ARGUMENTS": {
        "id": "T1059.001",
        "name": "PowerShell / Shell Obfuscation & Downloaders",
        "tactic": "Execution"
    },
    "ANOMALOUS_PROCESS_LINEAGE": {
        "id": "T1059",
        "name": "Exploitation for Client / WebShell Execution",
        "tactic": "Execution"
    },
    "REVERSE_SHELL_PATTERN": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control"
    },
    "RANSOMWARE_SHADOW_DELETION": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact"
    },
    "CREDENTIAL_ACCESS_ATTEMPT": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access"
    }
}

class HeuristicAnalyzer:
    def __init__(self, logger=None, alerter=None, defender=None, telemetry_engine=None):
        self.logger = logger
        self.alerter = alerter
        self.defender = defender
        self.telemetry_engine = telemetry_engine
        self.ip_connection_counts = defaultdict(list)
        self.port_scan_threshold = 5
        self.time_window = 60
        self.known_ips = {"127.0.0.1", "0.0.0.0", "::1"}
        self.threat_history = []
        self.max_history = 100

    def record_threat(
        self,
        threat_type: str,
        severity: str,
        score: int,
        details: dict,
        auto_mitigated: bool = False
    ) -> Dict[str, Any]:
        mitre_info = MITRE_TECHNIQUES.get(threat_type, {
            "id": "T1000",
            "name": "Unclassified Anomaly",
            "tactic": "General"
        })

        event = {
            "id": f"THREAT-{int(time.time()*1000)}",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": threat_type,
            "severity": severity,
            "score": score,
            "details": details,
            "auto_mitigated": auto_mitigated,
            "mitre": mitre_info
        }
        self.threat_history.insert(0, event)
        if len(self.threat_history) > self.max_history:
            self.threat_history.pop()

        if self.telemetry_engine:
            self.telemetry_engine.record_telemetry_event(
                event_type=f"THREAT_{threat_type}",
                payload=event,
                severity=severity
            )

        return event

    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.threat_history[:limit]

    def analyze_connections(self, new_connections):
        """Analyze network entries for port scanning or anomalous remote hosts."""
        for conn in new_connections:
            remote = conn.get('remote', '')
            if not remote or ':' not in remote:
                continue

            remote_ip = remote.split(':')[0]
            if remote_ip in self.known_ips:
                continue

            current_time = time.time()
            self.ip_connection_counts[remote_ip].append(current_time)

            self.ip_connection_counts[remote_ip] = [
                t for t in self.ip_connection_counts[remote_ip]
                if current_time - t < self.time_window
            ]

            count = len(self.ip_connection_counts[remote_ip])
            if count >= self.port_scan_threshold:
                alert_msg = (
                    f"PORT SCAN DETECTED!\n"
                    f"Source IP: {remote_ip}\n"
                    f"Frequency: {count} connections in {self.time_window}s"
                )
                if self.logger:
                    self.logger.log_event("SECURITY_HEURISTIC", "PORT_SCAN", remote_ip, "Heuristic Port Monitor")
                if self.alerter:
                    self.alerter.send_alert(alert_msg)
                print(f"[!!!] {alert_msg}")

                auto_mitigated = False
                if self.defender and self.defender.auto_defense:
                    res = self.defender.block_ip(remote_ip, reason="Automated mitigation: Port scanning threshold reached")
                    auto_mitigated = res.get("success", False)

                self.record_threat(
                    threat_type="PORT_SCAN",
                    severity="HIGH",
                    score=85,
                    details={"ip": remote_ip, "connections_in_window": count, "entry_point": conn.get("entry_point")},
                    auto_mitigated=auto_mitigated
                )
                self.ip_connection_counts[remote_ip] = []

    def analyze_process_launch(self, process_info: Dict[str, Any]):
        """
        Deep inspection of newly launched processes:
          1. Command line argument analysis (malicious scripts, obfuscation)
          2. Process Lineage (Parent-Child anomaly correlation)
          3. Suspicious execution paths
        """
        pid = process_info.get('pid', 0)
        proc_name = process_info.get('name', 'Unknown')
        path = (process_info.get('path') or "").lower()
        cmdline = (process_info.get('cmdline') or "").lower()
        parent_name = (process_info.get('parent_name') or "").lower()
        user = process_info.get('user', 'Unknown')
        sha256 = process_info.get('sha256')

        # Rule 1: Command line malicious pattern detection
        suspicious_patterns = [
            ("downloadstring", "PowerShell Web Downloader", "SUSPICIOUS_CMDLINE_ARGUMENTS", "HIGH", 85),
            ("-encodedcommand", "Obfuscated Encoded PowerShell", "SUSPICIOUS_CMDLINE_ARGUMENTS", "HIGH", 88),
            ("-enc ", "Obfuscated Base64 PowerShell", "SUSPICIOUS_CMDLINE_ARGUMENTS", "HIGH", 88),
            ("vssadmin delete shadows", "Ransomware Shadow Deletion Attempt", "RANSOMWARE_SHADOW_DELETION", "CRITICAL", 98),
            ("wmic shadowcopy delete", "Ransomware Shadow Deletion Attempt", "RANSOMWARE_SHADOW_DELETION", "CRITICAL", 98),
            ("mimikatz", "Credential Dumping Tool Detected", "CREDENTIAL_ACCESS_ATTEMPT", "CRITICAL", 99),
            ("sekurlsa", "Credential Dumping Tool Detected", "CREDENTIAL_ACCESS_ATTEMPT", "CRITICAL", 99),
            ("/dev/tcp/", "Linux Reverse Shell Payload", "REVERSE_SHELL_PATTERN", "CRITICAL", 95),
            ("nc -e", "Netcat Reverse Shell Payload", "REVERSE_SHELL_PATTERN", "CRITICAL", 95),
            ("| bash", "Direct Pipe to Shell Execution", "SUSPICIOUS_CMDLINE_ARGUMENTS", "HIGH", 82),
            ("| sh", "Direct Pipe to Shell Execution", "SUSPICIOUS_CMDLINE_ARGUMENTS", "HIGH", 82),
            ("curl -fssl", "Automated Web Dropper Download", "SUSPICIOUS_CMDLINE_ARGUMENTS", "MEDIUM", 75)
        ]

        for pattern, desc, threat_type, severity, score in suspicious_patterns:
            if pattern in cmdline:
                alert_msg = f"[!] {desc.upper()} DETECTED!\nPID: {pid} ({proc_name})\nCmd: {cmdline[:120]}"
                print(f"[!!!] {alert_msg}")
                if self.logger:
                    self.logger.log_event("SECURITY_HEURISTIC", threat_type, proc_name, f"PID:{pid} | {desc}")
                if self.alerter:
                    self.alerter.send_alert(alert_msg)

                auto_mitigated = False
                if self.defender and self.defender.auto_defense:
                    res = self.defender.kill_process(pid, reason=f"Automated mitigation: {desc}")
                    auto_mitigated = res.get("success", False)

                self.record_threat(
                    threat_type=threat_type,
                    severity=severity,
                    score=score,
                    details={
                        "name": proc_name,
                        "pid": pid,
                        "cmdline": cmdline[:200],
                        "sha256": sha256,
                        "pattern_matched": pattern,
                        "description": desc
                    },
                    auto_mitigated=auto_mitigated
                )
                return

        # Rule 2: Suspicious Process Lineage (Parent-Child Anomaly)
        # Web server or Office spawning shells
        web_servers = ["nginx", "httpd", "apache2", "w3wp", "node", "uwsgi"]
        office_apps = ["winword", "excel", "powerpnt", "outlook"]
        shells = ["cmd.exe", "powershell.exe", "bash", "sh", "zsh"]

        is_web_parent = any(ws in parent_name for ws in web_servers)
        is_office_parent = any(off in parent_name for off in office_apps)
        is_shell = any(sh == proc_name.lower() or sh in path for sh in shells)

        if (is_web_parent or is_office_parent) and is_shell:
            threat_desc = "Web Shell Execution" if is_web_parent else "Office Document Macro / Exploit Shell"
            alert_msg = f"[!] ANOMALOUS PROCESS LINEAGE ({threat_desc.upper()})!\nParent: {parent_name} -> Child: {proc_name} (PID: {pid})"
            print(f"[!!!] {alert_msg}")

            if self.logger:
                self.logger.log_event("SECURITY_HEURISTIC", "ANOMALOUS_PROCESS_LINEAGE", proc_name, f"Parent:{parent_name} -> PID:{pid}")

            auto_mitigated = False
            if self.defender and self.defender.auto_defense:
                res = self.defender.kill_process(pid, reason=f"Automated mitigation: {threat_desc}")
                auto_mitigated = res.get("success", False)

            self.record_threat(
                threat_type="ANOMALOUS_PROCESS_LINEAGE",
                severity="CRITICAL",
                score=96,
                details={
                    "name": proc_name,
                    "pid": pid,
                    "parent_name": parent_name,
                    "description": threat_desc,
                    "sha256": sha256
                },
                auto_mitigated=auto_mitigated
            )
            return

        # Rule 3: Execution from temporary or hidden paths
        suspicious_paths = ['temp', 'tmp', 'appdata\\local\\temp', 'hidden', '/tmp', '/var/tmp', '.hidden']
        if any(sp in path for sp in suspicious_paths):
            alert_msg = f"[!] SUSPICIOUS PROCESS PATH!\nName: {proc_name} (PID: {pid})\nPath: {path}"
            print(f"[!!!] {alert_msg}")

            if self.logger:
                self.logger.log_event("SECURITY_HEURISTIC", "SUSPICIOUS_PATH", proc_name, f"PID:{pid} | Path:{path}")

            auto_mitigated = False
            if self.defender and self.defender.auto_defense:
                res = self.defender.kill_process(pid, reason="Automated mitigation: Process launched from temp/hidden directory")
                auto_mitigated = res.get("success", False)

            self.record_threat(
                threat_type="SUSPICIOUS_PATH_EXECUTION",
                severity="CRITICAL" if any(x in path for x in ["temp", "tmp"]) else "MEDIUM",
                score=92 if any(x in path for x in ["temp", "tmp"]) else 70,
                details={"name": proc_name, "pid": pid, "user": user, "path": path, "sha256": sha256},
                auto_mitigated=auto_mitigated
            )
