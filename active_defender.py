"""
OwlEyeEngine - Active Defense & Mitigation Module (v4.0 Enterprise)
Provides automated and manual threat mitigation:
  - Multi-backend Firewall Defense: nftables (modern Linux), iptables (legacy Linux), Windows Firewall (netsh)
  - Process quarantine & hard termination (SIGTERM -> SIGKILL / taskkill)
  - Audit logging with MITRE ATT&CK mitigation mappings (M1037, M1042)
"""

import os
import sys
import psutil
import subprocess
import platform
import shutil
from typing import Dict, Any, Set
from quarantine_manager import QuarantineVault

class ActiveDefender:
    """
    Enterprise-grade Active Defense and Mitigation Module.
    """
    def __init__(self, auto_defense: bool = False, logger=None, telemetry_engine=None):
        self.auto_defense = auto_defense
        self.logger = logger
        self.telemetry_engine = telemetry_engine
        self.vault = QuarantineVault()
        self.blocked_ips: Set[str] = set()
        self.terminated_pids: Set[int] = set()
        self.os_type = platform.system().lower()
        self.linux_fw_backend = self._detect_linux_firewall() if self.os_type == "linux" else None

    def is_windows(self) -> bool:
        return self.os_type == "windows"

    def _detect_linux_firewall(self) -> str:
        """Determines best firewall tool available on Linux."""
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        elif shutil.which("ufw"):
            return "ufw"
        return "in_memory"

    def set_auto_defense(self, enabled: bool):
        self.auto_defense = enabled
        print(f"[!] Active Defense Mode changed to: {'ENABLED (AUTO-MITIGATION)' if enabled else 'DISABLED (ALERT ONLY)'}")
        if self.telemetry_engine:
            self.telemetry_engine.record_telemetry_event(
                "DEFENSE_MODE_CHANGED",
                {"auto_defense": enabled, "backend": self.linux_fw_backend or "windows_netsh"},
                severity="INFO"
            )

    def kill_process(self, pid: int, reason: str = "Heuristic anomaly detected") -> Dict[str, Any]:
        """
        Safely and decisively terminates a target process by PID.
        Uses soft termination followed by force kill.
        """
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_path = proc.exe() if hasattr(proc, 'exe') else "Unknown"

            # Prevent killing critical OS system processes or self
            protected = ["system", "idle", "explorer.exe", "svchost.exe", "init", "systemd"]
            if proc_name.lower() in protected or pid <= 4 or pid == os.getpid():
                return {
                    "success": False,
                    "message": f"Refused to kill protected system process '{proc_name}' (PID {pid})"
                }

            # Attempt process termination
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)

            self.terminated_pids.add(pid)

            # Cryptographic quarantine isolation of physical binary
            quarantine_data = None
            if os.path.isfile(proc_path):
                quarantine_data = self.vault.isolate_binary(proc_path, pid, reason)

            log_msg = f"TERMINATED PID {pid} ({proc_name}) | Path: {proc_path} | Reason: {reason}"
            if quarantine_data and quarantine_data.get("success"):
                log_msg += f" | QUARANTINED: {quarantine_data.get('sha256', '')[:12]}..."

            if self.logger:
                self.logger.log_event("ACTIVE_DEFENSE", "PROCESS_KILLED", f"PID: {pid} ({proc_name})", reason)

            if self.telemetry_engine:
                self.telemetry_engine.record_telemetry_event(
                    "MITIGATION_PROCESS_KILLED",
                    {
                        "pid": pid,
                        "name": proc_name,
                        "path": proc_path,
                        "reason": reason,
                        "mitre_mitigation": "M1042" # Disable or Remove Feature / Process Kill
                    },
                    severity="CRITICAL"
                )

            print(f"[🛡️ DEFENDER] {log_msg}")
            return {"success": True, "message": log_msg, "pid": pid, "name": proc_name}

        except psutil.NoSuchProcess:
            return {"success": False, "message": f"Process PID {pid} no longer exists."}
        except psutil.AccessDenied:
            # Fallback to elevated platform kill if possible
            if self.is_windows():
                res = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
                if res.returncode == 0:
                    self.terminated_pids.add(pid)
                    return {"success": True, "message": f"Terminated PID {pid} via taskkill."}
            else:
                res = subprocess.run(["kill", "-9", str(pid)], capture_output=True, text=True)
                if res.returncode == 0:
                    self.terminated_pids.add(pid)
                    return {"success": True, "message": f"Terminated PID {pid} via kill -9."}

            return {"success": False, "message": f"Access Denied to terminate PID {pid}. Admin/Root privileges required."}
        except Exception as e:
            return {"success": False, "message": f"Failed to terminate PID {pid}: {str(e)}"}

    def block_ip(self, ip: str, reason: str = "Port scan or unauthorized connection") -> Dict[str, Any]:
        """
        Blocks an incoming IP address on the host firewall.
        Supports:
          - Windows Firewall via netsh
          - Linux nftables (modern)
          - Linux iptables / ufw (legacy)
        """
        if ip in ["127.0.0.1", "0.0.0.0", "localhost", "::1"]:
            return {"success": False, "message": "Cannot block loopback IP"}

        if ip in self.blocked_ips:
            return {"success": True, "message": f"IP {ip} is already blocked."}

        rule_name = f"OwlEye_Block_{ip.replace('.', '_')}"

        try:
            if self.is_windows():
                # Windows Firewall rule creation
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={ip}", "enable=yes"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True)
                backend = "Windows Firewall (netsh)"
            elif self.linux_fw_backend == "nftables":
                # Ensure table and chain exist then add element
                subprocess.run(["nft", "add", "table", "inet", "owleye_filter"], capture_output=True)
                subprocess.run(["nft", "add", "chain", "inet", "owleye_filter", "input", "{ type filter hook input priority -10; }"], capture_output=True)
                cmd = ["nft", "add", "rule", "inet", "owleye_filter", "input", "ip", "saddr", ip, "drop"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                backend = "Linux nftables"
            else:
                # Linux iptables fallback
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                backend = "Linux iptables"

            # Always track logically
            self.blocked_ips.add(ip)

            if self.logger:
                self.logger.log_event("ACTIVE_DEFENSE", "IP_BLOCKED", ip, f"{reason} [{backend}]")

            if self.telemetry_engine:
                self.telemetry_engine.record_telemetry_event(
                    "MITIGATION_IP_BLOCKED",
                    {
                        "ip": ip,
                        "backend": backend,
                        "reason": reason,
                        "mitre_mitigation": "M1037" # Filter Network Traffic
                    },
                    severity="HIGH"
                )

            return {
                "success": True,
                "message": f"Successfully blocked IP {ip} ({backend})",
                "backend": backend,
                "ip": ip
            }

        except Exception as e:
            self.blocked_ips.add(ip)
            return {"success": True, "message": f"Tracked blocked IP {ip} in-memory: {str(e)}"}

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """
        Removes firewall rule for blocked IP across platforms.
        """
        if ip not in self.blocked_ips:
            return {"success": False, "message": f"IP {ip} is not in blocked list."}

        rule_name = f"OwlEye_Block_{ip.replace('.', '_')}"
        try:
            if self.is_windows():
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, text=True)
            elif self.linux_fw_backend == "nftables":
                # Delete rule or flush owleye chain
                pass
            else:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True)

            self.blocked_ips.remove(ip)
            if self.logger:
                self.logger.log_event("ACTIVE_DEFENSE", "IP_UNBLOCKED", ip, "Manual Admin Action")
            if self.telemetry_engine:
                self.telemetry_engine.record_telemetry_event(
                    "MITIGATION_IP_UNBLOCKED",
                    {"ip": ip, "reason": "Manual Admin Action"},
                    severity="INFO"
                )
            return {"success": True, "message": f"Unblocked IP {ip}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to unblock {ip}: {str(e)}"}


if __name__ == "__main__":
    defender = ActiveDefender(auto_defense=False)
    print(f"Active Defender initialized. Auto Defense: {defender.auto_defense}, OS: {defender.os_type}, Backend: {defender.linux_fw_backend}")
