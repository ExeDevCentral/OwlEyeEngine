"""
OwlEyeEngine - Low-Level Process Monitor with Lineage & Command-Line Telemetry (v4.0 Enterprise)
Captures:
  - Process PID, Name, User, Executable Path
  - Full Command-Line arguments (cmdline)
  - Parent Process ID (PPID) & Parent Name (Lineage / Ancestry)
  - Binary SHA-256 hash calculation
"""

import psutil
import time
import os
import hashlib
from typing import List, Dict, Any, Optional

def get_file_sha256(filepath: str) -> Optional[str]:
    """Calculates SHA-256 hash of executable file."""
    if not filepath or not os.path.isfile(filepath):
        return None
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(32768), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

class ProcessMonitor:
    def __init__(self):
        self.running_pids = set()
        self._initialize_pids()

    def _initialize_pids(self):
        for proc in psutil.process_iter(['pid']):
            self.running_pids.add(proc.info['pid'])

    def check_new_processes(self) -> List[Dict[str, Any]]:
        """
        Scans for new process executions, extracting forensic details,
        command line arguments, parent lineage and binary hash.
        """
        new_events = []
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'ppid', 'create_time']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                if pid not in self.running_pids:
                    # Capture deep forensic details
                    path = proc.info.get('exe') or "Unknown"
                    ppid = proc.info.get('ppid') or 0
                    
                    # Command line arguments
                    try:
                        cmdline_args = proc.cmdline()
                        cmdline_str = " ".join(cmdline_args)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        cmdline_str = ""

                    # Parent process identification
                    parent_name = "System"
                    try:
                        parent = proc.parent()
                        if parent:
                            parent_name = parent.name()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    # Binary hash
                    sha256_hash = get_file_sha256(path) if path != "Unknown" else None

                    info = {
                        "pid": pid,
                        "ppid": ppid,
                        "parent_name": parent_name,
                        "name": proc.info.get('name') or "Unknown",
                        "user": proc.info.get('username') or "N/A",
                        "path": path,
                        "cmdline": cmdline_str,
                        "sha256": sha256_hash,
                        "created": proc.info.get('create_time')
                    }
                    new_events.append(info)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.running_pids = current_pids
        return new_events

if __name__ == "__main__":
    monitor = ProcessMonitor()
    print("Forensic Process Monitor active. Spawn a process to test...")
    try:
        while True:
            new_procs = monitor.check_new_processes()
            for p in new_procs:
                print(f"[+] PID: {p['pid']} | PPID: {p['ppid']} ({p['parent_name']}) | Name: {p['name']} | Cmd: {p['cmdline'][:80]} | SHA: {p['sha256']}")
            time.sleep(1.5)
    except KeyboardInterrupt:
        pass
