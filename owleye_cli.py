#!/usr/bin/env python3
"""
OwlEyeEngine - Enterprise Command Line Interface (CLI)
Usage:
    owleye status                Check engine, kernel hooks and defense state
    owleye kernel                Check kernel capabilities and eBPF support
    owleye stream                Live stream kernel intercepted syscalls
    owleye metrics               Dump Prometheus OpenMetrics snapshot
    owleye block <ip> [reason]   Block an IP address via host firewall
    owleye unblock <ip>          Unblock an IP address
    owleye kill <pid>            Terminate suspicious process by PID
    owleye daemon [--port PORT]  Run OwlEyeEngine daemon
"""

import sys
import os
import argparse
import time
import requests
import json
import platform

DEFAULT_URL = os.getenv("OWLEYE_API_URL", "http://localhost:8000")

def print_banner():
    banner = r"""
  ___           _ _____            _____             _            
 / _ \__      _| | ____|   _  ___ | ____|_ __   __ _(_)_ __   ___ 
| | | \ \ /\ / / |  _|| | | |/ _ \|  _| | '_ \ / _` | | '_ \ / _ \
| |_| |\ V  V /| | |__| |_| |  __/| |___| | | | (_| | | | | |  __/
 \___/  \_/\_/ |_|_____\__, |\___||_____|_| |_|\__, |_|_| |_|\___|
                       |___/                   |___/   v4.0 Enterprise
    """
    print(banner)

def check_status(api_url=DEFAULT_URL):
    try:
        res = requests.get(f"{api_url}/api/status", timeout=3)
        if res.status_code == 200:
            data = res.json()
            print_banner()
            print("==================================================")
            print(f"[*] Engine Status:       \033[92m{data.get('status')}\033[0m")
            print(f"[*] Engine Version:      {data.get('engine')}")
            print(f"[*] Uptime:              {data.get('uptime')}")
            print(f"[*] Operation Mode:      {'DEMO / PRESENTATION' if data.get('demo_mode') else 'PRODUCTION (Kernel Active)'}")
            print("--------------------------------------------------")
            k = data.get("kernel_telemetry", {})
            print(f"[*] Kernel Probe:        \033[96m{k.get('probe_type')}\033[0m")
            print(f"[*] Kernel Syscalls/s:   {k.get('events_per_second')}")
            print(f"[*] Kernel Latency:      {k.get('avg_latency_us')} μs")
            print(f"[*] Ring Buffer Usage:   {k.get('ring_buffer_usage_pct')}%")
            print("--------------------------------------------------")
            d = data.get("active_defense", {})
            mode_color = "\033[92m" if d.get('auto_defense') else "\033[93m"
            print(f"[*] Active Defense:      {mode_color}{'ENABLED (AUTO-KILL)' if d.get('auto_defense') else 'ALERT ONLY'}\033[0m")
            print(f"[*] Firewall Backend:    {d.get('backend', 'N/A')}")
            print(f"[*] Blocked IPs Count:   {d.get('blocked_ips_count')}")
            print(f"[*] Terminated PIDs:     {d.get('terminated_pids_count')}")
            print("--------------------------------------------------")
            sys_info = data.get("system", {})
            print(f"[*] CPU Utilization:     {sys_info.get('cpu_percent')}%")
            print(f"[*] Memory Usage:        {sys_info.get('memory_used_mb')} MB / {sys_info.get('memory_total_mb')} MB ({sys_info.get('memory_percent')}%)")
            print("==================================================")
        else:
            print(f"[X] API returned code {res.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"[X] Could not connect to OwlEyeEngine daemon at {api_url}.")
        print("[*] Tip: Start the daemon with 'python sentry.py' or run 'owleye daemon'")

def check_kernel():
    from kernel_telemetry import KernelTelemetryEngine
    k = KernelTelemetryEngine()
    caps = k.capabilities
    print_banner()
    print("[*] OwlEye Host Kernel Capability Assessment:")
    print("--------------------------------------------------")
    print(f"[*] Operating System:        {caps['os'].upper()} ({caps['kernel_release']})")
    print(f"[*] Kernel Version:         {caps['kernel_version']}")
    print(f"[*] eBPF Support:           {'[+] DETECTED / SUPPORTED' if caps['ebpf_supported'] else '[-] NOT DETECTED'}")
    print(f"[*] Tracepoints:            {'[+] AVAILABLE' if caps['tracepoints_supported'] else '[-] UNAVAILABLE'}")
    print(f"[*] Netlink Connector:      {'[+] AVAILABLE' if caps['netlink_connector_supported'] else '[-] N/A'}")
    print(f"[*] Windows ETW:            {'[+] AVAILABLE' if caps['etw_supported'] else '[-] N/A'}")
    print(f"[*] Active Probe Selected:  \033[96m{caps['active_probe_type']}\033[0m")
    print("--------------------------------------------------")

def stream_telemetry(api_url=DEFAULT_URL):
    print(f"[*] Connecting to live kernel telemetry stream at {api_url}...")
    try:
        import requests
        with requests.get(f"{api_url}/api/telemetry/stream", stream=True, timeout=60) as r:
            for line in r.iter_lines():
                if line:
                    decoded = line.decode('utf-8')
                    if decoded.startswith("data: "):
                        raw = decoded[6:]
                        try:
                            ev = json.loads(raw)
                            sub = ev.get("subsystem", "SYS")
                            sysc = ev.get("syscall", "unknown")
                            comm = ev.get("comm", "unknown")
                            pid = ev.get("pid", 0)
                            lat = ev.get("latency_us", 0)
                            tactic = ev.get("mitre", {}).get("tactic", "General")
                            print(f"\033[96m[{sub}]\033[0m \033[92m{sysc}\033[0m PID:{pid} ({comm}) | Latency: {lat}μs | MITRE: {tactic}")
                        except Exception:
                            print(decoded)
    except KeyboardInterrupt:
        print("\n[*] Stream closed by user.")
    except Exception as e:
        print(f"[X] Stream error: {e}")

def dump_metrics(api_url=DEFAULT_URL):
    try:
        res = requests.get(f"{api_url}/metrics", timeout=3)
        if res.status_code == 200:
            print(res.text)
        else:
            print(f"[X] Prometheus endpoint error: {res.status_code}")
    except Exception as e:
        print(f"[X] Failed to fetch metrics: {e}")

def block_ip_cmd(ip, reason="CLI Admin Block", api_url=DEFAULT_URL):
    try:
        res = requests.post(f"{api_url}/api/actions/block_ip", json={"ip": ip, "reason": reason}, timeout=5)
        print(res.json().get("message", res.text))
    except Exception as e:
        print(f"[X] Action failed: {e}")

def unblock_ip_cmd(ip, api_url=DEFAULT_URL):
    try:
        res = requests.post(f"{api_url}/api/actions/unblock_ip", json={"ip": ip}, timeout=5)
        print(res.json().get("message", res.text))
    except Exception as e:
        print(f"[X] Action failed: {e}")

def kill_pid_cmd(pid, reason="CLI Admin Kill", api_url=DEFAULT_URL):
    try:
        res = requests.post(f"{api_url}/api/actions/kill", json={"pid": int(pid), "reason": reason}, timeout=5)
        print(res.json().get("message", res.text))
    except Exception as e:
        print(f"[X] Action failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="OwlEyeEngine Enterprise CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Show system, kernel and defense status")
    subparsers.add_parser("kernel", help="Inspect OS kernel capabilities")
    subparsers.add_parser("stream", help="Live stream kernel syscall telemetry")
    subparsers.add_parser("metrics", help="Print Prometheus OpenMetrics format")

    p_block = subparsers.add_parser("block", help="Block IP address on host firewall")
    p_block.add_argument("ip", help="IP address to block")
    p_block.add_argument("--reason", default="CLI Admin Block", help="Reason for block")

    p_unblock = subparsers.add_parser("unblock", help="Unblock IP address on host firewall")
    p_unblock.add_argument("ip", help="IP address to unblock")

    p_kill = subparsers.add_parser("kill", help="Terminate process by PID")
    p_kill.add_argument("pid", type=int, help="Target process PID")
    p_kill.add_argument("--reason", default="CLI Admin Kill", help="Reason for termination")

    p_daemon = subparsers.add_parser("daemon", help="Run OwlEyeEngine daemon")
    p_daemon.add_argument("--port", type=int, default=8000, help="Web dashboard port")

    args = parser.parse_args()

    if args.command == "status":
        check_status()
    elif args.command == "kernel":
        check_kernel()
    elif args.command == "stream":
        stream_telemetry()
    elif args.command == "metrics":
        dump_metrics()
    elif args.command == "block":
        block_ip_cmd(args.ip, args.reason)
    elif args.command == "unblock":
        unblock_ip_cmd(args.ip)
    elif args.command == "kill":
        kill_pid_cmd(args.pid, args.reason)
    elif args.command == "daemon":
        os.environ["OWLEYE_PORT"] = str(args.port)
        import sentry
        sentry.main()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
