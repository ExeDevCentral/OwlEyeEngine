<div align="center">

# OwlEyeEngine • Kernel eBPF Telemetry & Active Defense
### *Sub-Microsecond Kernel Observability, Autonomous EDR/XDR Defense & OCSF SIEM Integration*

[![Focus: EDR/XDR](https://img.shields.io/badge/Domain-Enterprise_EDR%20%7C%20XDR-blue?style=for-the-badge&logo=shield)](https://github.com/ExeDevCentral/OwlEyeEngine)
[![Kernel: eBPF & ETW](https://img.shields.io/badge/Kernel-Linux_eBPF_%7C_Windows_ETW-purple?style=for-the-badge&logo=linux)](https://ebpf.io/)
[![Telemetry: Prometheus & OCSF](https://img.shields.io/badge/Telemetry-Prometheus_%7C_OCSF_v1.1-orange?style=for-the-badge&logo=prometheus)](https://prometheus.io/)
[![Active Defense](https://img.shields.io/badge/Mitigation-nftables_%7C_iptables_%7C_netsh-critical?style=for-the-badge)](https://netfilter.org/projects/nftables/)
[![API: FastAPI](https://img.shields.io/badge/API-FastAPI_Async_Engine-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald?style=for-the-badge)](https://opensource.org/licenses/MIT)

```text
    ^...^
   / o o \   "Sub-microsecond kernel observability, zero-overhead ring buffers,
   |  Y  |    and deterministic active defense across the system call horizon."
    V v V    OwlEyeEngine v4.0 Enterprise Architecture
```

<p align="center">
  <b>A low-level kernel telemetry and automated active defense platform intercepting syscall transitions via Linux eBPF probes and Windows ETW tracepoints, mapping threat vectors to MITRE ATT&CK, and enforcing instant packet/PID mitigation.</b>
</p>

---

</div>

## 1. Abstract & System Architecture

Traditional user-space endpoint detection agents suffer from inherent blind spots: unhookable syscall wrappers, user-space tampering, and memory latency overhead.

**OwlEyeEngine** operates directly at the operating system kernel boundary:
- **Kernel-Space Hooking:** Injects non-blocking **eBPF C probes** (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_kill`) within Linux, and Event Tracing for Windows (**ETW**) on NT kernels, extracting telemetry into lockless ring buffers with sub-microsecond latency.
- **MITRE ATT&CK Matrix Correlation:** Heuristic engine continuously evaluates execution traces against tactical matrices (Execution, Discovery, C2, Privilege Escalation).
- **Automated Active Mitigation:** Instant bidirectional firewall injection via `nftables` / `iptables` / `netsh` and deterministic task eviction (`SIGKILL`) upon malicious signature threshold breach.
- **OCSF & Prometheus Integration:** Direct export to modern SOC infrastructure via **Open Cybersecurity Schema Framework (OCSF v1.1)** and native Prometheus `/metrics`.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        KERNEL SPACE OBSERVABILITY                      │
│   [eBPF C Probes / Tracepoints] ──► [Lockless BPF Ring Buffer]         │
│   [Windows ETW Kernel Sessions] ──► [Sub-Microsecond Dispatch]         │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 HEURISTIC CORRELATION & THREAT TRIAGE                  │
│    • MITRE ATT&CK Engine (T1059, T1046, T1071, T1036, T1068)           │
│    • Tokenized Behavioral Classifier: Anomaly Scoring Vector           │
│    • System Call Frequency Analysis: $\Delta \tau_{\text{burst}}$      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌──────────────────────────────────┐        ┌──────────────────────────────────┐
│      TELEMETRY EXPORT ENGINE     │        │     AUTONOMOUS ACTIVE DEFENDER   │
│   Prometheus `/metrics` Scraper  │        │   Kernel `nftables` Drop Rules   │
│   OCSF v1.1 JSON Batch Streamer  │        │   Deterministic Process Eviction │
│   Server-Sent Events (SSE) Wire  │        │   Quarantine Vault Isolation     │
└──────────────────────────────────┘        └──────────────────────────────────┘
```

---

## 2. Low-Level Kernel Specifications & Mathematical Formalism

### 2.1. Kernel-Space Syscall Interception (`ebpf_probe.c`)
Probes hook into the tracepoint subsystem, eliminating context-switch penalties:
- `tracepoint/syscalls/sys_enter_execve`: Traverses process argument vectors and environment flags.
- `tracepoint/syscalls/sys_enter_connect`: Captures target IPv4/IPv6 socket structures prior to TCP handshake completion.
- `tracepoint/syscalls/sys_enter_kill`: Audits inter-process signal terminations to prevent watchdog evasion.

### 2.2. Ring Buffer Burst & Ingestion Rate
Let $E_i$ represent a kernel event tuple $\langle \text{PID}, \text{Syscall}, \text{Timestamp}, \vec{\theta} \rangle$. The circular BPF ring buffer throughput adheres to:

$$\mathcal{T}_{\text{drain}} \ge \sum_{k=1}^{M} \lambda_k \cdot \text{sizeof}(E_k)$$

Where lockless atomic head/tail pointers guarantee zero packet loss under sustained burst volumes ($\ge 50\,000 \text{ events/sec}$).

---

## 3. MITRE ATT&CK Matrix Alignment

| Tactic | Technique ID | Behavioral Pattern Detected | Active Defense Triggered |
| :--- | :--- | :--- | :--- |
| **Execution** | T1059.004 | Shell spawning from non-interactive system daemons | Process group termination (`SIGKILL`) |
| **Discovery** | T1046 | Systematic TCP SYN scanning across subnet blocks | Instant IP isolation via `nftables drop` |
| **Command & Control** | T1071 | Uncorrelated outbound sockets to threat intel feeds | Socket eviction & routing sinkhole |
| **Defense Evasion** | T1036 | Execution of stripped binaries originating from `/tmp` | File isolation to Quarantine Vault |
| **Privilege Escalation**| T1055 | Foreign memory injection and unapproved `ptrace` hooks | Memory segment unmapping & audit alert |

---

## 4. Systems Directory Hierarchy

```text
OwlEyeEngine/
├── ebpf_probe.c             # C source for Linux kernel eBPF tracepoint probes
├── kernel_telemetry.py      # Python BPF/ETW ring buffer consumer & telemetry mapper
├── active_defender.py       # nftables, iptables & netsh firewall injection engine
├── heuristic_analyzer.py    # MITRE ATT&CK tactical correlation & anomaly scoring
├── sentry.py                # Main daemon supervisor & event dispatcher
├── owleye_cli.py            # Administrative CLI for operations & SOC analysts
├── web_dashboard.py         # FastAPI async REST API & telemetry streamer
├── packaging/
│   ├── systemd/             # Hardened systemd service descriptor (`owleye.service`)
│   └── install_enterprise.sh# Automated enterprise installation script
└── quarantine_vault/        # Cryptographically isolated malware containment
```

---

## 5. Development Runtime & Operational Lifecycle

### Prerequisites
- **Linux Kernel**: $\ge 5.8$ (with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_NETFILTER=y`) or **Windows 10/11 / Server 2019+**
- **Python**: $\ge 3.10$ LTS

### Installation & Deployment

#### Option A: Automated Linux Enterprise Node Deployment
```bash
# Clone the repository
git clone https://github.com/ExeDevCentral/OwlEyeEngine.git
cd OwlEyeEngine

# Execute enterprise installer (probes, dependencies & systemd registration)
sudo bash packaging/install_enterprise.sh

# Verify operational status
sudo systemctl status owleye
```

#### Option B: Standalone Python Runtime (Development & Testing)
```bash
# Install core dependencies and package in editable mode
pip install -r requirements.txt
pip install -e .

# Launch security engine daemon
python sentry.py
```

#### Option C: Dockerized Deployment
```bash
# Production deployment with Linux kernel capabilities
docker compose up -d owleye

# Staging demo mode
docker compose --profile demo up -d owleye-demo
```

---

## 6. Command Line Interface (`owleye`)

The platform includes a dedicated systems CLI for SOC analysts and site reliability engineers:

```bash
# Probe agent health, kernel hooks, and memory allocation
owleye status

# Inspect host kernel capabilities (eBPF, JIT compiler, ETW, Netlink)
owleye kernel

# Stream intercepted system calls live to stdout
owleye stream

# Fetch instantaneous Prometheus metrics snapshot
owleye metrics

# Dynamically inject IP isolation rule into kernel firewall
owleye block 198.51.100.7 --reason "Brute-force attack detected"
owleye unblock 198.51.100.7

# Forcefully evict malicious process tree by PID
owleye kill 4921 --reason "Unauthorized binary execution in /tmp"
```

---

## 7. Telemetry & Integration Endpoints

| Endpoint | Protocol | Payload Type | Description |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `OpenMetrics` | Direct Prometheus / Datadog scraping endpoint |
| `/api/kernel/status` | `GET` | `JSON` | Hook latency (µs), throughput, and ring buffer utilization |
| `/api/telemetry/stream`| `GET` | `SSE` | Real-time Server-Sent Events stream for live SOC terminals |
| `/api/telemetry/export`| `GET` | `JSON` | OCSF v1.1 compliance batches for SIEM ingestion |
| `/api/mitre/matrix` | `GET` | `JSON` | Live threat distribution mapped to MITRE ATT&CK |
| `/api/actions/kill` | `POST` | `JSON` | Active mitigation: Targeted process tree eviction |
| `/api/actions/block_ip`| `POST` | `JSON` | Active mitigation: Kernel firewall block injection |
| `/dashboard` | `GET` | `HTML` | Interactive low-latency Cyberpunk Operations Dashboard |

---

## 8. License

Distributed under the **MIT License**. Engineered for defensive cybersecurity research and enterprise host observability.

<div align="center">
  <sub>Engineered by <a href="https://github.com/ExeDevCentral">ExeDevCentral</a>.</sub>
</div>
