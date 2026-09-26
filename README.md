# 🦉 OwlEyeEngine: Kernel Telemetry & Active Defense (v4.0 Enterprise Edition)

![OwlEye Logo](owl_eye.png)

![Cybersecurity Shield](https://img.shields.io/badge/Focus-Enterprise%20EDR%20%7C%20XDR-blue?style=for-the-badge&logo=shield)
![Kernel eBPF](https://img.shields.io/badge/Kernel-Linux%20eBPF%20%7C%20ETW-purple?style=for-the-badge&logo=linux)
![Telemetry](https://img.shields.io/badge/Telemetry-Prometheus%20%7C%20OCSF-orange?style=for-the-badge&logo=prometheus)
![Platform Support](https://img.shields.io/badge/Platform-Linux%20(Systemd)%20%7C%20Windows-brightgreen?style=for-the-badge)
![Active Defense](https://img.shields.io/badge/Defense-nftables%20%7C%20iptables%20%7C%20netsh-red?style=for-the-badge)
![Dashboard](https://img.shields.io/badge/UI-FastAPI%20Cyberpunk%20Dashboard-cyan?style=for-the-badge)

```text
    ^...^
   / o o \   "Silent flight, sub-microsecond kernel vision, total active defense.
   |  Y  |    The predator the intruder never hears... until it strikes."
    V v V    OwlEyeEngine v4.0 Enterprise & Regional Edition
```

**OwlEyeEngine v4.0 Enterprise** es una plataforma integral de ciberseguridad, deteccion a nivel kernel (**eBPF & ETW**) y defensa activa automatizada. Inspirado en la naturaleza del buho (cazador nocturno con vision de 360 grados), este motor trasciende el monitoreo tradicional en espacio de usuario para ofrecer **telemetria en tiempo real**, **intercepcion de syscalls con latencia de microsegundos**, exportacion estandar a **Prometheus / SIEM**, soporte nativo para **Linux con nftables/systemd**, y un panel de comando interactivo futurista preparado para demostraciones y despliegues a nivel regional.

---

## ⚡ Novedades de la Version 4.0 Enterprise

1. **🔬 Telemetria a Nivel Kernel (Linux eBPF & Windows ETW):**
   - Intercepcion de eventos de proceso (`sys_enter_execve`), conexiones de red (`sys_enter_connect`) y senales de terminacion (`sys_enter_kill`) directamente en el kernel del sistema operativo.
   - Sonda C para eBPF en [`ebpf_probe.c`](file:///c:/Users/exeme/Desktop/owl/OwlEyeEngine-main/OwlEyeEngine-main/ebpf_probe.c) compatible con BCC, tracepoints y Netlink Process Connector.
   - Ring Buffer circular con calculo instantaneo de llamadas por segundo, microsegundos de latencia y porcentaje de utilizacion.

2. **🌐 Pipeline de Telemetria Abierta & Prometheus Exporter:**
   - Endpoint nativo `/metrics` en formato OpenMetrics compatible con Prometheus, Grafana Agent, VictoriaMetrics y Datadog.
   - Streaming en vivo via **Server-Sent Events (SSE)** en `/api/telemetry/stream` y WebSockets `/ws/telemetry`.
   - Exportacion de lotes de auditoria en formato **OCSF (Open Cybersecurity Schema Framework)** para integracion directa con SIEM (Splunk, Elastic, Wazuh).

3. **🐧 Soporte Linux de Primera Clase & Empaquetado:**
   - Soporte nativo para cortafuegos **`nftables`** (estandar en Debian 11/12, Ubuntu 22/24, RHEL 9) con retrocompatibilidad para **`iptables`** y Windows Firewall (`netsh`).
   - Servicio del sistema **systemd** listo para produccion en [`packaging/systemd/owleye.service`](file:///c:/Users/exeme/Desktop/owl/OwlEyeEngine-main/OwlEyeEngine-main/packaging/systemd/owleye.service) con directivas de hardening (`ProtectSystem=full`, `CAP_BPF`, `CAP_NET_ADMIN`).
   - Herramienta de linea de comandos **`owleye`** ([`owleye_cli.py`](file:///c:/Users/exeme/Desktop/owl/OwlEyeEngine-main/OwlEyeEngine-main/owleye_cli.py)) instalable via `pip install -e .`.
   - Script instalador corporativo [`packaging/install_enterprise.sh`](file:///c:/Users/exeme/Desktop/owl/OwlEyeEngine-main/OwlEyeEngine-main/packaging/install_enterprise.sh).

4. **🎯 Mapeo Tactico MITRE ATT&CK:**
   - Detecciones correlacionadas con la taxonomia MITRE:
     - **Execution (T1059 / T1059.004):** Rastreo de scripts e interpretes en eBPF.
     - **Discovery (T1046):** Deteccion heuristica de barrido de puertos.
     - **Command & Control (T1071):** Intercepcion de sockets de salida anomalos.
     - **Defense Evasion (T1036):** Deteccion de binarios en `/tmp` o directorios temporales ocultos.
     - **Privilege Escalation (T1068 / T1055):** Sonda de llamadas `ptrace` y manipulacion de memoria.

5. **🖥️ Command Center Futurista (Glassmorphic Cyberpunk):**
   - Nueva pestana **`Kernel & Telemetry`** con metricas en tiempo real, matriz interactiva MITRE ATT&CK, terminal de telemetria en streaming y centro de exportacion para SOCs.

---

## 🏛️ Arquitectura del Sistema v4.0

```text
[ Kernel Space: eBPF / Tracepoints / Netlink / ETW ]
                     │  (sub-microsecond ring buffer)
                     ▼
           [ Kernel Telemetry Engine ]
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
[ Telemetry Pipeline ]   [ Heuristic Analyzer & MITRE ]
 (Prometheus /metrics)           │
 (OCSF / SIEM Export)            ▼
 (SSE & WS Live Feed)    [ Active Defender: nftables / kill ]
```

---

## 🚀 Instalacion y Despliegue

### Opcion A: Instalador Rapido en Linux (Servidores & Nodos)

```bash
git clone https://github.com/ExeDevCentral/OwlEyeEngine.git
cd OwlEyeEngine

# Ejecutar el instalador corporativo (requiere sudo para sondas y systemd)
sudo bash packaging/install_enterprise.sh
```

El script configurara automaticamente las sondas de kernel, instalara el paquete Python en modo editable, registrara y habilitara el servicio `systemd`:
```bash
sudo systemctl status owleye
```

### Opcion B: Instalacion Rapida Local en Python

```bash
pip install -r requirements.txt
pip install -e .

# Iniciar el motor en modo produccion (o demo si no cuenta con privilegios)
python sentry.py
```

### Opcion C: Despliegue en Docker con Capacidades de Kernel

```bash
# Modo produccion con capacidades BPF
docker compose up -d owleye

# Modo Demo para presentaciones regionales y testing
docker compose --profile demo up -d owleye-demo
```

---

## 💻 Herramienta CLI (`owleye`)

La version 4.0 incluye una suite de linea de comandos para administradores y analistas SOC:

```bash
# Diagnosticar estado del motor, sondas activas y telemetria
owleye status

# Evaluar capacidades del kernel anfitrion (eBPF, Netlink, ETW, JIT)
owleye kernel

# Transmision en tiempo real de llamadas al sistema interceptadas
owleye stream

# Obtener snapshot de metricas Prometheus
owleye metrics

# Bloquear o desbloquear una IP en el cortafuegos del host
owleye block 198.51.100.7 --reason "Ataque de fuerza bruta detectado"
owleye unblock 198.51.100.7

# Finalizar proceso malicioso por PID
owleye kill 4921 --reason "Binario no autorizado en /tmp"
```

---

## 📊 Endpoints de Telemetria & API REST

| Endpoint | Metodo | Descripcion | Formato |
| :--- | :---: | :--- | :--- |
| `/metrics` | `GET` | Scraping de Prometheus / VictoriaMetrics / Grafana | `text/plain (OpenMetrics)` |
| `/api/kernel/status` | `GET` | Estado de sondas de kernel, latencia (us) y rendimiento | `application/json` |
| `/api/kernel/events` | `GET` | Ultimos eventos interceptados en el ring-buffer de kernel | `application/json` |
| `/api/telemetry/stream` | `GET` | Flujo en vivo de telemetria por Server-Sent Events (SSE) | `text/event-stream` |
| `/api/telemetry/export` | `GET` | Exportacion de auditoria en estandar OCSF v1.1 para SIEM | `application/json` |
| `/api/mitre/matrix` | `GET` | Matriz regional de amenazas alineada a MITRE ATT&CK | `application/json` |
| `/api/status` | `GET` | Estado del agente, CPU, memoria, uptime y defensa activa | `application/json` |
| `/api/actions/kill` | `POST` | Mitigacion activa: Terminacion segura y forzada de PID | `application/json` |
| `/api/actions/block_ip` | `POST` | Mitigacion activa: Inyeccion de regla en firewall | `application/json` |
| `/dashboard` | `GET` | Interfaz grafica interactiva Cyberpunk | `text/html` |

---

## 🌟 Firma & Creditos

Desarrollado y mantenido por **ExeDevCentral**.
Diseno de interfaz y experiencia de usuario cyberpunk: **[Exepaginasweb.com](https://exepaginasweb.com)**.
Licencia MIT.
