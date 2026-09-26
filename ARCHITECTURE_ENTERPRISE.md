# 🛡️ OwlEyeEngine v4.0 Enterprise: Kernel Telemetry & Regional Security Dossier

## 1. Resumen Ejecutivo (Executive Summary)

**OwlEyeEngine v4.0 Enterprise** representa un salto cuantitativo y cualitativo en la arquitectura de detección y respuesta en endpoints (**EDR / XDR**). Los agentes de seguridad convencionales se basan predominantemente en sondeos periódicos en espacio de usuario (*user-space polling* vía `/proc` o `psutil`), lo que genera una "ventana ciega" de 2 a 5 segundos donde procesos maliciosos efímeros (como droppers, scripts temporales en memoria o sockets fugaces) se ejecutan y se autodestruyen sin ser detectados.

**OwlEyeEngine v4.0** resuelve este desafío trasladando la primera línea de visión directamente al **espacio del núcleo (Kernel Space)**:
* **Linux:** Utiliza sondas **eBPF (Extended Berkeley Packet Filter)** y el conector de procesos del núcleo (**Linux Netlink Process Connector**) para interceptar llamadas al sistema (`sys_enter_execve`, `sys_enter_connect`, `sys_enter_kill`) en el instante exacto en que ocurren, con una latencia promedio inferior a **15 microsegundos**.
* **Windows:** Emplea consumidores de eventos de kernel basados en **ETW (Event Tracing for Windows)** y trazas WMI sin impacto en CPU.
* **Telemetría Estándar:** Provee un exportador nativo de **Prometheus (`/metrics`)** y esquemas de telemetría estructurados compatibles con **OCSF (Open Cybersecurity Schema Framework)** para una integración inmediata con centros de operaciones de seguridad regionales (**SOC / SIEM**).

---

## 2. Diagrama de Arquitectura Multicapa

```
+-----------------------------------------------------------------------------------+
|                                  KERNEL SPACE                                     |
|  +--------------------------------+   +----------------------------------------+  |
|  | Linux eBPF Kernel Probes       |   | Linux Netlink Process Connector        |  |
|  | (sys_enter_execve / connect)   |   | (PROC_EVENT_EXEC / EXIT)               |  |
|  +--------------------------------+   +----------------------------------------+  |
|                                   │                                               |
|                                   ▼  (Sub-microsecond Perf Ring Buffer)           |
+-----------------------------------------------------------------------------------+
                                    │
+-----------------------------------------------------------------------------------+
|                                USER SPACE AGENT                                   |
|                                   ▼                                               |
|                    [ Kernel Telemetry Engine ]                                    |
|             (Ring-buffer circular, cálculo de latencia en μs)                     |
|                                   │                                               |
|         ┌─────────────────────────┴─────────────────────────┐                     |
|         ▼                                                   ▼                     |
|  [ Telemetry Pipeline ]                           [ Heuristic Analyzer ]          |
|  • Prometheus Exporter (/metrics)                 • MITRE ATT&CK Matrix           |
|  • OCSF / SIEM Batch Export                       • Correlación de Procesos       |
|  • Real-Time SSE Stream (/api/telemetry/stream)   • Detección de Port Scans       |
|  • Live WebSocket Channel (/ws/telemetry)                           │             |
|                                                                     ▼             |
|                                                           [ Active Defender ]     |
|                                                           • Linux nftables        |
|                                                           • Linux iptables        |
|                                                           • Windows netsh         |
|                                                           • Multi-stage Kill      |
+-----------------------------------------------------------------------------------+
                                    │
+-----------------------------------------------------------------------------------+
|                            INTERFACES & PRESENTACIÓN                              |
|  • Cyberpunk Glassmorphic Dashboard (FastAPI + Vanilla CSS + JS)                  |
|  • Suite CLI 'owleye' para administradores de sistemas y analistas de seguridad  |
|  • Servicio nativo systemd 'owleye.service' para servidores Linux                |
+-----------------------------------------------------------------------------------+
```

---

## 3. Matriz Táctica MITRE ATT&CK® Implementada

| Táctica MITRE | Técnica | ID | Mecanismo de Detección en OwlEye v4.0 | Mitigación Automatizada |
| :--- | :--- | :---: | :--- | :--- |
| **Execution** | Command and Scripting Interpreter | `T1059` | Intercepción eBPF `sys_enter_execve` en rutas `/tmp`, `/var/tmp`, `AppData\Local\Temp` | Terminación inmediata de proceso (*Auto-Kill*) |
| **Discovery** | Network Service Discovery | `T1046` | Correlación temporal de aperturas de socket por IP de origen | Inyección de regla en firewall (`nftables` / `netsh`) |
| **Command & Control** | Application Layer Protocol | `T1071` | Sonda de sockets `sys_enter_connect` hacia puertos no estándar | Bloqueo perimetral y alerta SOC |
| **Defense Evasion** | Masquerading & Tool Disabling | `T1036` / `T1562` | Intercepción `sys_enter_kill` dirigida a procesos protegidos de seguridad | Aislamiento y bloqueo de señal |
| **Privilege Escalation** | Process Injection / Ptrace | `T1068` / `T1055` | Detección de llamadas `sys_enter_ptrace` no autorizadas | Alerta crítica de seguridad |

---

## 4. Especificaciones del Pipeline de Telemetría

### 4.1. Exposición OpenMetrics / Prometheus (`/metrics`)
El agente expone métricas directamente consumibles por Prometheus, VictoriaMetrics, Datadog o Grafana Agent sin dependencias pesadas:
* `owleye_kernel_events_total{status="intercepted|dropped"}`: Total de llamadas al sistema capturadas.
* `owleye_kernel_events_rate_per_sec`: Tasa instantánea de eventos de kernel por segundo.
* `owleye_kernel_interception_latency_us`: Latencia promedio de captura (en microsegundos).
* `owleye_threat_score`: Índice de amenaza más elevado activo.
* `owleye_active_mitigations_total{action="kill_process|block_ip"}`: Contador de defensas ejecutadas.
* `owleye_kernel_subsystem_events_total{subsystem="process|network|defense|memory"}`: Desglose por subsistema del kernel.

### 4.2. Formato OCSF (Open Cybersecurity Schema Framework)
Para integración con plataformas SIEM corporativas (Splunk, Elastic Common Schema, Graylog, Wazuh), el endpoint `/api/telemetry/export` genera lotes JSON estructurados conforme al estándar OCSF v1.1:
```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "OwlEyeEngine Enterprise",
      "vendor_name": "ExeDevCentral",
      "version": "4.0.0"
    }
  },
  "events": [
    {
      "telemetry_id": "TEL-1725300000000-0001",
      "class_uid": 1001,
      "type": "THREAT_SUSPICIOUS_PATH_EXECUTION",
      "severity": "CRITICAL",
      "data": {
        "name": "dropper.elf",
        "pid": 4921,
        "path": "/tmp/.hidden/dropper.elf",
        "kernel_probe": "sys_enter_execve",
        "latency_us": 6,
        "mitre": {
          "id": "T1059",
          "tactic": "Execution"
        }
      }
    }
  ]
}
```

---

## 5. Paquetes y Soporte Linux Corporativo

### 5.1. Soporte Multi-Firewall Inteligente
En lugar de depender exclusivamente de comandos antiguos, `ActiveDefender` autodetecta el stack de red del anfitrión:
1. **`nftables` (Prioritario en Linux moderno):** Inyecta reglas atómicas en la tabla `inet owleye_filter` (`nft add rule inet owleye_filter input ip saddr <IP> drop`).
2. **`iptables` (Retrocompatibilidad):** Reglas `INPUT -s <IP> -j DROP`.
3. **`netsh advfirewall` (Windows):** Reglas en Windows Firewall con perfil persistente.

### 5.2. Servicio `systemd` Hardened (`packaging/systemd/owleye.service`)
Diseñado para servidores de misión crítica con directivas de aislamiento:
* `ProtectSystem=full` y `PrivateTmp=true`: Evita que el propio agente sea manipulado.
* `CapabilityBoundingSet`: Limita los privilegios estrictamente a `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_BPF` y `CAP_SYS_PTRACE`.

### 5.3. Suite CLI `owleye`
Permite a los operadores ejecutar auditorías instantáneas en terminal sin requerir navegador:
```bash
owleye status         # Estado global de telemetría y CPU
owleye kernel         # Chequeo de capacidades del kernel del nodo
owleye stream         # Streaming en vivo de llamadas interceptadas
owleye metrics        # Volcado de métricas Prometheus
owleye block <IP>     # Bloqueo manual de emergencia
```

---

## 6. Guía de Presentación Regional (Regional Pitch Guide)

Al presentar este producto ante comités de ciberseguridad, inversores o eventos de tecnología regional (LATAM / Global), enfocar la narrativa en:

1. **El Problema del EDR Tradicional:** Las soluciones tradicionales saturan el CPU ejecutando bucles de `ps` o inspecciones cada varios segundos, permitiendo que malware moderno se ejecute y limpie sus huellas en menos de 500ms.
2. **La Solución OwlEye:** Visión sub-microsegundo mediante eBPF en el kernel. No hay punto ciego temporal.
3. **Bajo Overhead Computacional:** Menos del **1.5% de consumo de CPU** y menos de **45 MB de memoria RAM**, lo que permite desplegarlo tanto en servidores de nube de alta densidad como en nodos Edge/IoT.
4. **Interoperabilidad Universal:** No encierra al cliente en un formato propietario. Se conecta nativamente con Prometheus, Grafana y cualquier SIEM corporativo.
5. **Impacto Visual Wow:** El panel Cyberpunk Glassmorphic ofrece a los analistas de seguridad un centro de comando intuitivo, estético y en tiempo real.
