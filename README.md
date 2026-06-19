<p align="center">
  <img src="https://img.shields.io/badge/SOC%20Sentinel-HIDS-red?style=for-the-badge&logo=shield&logoColor=white" alt="SOC Sentinel"/>
  <br/>
  <strong>Host-based Intrusion Detection System with AI-Powered Analysis</strong>
  <br/><br/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square&logo=windows&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI-Ollama%20%2F%20API-orange?style=flat-square&logo=openai&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square"/>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [AI Analysis Setup](#ai-analysis-setup)
- [Log Format](#log-format)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Author](#author)
- [License](#license)

---

## Overview

**SOC Sentinel** is a lightweight, modular, **Host-based Intrusion Detection System (HIDS)** built in Python. It continuously monitors your system for anomalous behaviour — high resource usage, suspicious processes, unusual network connections, and repeated failed login attempts — and delivers real-time alerts with AI-powered analysis.

Designed to simulate the core workflow of a real **Security Operations Centre (SOC)** monitoring tool, SOC Sentinel separates detection from classification: rule-based logic detects threats, while an AI model (local via Ollama or remote via API) classifies severity, explains the finding, and generates a professional incident report — the same output a Tier-1 SOC analyst would produce.

> **Portfolio context:** This project demonstrates practical knowledge of system monitoring, cybersecurity detection logic, AI integration, cross-platform software design, and production-grade Python engineering.

---

## Features

### Real-Time System Monitoring
- **CPU usage** — alert when load exceeds configurable threshold
- **RAM usage** — alert on memory pressure
- **Running processes** — detect processes matching a suspicious name list
- **Network connections** — flag established connections to suspicious ports or IPs
- **Failed login attempts** — parse `/var/log/auth.log` (Linux) for brute-force patterns

### Rule-Based Detection Engine
- Fully configurable thresholds and allow/blocklists via `config.yaml`
- Zero code changes required to tune sensitivity
- Deduplication within each monitoring cycle

### Multi-Channel Alerting
- **Audio alarm** — platform-native beep (winsound → afplay → beep → terminal bell)
- **Desktop notification** — cross-platform popup via `plyer` with console fallback
- **Structured log** — NDJSON format, one record per line, SIEM-compatible

### AI Analysis Layer
- Accepts structured alert JSON — no raw system access
- Classifies severity: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
- Provides plain-English explanation, plausible causes, and recommended action
- Generates a professional **SOC-style incident report**
- Supports **Ollama** (local, privacy-preserving) and any **OpenAI-compatible API**
- Graceful fallback if AI is unavailable — alerts are never lost

### Operational Features
- **Autostart** — registers as a system service with a single flag (`--install`)
- **Cross-platform** — Linux, Windows, macOS
- **Non-blocking pipeline** — AI analysis runs in a daemon thread; slow responses never stall monitoring
- **Config-driven** — no recompilation to change behaviour

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                           main.py                                │
│                   SentinelOrchestrator (event loop)              │
└────────────────────────┬─────────────────────────┬──────────────┘
                         │                         │
              collect()  │               alerts[]  │
                         ▼                         ▼
         ┌───────────────────────┐    ┌────────────────────────────┐
         │      core/            │    │       alerts/              │
         │  monitor.py (psutil)  │───►│  logger.py   (NDJSON)      │
         │  detector.py (rules)  │    │  sound_alert.py            │
         │  rules.py             │    │  popup_alert.py            │
         └───────────────────────┘    └────────────────┬───────────┘
                                                       │
                                          Alert object │
                                                       ▼
                                      ┌────────────────────────────┐
                                      │        ai/                 │
                                      │  prompt_engine.py          │
                                      │  analyzer.py (Ollama/API)  │
                                      └────────────────────────────┘
```

### Data Flow (per monitoring cycle)

```
Every N seconds
  │
  ├─► monitor.py    →  SystemSnapshot  (cpu%, ram%, processes, connections)
  │
  ├─► detector.py   →  evaluates snapshot against Rules
  │         │
  │         └─► yields List[Alert]   (empty if all clear)
  │
  └─► per Alert (daemon thread):
        ├─► logger.py          writes raw alert to NDJSON log
        ├─► sound_alert.py     plays audio alarm
        ├─► popup_alert.py     shows desktop notification
        └─► ai/analyzer.py     → AnalysisResult
                  │
                  └─► logger.py  appends AI report to same log
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Tested on 3.10, 3.11, 3.12 |
| pip | Latest | `python -m pip install --upgrade pip` |
| Ollama *(optional)* | Latest | Required only for local AI analysis |

**Linux additional:** The `beep` package is optional for audio (`sudo apt install beep`). The system falls back to the terminal bell automatically.

**Windows additional:** No extra tools required. `winsound` is part of the standard library.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/soc-sentinel.git
cd soc-sentinel
```

### 2. Create a virtual environment (recommended)

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify the installation

```bash
python main.py --help
```

Expected output:

```
usage: soc-sentinel [-h] [--config PATH] [--install] [--uninstall] [--verbose]

SOC Sentinel — Host-based Intrusion Detection System
Monitors CPU, RAM, processes, and network connections in real time.
...
```

---

## Configuration

All behaviour is controlled through `config.yaml`. Edit this file before starting the sentinel.

```yaml
monitoring:
  interval: 5               # Seconds between each collection cycle
  cpu_threshold: 85         # Alert if CPU usage exceeds this %
  ram_threshold: 90         # Alert if RAM usage exceeds this %
  failed_login_threshold: 5 # Failed auth attempts before alerting

rules:
  process_whitelist:        # These processes are never flagged
    - python3
    - nginx
    - sshd

  suspicious_processes:     # Immediate alert if any of these are seen
    - nc
    - nmap
    - mimikatz
    - hydra

  suspicious_ports:         # Alert on established outbound connections to these ports
    - 4444   # Metasploit
    - 6667   # IRC / C2
    - 9050   # Tor SOCKS

  suspicious_ips: []        # Specific IPs to flag

alerts:
  sound: true               # Audio alarm on alert
  popup: true               # Desktop notification
  log: true                 # Write to disk
  log_path: "logs/sentinel.log"
  notify_threshold: "MEDIUM" # Minimum severity to trigger sound/popup

ai:
  enabled: true
  provider: "ollama"        # "ollama" or "api"
  ollama:
    url: "http://localhost:11434"
    model: "llama3"
  timeout: 30
```

> **Tip:** You can maintain separate config files for different environments and pass them with `--config`.
>
> ```bash
> python main.py --config /etc/sentinel/production.yaml
> ```

---

## Usage

### Start monitoring (foreground)

```bash
python main.py
```

### Start with verbose debug output

```bash
python main.py --verbose
```

### Use a custom config file

```bash
python main.py --config /path/to/your/config.yaml
```

### Register as a system startup service

Installs SOC Sentinel to launch automatically when the system starts. On Linux this creates a **systemd user service**; on Windows it adds a **registry Run key**; on macOS a **launchd agent**.

```bash
python main.py --install
```

After installing, manage the service with your platform tools:

```bash
# Linux
systemctl --user status soc-sentinel
systemctl --user stop soc-sentinel
systemctl --user restart soc-sentinel

# Check logs (Linux)
journalctl --user -u soc-sentinel -f
```

### Remove the startup service

```bash
python main.py --uninstall
```

---

## AI Analysis Setup

### Option A — Local (Ollama, recommended)

Ollama runs the AI model entirely on your machine. No data leaves your system.

```bash
# Install Ollama (Linux/macOS)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model (one-time download)
ollama pull llama3

# Verify Ollama is running
ollama list
```

Set in `config.yaml`:

```yaml
ai:
  enabled: true
  provider: "ollama"
  ollama:
    url: "http://localhost:11434"
    model: "llama3"
```

**Recommended models by resource budget:**

| Model | RAM Required | Quality |
|---|---|---|
| `llama3` | ~8 GB | High |
| `mistral` | ~5 GB | High |
| `phi3` | ~2 GB | Good |
| `llama3.2:1b` | ~1 GB | Basic |

### Option B — Remote API (OpenAI-compatible)

Any service exposing an OpenAI-compatible `/chat/completions` endpoint works.

```yaml
ai:
  enabled: true
  provider: "api"
  api:
    url: "https://api.openai.com/v1/chat/completions"
    key: "sk-..."
    model: "gpt-4o-mini"
```

### Disabling AI

If you only want rule-based detection with no AI overhead:

```yaml
ai:
  enabled: false
```

Alerts will still be logged, and sound/popup notifications will still fire.

---

## Log Format

Logs are written in **NDJSON** (Newline-Delimited JSON) — one record per line, readable with `cat`, `jq`, or any SIEM tool.

### Raw alert record

```json
{
  "event": "ALERT",
  "alert_id": "A3F9C1D2",
  "alert_type": "SUSPICIOUS_PROCESS",
  "pre_severity": "HIGH",
  "title": "Suspicious Process Detected: nc",
  "description": "Process 'nc' (PID 14821, user: root) matches the suspicious process list.",
  "raw_data": {
    "pid": 14821,
    "name": "nc",
    "username": "root",
    "cpu_percent": 0.1,
    "memory_percent": 0.02
  },
  "timestamp": "2025-06-19T14:32:11.004812+00:00"
}
```

### AI analysis record (appended after)

```json
{
  "event": "AI_ANALYSIS",
  "alert_id": "A3F9C1D2",
  "logged_at": "2025-06-19T14:32:13.881204+00:00",
  "severity": "HIGH",
  "explanation": "Netcat (nc) is a general-purpose network utility commonly abused by attackers to establish reverse shells, exfiltrate data, or create persistent backdoors.",
  "possible_causes": [
    "Active reverse shell session from a compromised process",
    "Legitimate use by an administrator for network diagnostics",
    "Malware establishing a C2 communication channel"
  ],
  "recommended_action": "Immediately inspect PID 14821 with 'ps aux' and 'lsof -p 14821', identify the parent process, and terminate if unauthorised. Capture network traffic on the associated connection before killing.",
  "incident_report": "At 14:32 UTC, SOC Sentinel detected execution of 'nc' (netcat) under the root account (PID 14821). Netcat is a dual-use tool frequently leveraged in post-exploitation scenarios to maintain persistence or exfiltrate data. The process was flagged against the configured suspicious process list. The system was operating within normal resource parameters at the time of detection. Immediate investigation of the process lineage and associated network connections is recommended before any remediation action is taken."
}
```

### Query your logs with `jq`

```bash
# View all alerts
cat logs/sentinel.log | jq 'select(.event == "ALERT")'

# View only HIGH and CRITICAL AI classifications
cat logs/sentinel.log | jq 'select(.event == "AI_ANALYSIS" and (.severity == "HIGH" or .severity == "CRITICAL"))'

# Count alerts by type
cat logs/sentinel.log | jq 'select(.event == "ALERT") | .alert_type' | sort | uniq -c

# Get full incident report for a specific alert ID
cat logs/sentinel.log | jq 'select(.alert_id == "A3F9C1D2")'
```

---

## Project Structure

```
soc-sentinel/
│
├── main.py                    Entry point, CLI, SentinelOrchestrator
├── config.yaml                User-configurable settings
├── requirements.txt
│
├── core/                      Detection engine
│   ├── rules.py               Immutable Rules dataclass (thresholds + lists)
│   ├── monitor.py             psutil collector → SystemSnapshot
│   └── detector.py            Pure logic: snapshot × rules → List[Alert]
│
├── alerts/                    Notification layer
│   ├── logger.py              Thread-safe NDJSON writer
│   ├── sound_alert.py         Cross-platform audio alarm
│   └── popup_alert.py         Desktop notification (plyer + console fallback)
│
├── ai/                        AI classification layer
│   ├── prompt_engine.py       Builds structured prompts from Alert objects
│   └── analyzer.py            Ollama / HTTP API client + response parser
│
├── utils/                     Shared utilities
│   ├── models.py              Alert, SystemSnapshot, AnalysisResult, Severity
│   ├── config.py              YAML loader with deep-merge defaults
│   └── installer.py           systemd / Registry / launchd service installer
│
└── logs/
    └── sentinel.log           Runtime alert + AI analysis log (NDJSON)
```

---

## How It Works

### 1. Boot sequence

`main.py` loads `config.yaml`, builds an immutable `Rules` object, and wires all subsystems together. Signal handlers for `SIGINT`/`SIGTERM` ensure clean shutdown.

### 2. Monitoring cycle (every N seconds)

`SystemMonitor.collect()` queries psutil for CPU, RAM, process list, and network connections. On Linux it also tails `/var/log/auth.log` for failed authentication patterns. The result is a `SystemSnapshot` — a plain data object with no logic attached.

### 3. Anomaly detection

`AnomalyDetector.evaluate()` is a pure function: same snapshot + same rules always produces the same output. It checks five categories, deduplicates findings within the cycle, and emits a list of `Alert` objects.

### 4. Alert pipeline (per alert, in a daemon thread)

Each alert immediately writes to the NDJSON log, triggers the audio alarm, and shows the desktop notification. The alert is then serialised to JSON and sent to the AI layer.

### 5. AI analysis

`AIAnalyzer` builds a structured chat prompt from the alert JSON and sends it to Ollama (or an API). The response is parsed into an `AnalysisResult` and appended to the log. If the AI call fails for any reason, the fallback result is logged and the original alert is preserved — no data is ever lost.

### 6. Autostart

`--install` writes a platform-native service descriptor (systemd unit / Windows registry key / launchd plist) pointing to the current Python interpreter and script path. `--uninstall` removes it cleanly.

---

## Author

<table>
  <tr>
    <td align="center">
      <b>Muazu Ibrahim Ahmad</b><br/>
      <i>Cybersecurity Engineer & Systems Developer</i><br/><br/>
      <a href="https://github.com/MrDotComSec">
        <img src="https://img.shields.io/badge/GitHub-000000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/>
      </a>
      &nbsp;
      <a href="https://linkedin.com/in/mrdotcom">
        <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/>
      </a>
      &nbsp;
      <a href="mailto:muazu0024@gmail.com">
        <img src="https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"/>
      </a>
    </td>
  </tr>
</table>

**Muazu Ibrahim Ahmad** is a cybersecurity practitioner with a focus on defensive security, system monitoring, and AI-assisted threat analysis. SOC Sentinel was designed and built as a portfolio project to demonstrate practical skills in:

- Host-based intrusion detection system design
- Real-time system telemetry and anomaly detection
- AI/LLM integration for security event classification
- Cross-platform Python systems programming
- SOC workflow automation

---

## Dependencies

| Package | Purpose |
|---|---|
| `psutil` | Cross-platform system metrics and process enumeration |
| `PyYAML` | Configuration file parsing |
| `plyer` | Cross-platform desktop notifications |
| `requests` | HTTP client for Ollama and API calls |
| `colorama` | Cross-platform terminal colour support |

All dependencies are lightweight. No machine learning frameworks, no heavyweight runtime requirements.

---

## Security Notice

SOC Sentinel is a **monitoring and alerting tool**. It does not:
- Block network connections
- Kill processes
- Modify system configuration
- Communicate with any external service (unless you configure an API provider)

The AI layer is **read-only** — it receives alert data and returns text. It has no access to your system.

---

## License

This project is licensed under the **MIT License** — see below for details.

```
MIT License

Copyright (c) 2026 Muazu Ibrahim Ahmad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<p align="center">
  Built with precision by <strong>Muazu Ibrahim Ahmad</strong><br/>
  <sub>If this project helped you, consider giving it a ⭐ on GitHub</sub>
</p>
