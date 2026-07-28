<div align="center">

```
  ██████╗ █████╗ ██████╗ ██████╗ ██╗   ██╗    █████╗ ███╗   ██╗██╗   ██╗██╗  ██╗███████╗███████╗██████╗ 
 ██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝   ██╔══██╗████╗  ██║██║   ██║██║  ██║╚══███╔╝██╔════╝██╔══██╗
 ██║     ███████║██║  ██║██║  ██║ ╚████╔╝    ███████║██╔██╗ ██║██║   ██║███████║  ███╔╝ █████╗  ██████╔╝
 ██║     ██╔══██║██║  ██║██║  ██║  ╚██╔╝     ██╔══██║██║╚██╗██║██║   ██║██╔══██║ ███╔╝  ██╔══╝  ██╔══██╗
 ╚██████╗██║  ██║██████╔╝██████╔╝   ██║      ██║  ██║██║ ╚████║╚██████╔╝██║  ██║███████╗███████╗██║  ██║
  ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═════╝    ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

### ⚡ The Ultimate Fast, Visual & Intelligent Access Log Analyzer for Caddy v2 ⚡

[![Go Version](https://img.shields.io/badge/Go-1.24-38bdf8?style=flat-square&logo=go)](https://go.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/L9Lenny/caddy-analyzer)](https://goreportcard.com/report/github.com/L9Lenny/caddy-analyzer)
[![CI Status](https://img.shields.io/github/actions/workflow/status/L9Lenny/caddy-analyzer/ci.yml?branch=main&style=flat-square&label=CI&color=4ade80)](https://github.com/L9Lenny/caddy-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.1.0-fbbf24?style=flat-square)](https://github.com/L9Lenny/caddy-analyzer)

---

**`caddy-analyzer`** is a ultra-fast, zero-config CLI tool, interactive TUI dashboard, threat detector, and offline HTML report generator designed natively for **Caddy v2 structured JSON access logs**.

</div>

---

## ✨ Features

- ⚡ **Native Caddy v2 JSON Parsing**: Understands Caddy's structured log schema out-of-the-box (no regex configs required).
- 📊 **Visual Terminal Bar Charts**: Displays Unicode proportion bars (`████████░░`) and Lipgloss status badges directly in your terminal.
- 🛡️ **Built-in Threat & Anomaly Detector (`--detect`)**: Identifies SQL Injection, XSS, Path Traversal / LFI, Log4j, RCE, sensitive file probes (`.env`, `.git/config`), and scanner tools.
- 🚫 **Real-time Firewall Guard (`guard`)**: Automatically blocks malicious IPs in real time via `iptables` thresholds.
- 🤖 **Traffic Classifier**: Differentiates human users from search engine crawlers (Googlebot, Bingbot, Yandex, DuckDuckBot) and automated scrapers.
- 🔍 **Comparative Diff Engine (`diff`)**: Compare two log files side-by-side (e.g. before vs after deployment) to detect 5xx error spikes, RPS shifts, and latency regressions.
- 🌐 **Interactive Single-File HTML Dashboard (`-f html`)**: Generates standalone, dark-mode visual web reports containing SVG charts for sharing with team members.
- 📺 **6-Tab Interactive TUI Dashboard (`--watch`)**: Live Bubbletea/Lipgloss dashboard featuring real-time log streaming, security alerts, and top metrics.
- 🐳 **Multi-Source Support**: Read from files (`access.log`), stdin (`-`), Docker (`docker://caddy`), Kubernetes (`k8s://pod`), and systemd (`journalctl://caddy`).

---

## 📦 Installation

### Via 1-Line Installer Script (Linux & macOS)

```bash
curl -sSfL https://raw.githubusercontent.com/L9Lenny/caddy-analyzer/main/install.sh | sh
```

### Via PowerShell (Windows)

```powershell
iwr -useb https://raw.githubusercontent.com/L9Lenny/caddy-analyzer/main/install.ps1 | iex
```

### Via `go install`

```bash
go install github.com/L9Lenny/caddy-analyzer/cmd/caddy-analyze@latest
```

### Via Docker

```bash
docker run --rm -v /var/log/caddy:/logs ghcr.io/L9Lenny/caddy-analyzer /logs/access.log
```

---

## ⚡ Quick Start

```bash
# Auto-detect local log file or run against log file
caddy-analyze /var/log/caddy/access.log

# Run threat detection engine
caddy-analyze --detect /var/log/caddy/access.log

# Filter slow requests (> 500ms) and exlude bots
caddy-analyze --slow 500ms --no-bots /var/log/caddy/access.log

# Stream colorized logs in real time
caddy-analyze tail docker://my-caddy

# Generate interactive dark-mode HTML report
caddy-analyze -f html -o report.html --detect /var/log/caddy/access.log

# Compare logs before vs after deployment
caddy-analyze diff baseline.log current.log
```

---

## 📖 Command Reference

```
caddy-analyze [flags] [source...]

Subcommands:
  tail [source...]                      Stream and colorize Caddy access logs in real time
  top <dimension> [source...]           Quick top-N metric inspector (path, ip, ua, status, bandwidth)
  diff <baseline_log> <target_log>      Compare two log files for RPS shifts, 5xx spikes, and latency changes
  guard [source...]                     Auto-block malicious IPs in real time via iptables
  block <ip...>                         Manually block IP address via iptables
  unban <ip...>                         Remove IP address block from iptables
```

### 🚩 Flags

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--format` | `-f` | `table` | Output format: `table`, `json`, `csv`, `html` |
| `--detect` | `-d` | `false` | Enable threat & anomaly detection engine |
| `--slow` | | `""` | Filter requests slower than duration (e.g. `500ms`, `1s`) |
| `--2xx` | | `false` | Filter 2xx status codes |
| `--3xx` | | `false` | Filter 3xx status codes |
| `--4xx` | | `false` | Filter 4xx status codes |
| `--5xx` | | `false` | Filter 5xx status codes |
| `--errors-only` | `-e` | `false` | Filter 5xx server errors only |
| `--no-bots` | | `false` | Exclude automated bot and crawler traffic |
| `--bots-only` | | `false` | Include only automated bot traffic |
| `--grep` | `-g` | `""` | Search pattern across URI, User-Agent, Remote IP |
| `--top` | `-t` | `10` | Show top N entries |
| `--watch` | `-w` | `false` | Live interactive TUI dashboard |
| `--output` | `-o` | `""` | Write output to specified file path |

---

## 🛡️ Security Detection Engine (`--detect`)

Scans every request against a security pattern engine:

| Attack Category | Pattern / Vector Detected |
| :--- | :--- |
| **SQL Injection** | `UNION SELECT`, `SELECT FROM`, `OR 1=1`, `information_schema`, `pg_sleep`, etc. |
| **Path Traversal / LFI** | `../`, `%2e%2e%2f`, `/etc/passwd`, `php://filter`, `file:///`, etc. |
| **XSS** | `<script>`, `javascript:`, `onerror=`, `alert(`, `%3Csvg`, etc. |
| **Remote Code Execution (RCE)** | `/bin/sh`, `powershell`, `whoami`, `cat /etc/`, `eval(base64`, etc. |
| **Sensitive File Discovery** | `.env`, `.git/config`, `wp-config.php`, `id_rsa`, `.aws/credentials`, etc. |
| **Admin Interface Probe** | `/phpmyadmin`, `/actuator/env`, `/wp-login.php`, `/console/`, etc. |
| **Scanner Tools** | `sqlmap`, `nikto`, `dirbuster`, `gobuster`, `nmap`, `burp suite`, `zap`, etc. |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
Check out the [Contributing Guide](CONTRIBUTING.md) to get started.

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more details.
