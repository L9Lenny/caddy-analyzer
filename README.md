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
[![Go Reference](https://pkg.go.dev/badge/github.com/L9Lenny/caddy-analyzer.svg)](https://pkg.go.dev/github.com/L9Lenny/caddy-analyzer)
[![Documentation](https://img.shields.io/badge/Documentation-GitHub_Pages-238636?style=flat-square&logo=github)](https://l9lenny.github.io/caddy-analyzer/)
[![CI Status](https://github.com/L9Lenny/caddy-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/L9Lenny/caddy-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.1.0-fbbf24?style=flat-square)](https://github.com/L9Lenny/caddy-analyzer)

---

**`caddy-analyzer`** is a ultra-fast, zero-config CLI tool, interactive TUI dashboard, threat detector, and offline HTML report generator designed natively for **Caddy v2 structured JSON access logs**.

📖 **Official Documentation**: [https://l9lenny.github.io/caddy-analyzer/](https://l9lenny.github.io/caddy-analyzer/)

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

## ⚡ Quick Start & Auto-Configuration

Set your default log source once so you don't have to specify log file paths on every run:

```bash
# Set default log source once (local or --global)
caddy-analyze config /var/log/caddy/access.log

# Now run commands without specifying paths!
caddy-analyze
caddy-analyze --detect
caddy-analyze top ip
caddy-analyze --slow 500ms --no-bots

# Stream colorized logs in real time
caddy-analyze tail docker://my-caddy

# Generate standalone dark-mode HTML report
caddy-analyze -f html -o report.html --detect
```

# Compare logs before vs after deployment
caddy-analyze diff baseline.log current.log

---

## 📖 Command Reference

```
caddy-analyze [flags] [source...]

Subcommands:
  tail [source...]                      Stream and colorize Caddy access logs in real time
  top [dimension] [source...]           Quick top-N metric inspector (path, ip, ua, status, bandwidth)
  diff <baseline_log> <target_log>      Compare two log files for RPS shifts, 5xx spikes, and latency changes
  guard [source...]                     Auto-block malicious IPs in real time via iptables
  config [show|set|reset|source]        Manage persistent default log source configuration
  block <ip...>                         Manually block IP address via iptables
  unban <ip...>                         Remove IP address block from iptables
```

### ⚙️ Persistent Configuration (`caddy-analyze config`)

Set a default log source so you can simply run `caddy-analyze` without specifying log paths:

```bash
# Save default log source locally (./caddy-analyzer.json)
caddy-analyze config /var/log/caddy/access.log

# Save default log source globally (~/.config/caddy-analyzer/config.json)
caddy-analyze config docker://my-caddy --global

# Show active configuration and source
caddy-analyze config show

# Remove configuration file
caddy-analyze config reset
```

### 📊 Quick Metric Inspector (`caddy-analyze top`)

The `top` command provides targeted top-N rankings for specific log dimensions without generating a full report:

```bash
# Top requested endpoints (default dimension)
caddy-analyze top /var/log/caddy/access.log

# Top client IP addresses (identify scrapers & DoS sources)
caddy-analyze top ip /var/log/caddy/access.log

# Top client IPs triggering 5xx server errors
caddy-analyze top ip /var/log/caddy/access.log --5xx

# Top paths consuming the highest bandwidth (top 20)
caddy-analyze top bandwidth /var/log/caddy/access.log -t 20

# Top status codes for slow requests (> 500ms)
caddy-analyze top /var/log/caddy/access.log --by status --slow 500ms
```

### 🚩 Flags Reference

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--detect` | `-d` | `false` | Enable security threat detection engine (SQLi, XSS, Path Traversal, Log4j, RCE, Probes, Scanners) |
| `--format` | `-f` | `table` | Set report output format (`table`, `json`, `csv`, `html`) |
| `--output` | `-o` | `""` | Write analysis output to specified destination file instead of stdout |
| `--watch` | `-w` | `false` | Launch full-screen 6-tab interactive terminal TUI dashboard (Bubbletea) |
| `--top` | `-t` | `10` | Set maximum number of top entries displayed in tables |
| `--interval` | `-i` | `""` | Periodically re-run analysis every N duration (e.g. `10s`, `1m`) |
| `--follow` | `-F` | `false` | Stream and process incoming log lines in real-time follow mode |
| `--2xx` | | `false` | Filter only successful HTTP 2xx status responses (200–299) |
| `--3xx` | | `false` | Filter only redirection HTTP 3xx status responses (300–399) |
| `--4xx` | | `false` | Filter only client error HTTP 4xx status responses (400–499) |
| `--5xx` | | `false` | Filter only server error HTTP 5xx status responses (500–599) |
| `--errors-only` | `-e` | `false` | Filter error responses (status &ge; 400) |
| `--slow` | | `""` | Filter requests slower than specified duration (e.g. `500ms`, `1s`) |
| `--ip` | | `""` | Filter requests originating from client IP or CIDR subnet |
| `--exclude-ip` | | `""` | Exclude requests from IP or CIDR subnet |
| `--no-bots` | | `false` | Exclude search engine crawlers and automated bots |
| `--bots-only` | | `false` | Include ONLY search engine crawlers and automated bots |
| `--grep` | `-g` | `""` | Filter entries containing string pattern in URI path, host, or User-Agent |
| `--compact` | | `false` | Output compact single-line log formatting |

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
