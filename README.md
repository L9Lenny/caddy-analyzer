# caddy-analyzer

Fast, zero-dependency access log analyzer, security threat inspector, and TUI dashboard designed natively for **Caddy v2 structured JSON access logs**.

[![Go Version](https://img.shields.io/badge/Go-1.24-38bdf8?style=flat-square&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/L9Lenny/caddy-analyzer.svg)](https://pkg.go.dev/github.com/L9Lenny/caddy-analyzer)
[![Documentation](https://img.shields.io/badge/Documentation-GitHub_Pages-238636?style=flat-square&logo=github)](https://l9lenny.github.io/caddy-analyzer/)
[![CI Status](https://github.com/L9Lenny/caddy-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/L9Lenny/caddy-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.1.0-fbbf24?style=flat-square)](https://github.com/L9Lenny/caddy-analyzer)

Documentation: [https://l9lenny.github.io/caddy-analyzer/](https://l9lenny.github.io/caddy-analyzer/)

---

## Features

- **Native Caddy v2 JSON Parsing**: Understands Caddy's structured log schema out-of-the-box (no regex definition required).
- **Security Threat Inspector (`--detect`)**: Identifies SQL Injection, XSS, Path Traversal / LFI, Log4j, RCE, sensitive file probes (`.env`, `.git/config`), and scanner tools.
- **Firewall Auto-Blocking Guard (`guard`)**: Automatically blocks malicious IPs in real time via `iptables` rate thresholds.
- **Traffic Classifier**: Differentiates human users from search engine crawlers (Googlebot, Bingbot, Yandex, DuckDuckBot) and automated scrapers.
- **Comparative Diff Engine (`diff`)**: Compare two log files side-by-side to detect 5xx error spikes, RPS shifts, and latency regressions.
- **Offline HTML Report Export (`-f html`)**: Generates standalone, dark-mode visual web reports for sharing with team members.
- **6-Tab Interactive TUI Dashboard (`--watch`)**: Live Bubbletea/Lipgloss dashboard featuring real-time log streaming, security alerts, and top metrics.
- **Multi-Source Support**: Read from files (`access.log`), stdin (`-`), Docker (`docker://caddy`), Kubernetes (`k8s://pod`), and systemd (`journalctl://caddy`).

---

## Installation

### Linux & macOS (One-Line Installer)

```bash
curl -sSfL https://raw.githubusercontent.com/L9Lenny/caddy-analyzer/main/install.sh | sh
```

### Windows (PowerShell Installer)

```powershell
iwr -useb https://raw.githubusercontent.com/L9Lenny/caddy-analyzer/main/install.ps1 | iex
```

### Via Go Toolchain

```bash
go install github.com/L9Lenny/caddy-analyzer/cmd/caddy-analyze@latest
```

### Via Docker

```bash
docker run --rm -v /var/log/caddy:/logs ghcr.io/L9Lenny/caddy-analyzer /logs/access.log
```

---

## Quick Start & Auto-Configuration

Set your default log source once so you don't have to specify log file paths on every run:

```bash
# Set default log source once (local or --global)
caddy-analyze config /var/log/caddy/access.log

# All commands read from your configured default log source automatically:
caddy-analyze
caddy-analyze --detect
caddy-analyze top ip
caddy-analyze --slow 500ms --no-bots

# Stream colorized logs in real time
caddy-analyze tail docker://my-caddy

# Generate standalone dark-mode HTML report
caddy-analyze -f html -o report.html --detect
```

---

## Command Reference

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

### Flags Reference

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

## Security Detection Engine (`--detect`)

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

## License

MIT License. See [LICENSE](LICENSE) for details.
