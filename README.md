<table>
  <tr>
    <td><img src="assets/mascot.svg" width="100" alt="caddy-analyzer mascot"></td>
    <td><img src="assets/title.svg" alt="caddy-analyzer" height="80"></td>
  </tr>
</table>

[![Go Version](https://img.shields.io/badge/Go-1.24-38bdf8?style=flat-square&logo=go)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/L9Lenny/caddy-analyzer.svg)](https://pkg.go.dev/github.com/L9Lenny/caddy-analyzer)
[![Documentation](https://img.shields.io/badge/Documentation-GitHub_Pages-238636?style=flat-square&logo=github)](https://l9lenny.github.io/caddy-analyzer/)
[![CI Status](https://github.com/L9Lenny/caddy-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/L9Lenny/caddy-analyzer/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.1.3-fbbf24?style=flat-square)](https://github.com/L9Lenny/caddy-analyzer)

---

**caddy-analyzer** is a zero-config CLI tool for parsing, analyzing, and visualizing Caddy v2 structured JSON access logs. It includes a TUI dashboard, a security threat detection engine, a real-time firewall guard, and offline HTML report generation.

---

## Installation

```bash
# Linux / macOS
curl -sSfL https://raw.githubusercontent.com/L9Lenny/caddy-analyzer/main/install.sh | sh

# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/L9Lenny/caddy-analyzer/main/install.ps1 | iex

# Go toolchain
go install github.com/L9Lenny/caddy-analyzer/cmd/caddy-analyze@latest

# Docker
docker run --rm -v /var/log/caddy:/logs ghcr.io/L9Lenny/caddy-analyzer /logs/access.log
```

---

## Quick Start

```bash
# Set default log source once
caddy-analyze config /var/log/caddy/access.log

# Analyze with security detection
caddy-analyze --detect

# Top-N metric inspector
caddy-analyze top ip

# Real-time streaming
caddy-analyze tail docker://my-caddy

# Filter by IP/CIDR
caddy-analyze --ip 10.0.0.0/8 --5xx --no-bots

# Generate HTML report
caddy-analyze -f html -o report.html --detect
```

---

## Features

- **Native Caddy v2 JSON parsing** — no regex configuration required
- **Security detection engine** (`--detect`) — identifies SQLi, NoSQLi, XSS, SSRF, SSTI, GraphQL introspection, path traversal/LFI, LFI wrapper abuse, Log4j/JNDI, RCE, sensitive file probes, WordPress/CGI probes, admin probes, and scanner tools with per-IP suspicious request details
- **Real-time firewall guard** (`guard`) — automatically blocks malicious IPs via iptables thresholds
- **Traffic classifier** — distinguishes human users from search engine crawlers (Googlebot, Bingbot, Yandex, DuckDuckBot) and automated scrapers
- **Comparative diff engine** (`diff`) — side-by-side log comparison for 5xx spikes, RPS shifts, and latency regressions
- **Interactive HTML reports** (`-f html`) — standalone dark-mode dashboard
- **6-tab TUI dashboard** (`--watch`) — live Bubbletea/Lipgloss dashboard with streaming, alerts, and top metrics
- **Multi-source support** — files, stdin, Docker (`docker://`), Kubernetes (`k8s://`), systemd (`journalctl://`)
- **Smart filter listing** — entry-level filters (`--ip`, `--5xx`, etc.) show color-coded log listings instead of aggregate reports
- **Per-IP and CIDR filtering** — works with both `caddy-analyze` and `caddy-analyze tail`

---

## Command Reference

```
caddy-analyze [flags] [source...]

Subcommands:
  tail                         Stream and colorize logs in real time
  top <dimension>              Top-N metric inspector (path, ip, ua, status, bandwidth)
  diff <baseline> <target>     Compare two log files
  guard                        Auto-block malicious IPs via iptables
  config                       Manage default log source configuration
  block <ip...>                Manually block IP via iptables
  unban <ip...>                Remove IP block from iptables
```

### Flags

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--detect` | `-d` | `false` | Enable security threat detection (SQLi, NoSQLi, XSS, SSRF, SSTI, GraphQL, path traversal, Log4j, RCE, probes, scanners) |
| `--format` | `-f` | `table` | Output format: `table`, `json`, `csv`, `html` |
| `--output` | `-o` | `""` | Write report to file |
| `--watch` | `-w` | `false` | Launch 6-tab interactive TUI dashboard |
| `--top` | `-t` | `10` | Max top entries in tables (0 disables) |
| `--from` | | `""` | Time filter start (RFC3339 or relative: `5m`, `1h`, `2d`) |
| `--to` | | `""` | Time filter end (RFC3339) |
| `--interval` | `-i` | `""` | Periodic aggregation (e.g. `10s`, `1m`) |
| `--follow` | `-F` | `false` | Stream and report every 5 seconds |
| `--slow` | | `""` | Filter requests slower than duration (e.g. `500ms`, `1s`) |
| `--ip` | | `""` | Filter by client IP or CIDR subnet |
| `--exclude-ip` | | `""` | Exclude IP or CIDR subnet |
| `--status` | `-s` | `""` | Filter by status code(s): `-s 200,404` |
| `--method` | `-m` | `""` | Filter by HTTP method: `-m POST` |
| `--path` | `-p` | `""` | Filter by path glob: `-p /api/*` |
| `--2xx` | | `false` | Filter 2xx responses |
| `--3xx` | | `false` | Filter 3xx responses |
| `--4xx` | | `false` | Filter 4xx responses |
| `--5xx` | | `false` | Filter 5xx responses |
| `--errors-only` | `-e` | `false` | Filter errors only |
| `--no-bots` | | `false` | Exclude bot/crawler traffic |
| `--bots-only` | | `false` | Include only bot traffic |
| `--grep` | `-g` | `""` | Search across URI, User-Agent, IP, Host |
| `--compact` | `-c` | `false` | Compact output mode |
| `--namespace` | `-n` | `""` | Kubernetes pod namespace |

---

## Security Detection Engine

Scans every request against a pattern-based engine. Suspicious requests are grouped by offending IP and displayed in all output formats.

```
  - 192.168.1.100     15 malicious requests
       [sql_injection] SQL injection attempt GET /search?id=1' OR '1'='1
       [scanner] Scanner / automated tool detected GET /admin
```

| Category | Detected Patterns |
| :--- | :--- |
| SQL Injection | `UNION SELECT`, `SELECT FROM`, `OR 1=1`, `information_schema`, `pg_sleep`, `exec xp_` |
| NoSQL Injection | `$ne`, `$gt`, `$regex`, `$where`, `$nin`, `%24ne`, `%24gt`, `%24regex` |
| XSS | `<script>`, `javascript:`, `onerror=`, `alert(`, `%3Csvg`, `prompt(` |
| SSTI | `{{...}}`, `${...}`, `<% %>`, `#{...}`, `__class__`, `freemarker`, `nunjucks` |
| SSRF | `169.254.169.254`, `metadata.google.internal`, `gopher://`, `dict://`, `0x7f000001` |
| RCE | `/bin/sh`, `powershell`, `whoami`, `sleep`, `ping`, `/dev/tcp/`, `nslookup` |
| Path Traversal / LFI | `../`, `%00..`, `/etc/passwd`, `/etc/shadow`, `php://filter`, `file:///` |
| LFI Wrapper Abuse | `phar://`, `zip://`, `data://text/plain`, `expect://`, `compress.zlib`, `php://input` |
| GraphQL Introspection | `__schema`, `__type`, `__typename`, `IntrospectionQuery` |
| Log4j / JNDI | `${jndi:`, `class.module.classLoader`, `${lower:jndi`, `${${::-j}}` |
| Sensitive File Probes | `.env`, `.git/config`, `wp-config.php`, `id_rsa`, `.gitignore`, `composer.json` |
| Admin Probes | `/phpmyadmin`, `/actuator/`, `/console/`, `/h2-console`, `/heapdump`, `/jolokia` |
| WordPress Probes | `/wp-content/plugins/`, `/wp-json/wp/v2/`, `/xmlrpc.php`, `/wp-includes/` |
| CGI Probes | `/cgi-bin/` |
| Scanner Tools | `sqlmap`, `nikto`, `gobuster`, `nuclei`, `httpx`, `ffuf`, `katana`, `dalfox`, `xsstrike` |

---

## Contributing

Contributions, issues, and feature requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE) for details.

<sub>Gopher created with [gopherize.me](https://gopherize.me) — Artwork by [Ashley McNamara](https://twitter.com/ashleymcnamara), inspired by [Renee French](http://reneefrench.blogspot.com/)</sub>
