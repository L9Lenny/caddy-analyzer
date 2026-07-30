<p align="center">
  <img src="assets/mascot.svg" width="90" alt="caddy-analyzer mascot"><br>
  <img src="assets/title.svg" alt="caddy-analyzer" height="80">
  <br>
  <sub>Gopher created with <a href="https://gopherize.me">gopherize.me</a> &middot; Artwork by <a href="https://twitter.com/ashleymcnamara">Ashley McNamara</a>, inspired by <a href="http://reneefrench.blogspot.com/">Renee French</a></sub>
</p>

<p align="center">
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.24-38bdf8?style=flat-square&logo=go" alt="Go Version"></a>
  <a href="https://pkg.go.dev/github.com/L9Lenny/caddy-analyzer"><img src="https://pkg.go.dev/badge/github.com/L9Lenny/caddy-analyzer.svg" alt="Go Reference"></a>
  <a href="https://l9lenny.github.io/caddy-analyzer/"><img src="https://img.shields.io/badge/Documentation-238636?style=flat-square&logo=github" alt="Documentation"></a>
  <a href="https://github.com/L9Lenny/caddy-analyzer/actions"><img src="https://github.com/L9Lenny/caddy-analyzer/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-purple.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/L9Lenny/caddy-analyzer/releases"><img src="https://img.shields.io/github/v/release/L9Lenny/caddy-analyzer?style=flat-square&color=fbbf24" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/L9Lenny/caddy-analyzer"><img src="https://goreportcard.com/badge/github.com/L9Lenny/caddy-analyzer?style=flat-square" alt="Go Report Card"></a>
  <a href="https://github.com/L9Lenny/caddy-analyzer"><img src="https://img.shields.io/github/stars/L9Lenny/caddy-analyzer?style=flat-square" alt="Stars"></a>
</p>

---

## Security Detection Engine

Scans every Caddy v2 request against **22 attack categories** using a dual-pass pattern engine — first on the URL-unescaped URI, second on the raw URI to catch multibyte and double-encoded bypass attempts. Suspicious requests are grouped by offending IP and surfaced in all output formats.

| Category | Covers | Example Patterns |
|---|---|---|
| **SQL Injection** | SQLi probes, blind injection, DB fingerprinting | `UNION SELECT`, `OR 1=1`, `pg_sleep`, `INTO OUTFILE`, `@@version` |
| **NoSQL Injection** | MongoDB operators, JS eval injection | `$ne`, `$gt`, `$regex`, `$where`, `$nin`, `%24ne` |
| **XSS** | Reflected/stored/DOM XSS, event handlers, protocol JS | `<script`, `onerror=`, `onfocus=`, `alert(`, `document.cookie`, `data:text/html` |
| **SSTI** | Server-side template injection (Jinja2, Freemarker, Twig, etc.) | `__class__`, `__mro__`, `freemarker`, `nunjucks`, `{{7*7}}`, `os.popen` |
| **SSRF** | Cloud metadata, loopback/private IPs, protocol smuggling | `169.254.169.254`, `0x7f000001`, `gopher://`, `dict://`, `redis://` |
| **RCE** | Shell injection, reverse shells, downloaders, LOLBins | `/bin/sh`, `whoami`, `/dev/tcp/`, `powershell`, `certutil`, `eval()` |
| **Path Traversal / LFI** | Directory traversal, null byte, `/proc/` filesystem, Windows system files | `../`, `..%00`, `/etc/passwd`, `/proc/self/*`, `php://input` |
| **GraphQL Introspection** | Schema discovery queries | `__schema`, `__type`, `IntrospectionQuery` |
| **Log4j / JNDI** | Log4Shell, JNDI lookups, env/sys access, obfuscated variants | `${jndi:ldap://`, `${env:`, `${lower:jndi`, `${::-j}` |
| **XXE / XInclude** | XML entity expansion, external DTD, XInclude | `<!ENTITY`, `SYSTEM`, `PUBLIC`, `xi:include`, `xpointer` |
| **Open Redirect** | URL parameter injection, protocol-relative URLs | `?url=http://`, `?redirect=//`, `//evil.com` |
| **LDAP Injection** | LDAP filter manipulation | `(&(`, `(|(`, `)(|(`, URL-encoded operators |
| **XPath Injection** | XPath query manipulation | `]\|//*`, `.//*` |
| **CRLF / Log Injection** | HTTP response header injection, log poisoning | `%0d%0aSet-Cookie:`, `%0d%0aLocation:`, literal CRLF |
| **Prototype Pollution** | JS prototype chain tampering | `__proto__`, `constructor.prototype`, JSON payloads |
| **SSI Injection** | Server-side include directive injection | `<!--#exec cmd=`, `#include virtual=`, `#echo var=` |
| **LFI Wrapper Abuse** | PHP stream wrappers for file read/execution | `phar://`, `data://`, `expect://`, `compress.zlib` |
| **Sensitive File Probes** | Credentials, backups, configs, source code, git exposure | `.env`, `.git/config`, `id_rsa`, `dump.sql`, `phpinfo.php` |
| **Admin Probes** | DB admin panels, Spring Actuator, heapdumps, API docs, VCS metadata | `/phpmyadmin`, `/actuator/*`, `/h2-console`, `/swagger-ui` |
| **WordPress Probes** | Plugin scanning, XML-RPC, rest API, backup directories | `/wp-content/plugins/`, `/xmlrpc.php`, `/wp-json/wp/v2/` |
| **CGI Probes** | Legacy CGI script discovery | `/cgi-bin/`, `.cgi`, `.fcgi` |
| **Scanner Tools** | 30+ scanner/user-agent signatures, automated tooling | `sqlmap`, `nuclei`, `gobuster`, `ffuf`, `wpscan`, `masscan`, `hydra`, `metasploit`, `shodan` |

Output example:

```
  - 192.168.1.100     15 malicious requests
       [sql_injection] SQL injection attempt GET /search?id=1' OR '1'='1
       [scanner] Scanner / automated tool detected GET /admin
```

> **Guard mode** (`caddy-analyze guard`) extends detection with automatic `iptables` banning — blocks offending IPs at the firewall on configurable thresholds.

---

## Why caddy-analyzer?

Caddy v2 uses a **structured JSON log format** that differs from the Common/Combined Log Format used by Apache, Nginx, and most log analysis tools. Generic tools like `goaccess`, `lnav`, or `grep`/`awk` pipelines cannot parse Caddy's nested schema out of the box.

| Capability | caddy-analyzer | goaccess | lnav | grep/awk |
|---|---|---|---|---|
| Caddy v2 JSON native | ✅ | ❌ | ❌ | ❌ |
| Security threat detection (22 categories) | ✅ | ❌ | ❌ | ❌ |
| Dual-pass evasion-resistant detection | ✅ | ❌ | ❌ | ❌ |
| Real-time firewall guard (iptables) | ✅ | ❌ | ❌ | ❌ |
| Per-IP suspicious request details | ✅ | ❌ | ❌ | ❌ |
| Comparative diff engine (RPS, 5xx, latency) | ✅ | ❌ | ❌ | ❌ |
| TUI dashboard with live streaming | ✅ | ✅ | ✅ | ❌ |
| Standalone HTML reports | ✅ | ✅ | ❌ | ❌ |
| Multi-source (Docker, K8s, journalctl) | ✅ | ❌ | ✅ | ❌ |
| CIDR filtering | ✅ | ❌ | ❌ | ❌ |
| Traffic classifier (crawler vs human) | ✅ | ❌ | ❌ | ❌ |

---

## Demo

![](assets/demo.gif)

---

## Quick Start

```bash
# Set default log source once (persistent config)
caddy-analyze config /var/log/caddy/access.log

# Analyze with full security detection
caddy-analyze --detect

# Top-N metric inspector
caddy-analyze top ip

# Real-time streaming with filters
caddy-analyze tail --ip 10.0.0.0/8 --no-bots docker://my-caddy

# Generate standalone HTML report
caddy-analyze -f html -o report.html --detect

# Compare two log files for regressions
caddy-analyze diff before.log after.log

# Launch interactive TUI dashboard
caddy-analyze --watch
```

---

## Features

| Area | Capability |
|---|---|
| **Parsing** | Native Caddy v2 structured JSON — no regex, no config required |
| **Security** | 22 attack categories: SQLi, NoSQLi, XSS, SSTI, SSRF, RCE, path traversal/LFI, LFI wrapper abuse, GraphQL introspection, Log4j/JNDI, XXE/XInclude, open redirect, LDAP injection, XPath injection, CRLF injection, prototype pollution, SSI injection, sensitive file probes, WordPress probes, CGI probes, admin probes, scanner tools |
| **Detection Accuracy** | Dual-pass engine: URL-unescaped + raw URI matching catches multibyte-encoded and double-encoded bypass attempts |
| **Firewall** | `guard` daemon auto-blocks malicious IPs via `iptables` with configurable thresholds and ban duration |
| **Traffic Analysis** | Classifies human users vs crawlers (Googlebot, Bingbot, Yandex, DuckDuckBot) and automated scrapers |
| **Diff Engine** | Side-by-side comparison of two log files detecting 5xx spikes, RPS shifts, and latency regressions |
| **TUI Dashboard** | 6-tab Bubbletea/Lipgloss interface with live streaming, security alerts, and top metrics |
| **HTML Reports** | Standalone dark-mode single-file HTML reports for sharing with your team |
| **Data Sources** | Local files, stdin, Docker (`docker://`), Kubernetes (`k8s://`), systemd journalctl (`journalctl://`) |
| **Filtering** | Entry-level filters auto-switch to color-coded log listings. Supports CIDR, status classes, methods, path globs |

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

## Documentation

Full documentation is available at **[l9lenny.github.io/caddy-analyzer](https://l9lenny.github.io/caddy-analyzer/)**.

<details>
<summary><strong>Command Reference</strong></summary>

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
</details>

<details>
<summary><strong>Flags Reference</strong></summary>

| Flag | Short | Default | Description |
|---|---|---|---|
| `--detect` | `-d` | `false` | Enable security threat detection |
| `--format` | `-f` | `table` | Output format: `table`, `json`, `csv`, `html` |
| `--output` | `-o` | `""` | Write report to file |
| `--watch` | `-w` | `false` | Launch 6-tab interactive TUI dashboard |
| `--top` | `-t` | `10` | Max top entries in tables (0 disables) |
| `--from` | | `""` | Time filter start (RFC3339 or relative: `5m`, `1h`, `2d`) |
| `--to` | | `""` | Time filter end (RFC3339) |
| `--interval` | `-i` | `""` | Periodic aggregation |
| `--follow` | `-F` | `false` | Stream and report every 5 seconds |
| `--slow` | | `""` | Filter requests slower than duration |
| `--ip` | | `""` | Filter by client IP or CIDR subnet |
| `--exclude-ip` | | `""` | Exclude IP or CIDR subnet |
| `--status` | `-s` | `""` | Filter by status code(s) |
| `--method` | `-m` | `""` | Filter by HTTP method |
| `--path` | `-p` | `""` | Filter by path glob |
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
</details>

---

## Development

```bash
git clone https://github.com/L9Lenny/caddy-analyzer.git
cd caddy-analyzer
go build ./cmd/caddy-analyze
go test ./...
```

PRs and issues are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License — see [LICENSE](LICENSE) for details.
