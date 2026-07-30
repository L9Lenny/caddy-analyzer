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

## Why caddy-analyzer?

Caddy v2 uses a **structured JSON log format** that differs from the Common/Combined Log Format used by Apache, Nginx, and most log analysis tools. Generic tools like `goaccess`, `lnav`, or `grep`/`awk` pipelines cannot parse Caddy's nested schema out of the box.

| Capability | caddy-analyzer | goaccess | lnav | grep/awk |
|---|---|---|---|---|
| Caddy v2 JSON native | ✅ | ❌ | ❌ | ❌ |
| Security threat detection (15 categories) | ✅ | ❌ | ❌ | ❌ |
| Real-time firewall guard (iptables) | ✅ | ❌ | ❌ | ❌ |
| Per-IP suspicious request details | ✅ | ❌ | ❌ | ❌ |
| Comparative diff engine (RPS, 5xx, latency) | ✅ | ❌ | ❌ | ❌ |
| TUI dashboard with live streaming | ✅ | ✅ | ✅ | ❌ |
| Standalone HTML reports | ✅ | ✅ | ❌ | ❌ |
| Multi-source (Docker, K8s, journalctl) | ✅ | ❌ | ✅ | ❌ |
| URL-unescape + raw URI dual-pass detection | ✅ | ❌ | ❌ | ❌ |
| CIDR filtering | ✅ | ❌ | ❌ | ❌ |
| Traffic classifier (crawler vs human) | ✅ | ❌ | ❌ | ❌ |

---

## Demo

![](assets/demo.gif)

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

## Security Detection Engine

Scans every request against a dual-pass pattern engine — the first pass matches against the URL-unescaped URI, the second against the raw URI. Suspicious requests are grouped by offending IP and displayed in all output formats.

```
  - 192.168.1.100     15 malicious requests
       [sql_injection] SQL injection attempt GET /search?id=1' OR '1'='1
       [scanner] Scanner / automated tool detected GET /admin
```

| Category | Detected Patterns |
|---|---|---|
| **SQL Injection** | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `INFORMATION_SCHEMA`, `pg_sleep`, `WAITFOR DELAY`, `BENCHMARK()`, `xp_cmdshell`, `INTO OUTFILE`, `CONVERT(`, `HAVING n`, `ORDER BY n`, `@@version`, `CHAR()`, `ASCII()`, `EXEC sp_` |
| **NoSQL Injection** | `$ne`, `$gt`, `$regex`, `$where`, `$exists`, `$nin`, `$in`, `$elemMatch`, `$mod`, URL-encoded variants `%24ne`, `%24gt`, `%24regex`, JavaScript eval injection |
| **XSS** | Tag injection (`<script`, `<img`, `<iframe`, `<svg/onload`, `<details/on`, `<body`, `<input`, `<marquee`, `<embed`), event handlers (`onerror=`, `onload=`, `onfocus=`, `onmouseover=`, `onclick=`, `onsubmit=`, `onkeydown=`, `onpointer*=`, `ontoggle=`, `onwheel=`), protocol handlers (`javascript:`, `vbscript:`, `data:text/html`), dangerous JS (`alert()`, `prompt()`, `setTimeout()`, `Function()`, `execScript()`), DOM access (`document.cookie`, `document.location`, `window.location`, `.innerHTML`, `.outerHTML`), CSS expression (`expression(`, `-moz-binding`, `@import url`), SVG/XML, encoded payloads (`%3C`, `%3E`, `&#x3C`, `&lt;`) |
| **SSTI** | Python MRO (`__class__`, `__mro__`, `__subclasses__`, `__builtins__`), template globals (`freemarker`, `nunjucks`, `lipsum`, `cycler`, `joiner`), OS command access (`os.popen`, `os.system`, `subprocess.Popen`), Java class access (`Runtime.getRuntime`, `ProcessBuilder`, `javax.script`), arithmetic probe (`{{7*7}}`, `${7*7}`, `#{7*7}`) |
| **SSRF** | Cloud metadata (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`, `168.63.129.16`, `fd00:ec2::23`), loopback variants (`127.x.x.x`, `0x7f000001`, `2130706433`, `0177...`, `0.0.0.0`, `[::1]`), private IPs (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`), protocol smuggling (`gopher://`, `dict://`, `ftp://`, `tftp://`, `ldap://`, `redis://`), metadata paths (`latest/meta-data`, `computeMetadata`) |
| **RCE** | Shell paths (`/bin/sh`, `/bin/bash`, `/bin/zsh`) + command sub (`$(id)`, `` `id` ``), recon (`whoami`, `id`, `cat /etc`, `pwd`), reverse shell (`/dev/tcp/`, `/dev/udp/`, `nc -e`, `bash -i`), downloaders (`curl`, `wget`, `fetch`, `certutil -urlcache`, `bitsadmin /transfer`, `mshta`, `rundll32`), LOLBins (`wmic`, `regsvr32`, `schtasks`, `cscript`), Windows cmd (`powershell`, `pwsh`, `cmd.exe`), PHP functions (`eval()`, `system()`, `exec()`, `shell_exec()`, `popen()`, `proc_open()`, `assert()`, `create_function()`, `call_user_func()`, `preg_replace /e`), interpreters (`python -c`, `perl -e`, `ruby -e`, `php -r`, `node -e`), PHP file operations (`include()`, `require()`, `file_get_contents()`, `php://input`), deserialization gadgets (`O:n:...`, `__destruct`, `__wakeup`, `__toString`), Java RCE (`Runtime.getRuntime().exec`, `ProcessBuilder`, `Unsafe.defineClass`), Windows recon (`ipconfig`, `systeminfo`, `net user`, `net group`, `tasklist`, `vssadmin`) |
| **Path Traversal / LFI** | Directory traversal (`../`, `..\\`, `..%2f`, `..%5c`, `%2e%2e%2f`), null byte (`..%00`, `%00..`), Unix system files (`/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/crontab`, `/etc/ssh/*`), `/proc/` filesystem (`/proc/self/environ`, `/proc/self/fd`, `/proc/self/maps`, `/proc/self/mem`, `/proc/self/root`), Windows system files (`/windows/win.ini`, `/boot.ini`, `pagefile.sys`, `ntldr`), dotfiles (`/.ssh/`, `/.git/`), user home data (`/root/.bash_history`, `/home/*/.ssh/`), var/usr paths |
| **LFI Wrapper Abuse** | `phar://`, `zip://`, `rar://`, `bz2://`, `zlib://`, `data://`, `expect://`, `php://input`, `php://filter`, `php://temp`, `php://memory`, `compress.zlib`, `compress.bzip2`, `convert.base64-encode`, `convert.iconv` |
| **GraphQL Introspection** | `__schema`, `__type`, `__typename`, `__field`, `__directive`, `__enumValue`, `IntrospectionQuery`, operation discovery (`{__schema`, `{__type`, `query{..{`) |
| **Log4j / JNDI** | JNDI lookups (`${jndi:ldap://`, `${jndi:rmi://`, `${jndi:dns://`), environment access (`${env:`, `${sys:`, `${java:`, `${spring:`, `${ctx:`), obfuscated (`${lower:jndi`, `${::-j}`, `${${::-j}}`, `%24{`), Docker/K8s (`${docker:`, `${k8s:`) |
| **XXE / XML Injection** | Entity declarations (`<!DOCTYPE`, `<!ENTITY`, `<!ELEMENT`), external DTD/entity (`SYSTEM`, `PUBLIC`), parameter entity (`ENTITY % ... SYSTEM`), XInclude (`xi:include`, `xmlns:xi=`, `xpointer`), internal DTD entity |
| **Sensitive File Probes** | Environment files (`.env`, `.env.local`, `.env.prod`), Git files (`/.git/config`, `/.git/HEAD`, `.gitignore`), SSH keys (`id_rsa`, `id_dsa`, `authorized_keys`), cloud credentials (`.aws/credentials`, `.azure/config`, `credentials.json`, `service-account.json`), htaccess (`.htaccess`, `.htpasswd`), Docker config (`docker-compose.yml`, `Dockerfile`), dependency files (`composer.json`, `package.json`, `go.mod`, `Gemfile`, `Pipfile`, `Cargo.toml`), app config (`config.php`, `database.php`, `settings.php`, `web.config`), database exports (`dump.sql`, `.sqlite`, `.ibd`, `.frm`), backup files (`.bak`, `.backup`, `.swp`, `.tar.gz`, `.zip`), log files (`access.log`, `error.log`, `laravel.log`), certificates (`.pem`, `.key`, `.crt`, `.p12`, `.jks`), file manager probes (`wp_filemanager.php`, `elfinder`, `ckfinder`), info pages (`phpinfo.php`, `info.php`, `test.php`), dev config (`.editorconfig`, `.prettierrc`, `webpack.config`, `vite.config`) |
| **Admin Probes** | Database interfaces (`/phpmyadmin`, `/adminer`, `/pgadmin`), Spring Boot Actuator (`/actuator/env`, `/actuator/heapdump`, `/actuator/beans`), H2 console (`/h2-console`), heap dump (`/heapdump`, `/jvm.dump`), JMX/Jolokia (`/jolokia`, `/jmx-console`), admin panels (`/admin`, `/administrator`, `/dashboard`, `/manager`, `/backoffice`), API docs (`/swagger-ui`, `/api-docs`, `/openapi.json`), monitoring (`/grafana`, `/prometheus`, `/kibana`, `/nagios`, `/zabbix`), VCS metadata (`/.svn/`, `/.DS_Store`, `/WEB-INF/`), debug endpoints (`/debug`, `/api/debug`, `/test`), server info (`/server-status`, `/cgi-bin/phpinfo`, `/trace.axd`), credential paths (`/credentials`, `/secrets`, `/tokens`) |
| **WordPress Probes** | Content directories (`/wp-content/plugins/`, `/wp-content/themes/`, `/wp-content/uploads/`), REST API (`/wp-json/wp/v2/`), core directories (`/wp-includes/`, `/wp-admin/js/`), XML-RPC (`/xmlrpc.php`), misc (`/wp-cron.php`, `/wp-signup.php`, `/wp-trackback.php`), popular plugin paths (`woocommerce`, `elementor`, `wordfence`, `akismet`, `yoast`, `jetpack`, `gravityforms`), backup dirs (`/wp-content/backup-`, `/wp-content/ai1wm-backups`), sensitive files (`/wp-content/debug.log`, `/wp-content/install.php`) |
| **CGI Probes** | `/cgi-bin/`, `/cgi-sys/`, `/fcgi-bin/`, script extensions (`.cgi`, `.pl`, `.fcgi`) |
| **Open Redirect** | URL parameter injection (`?url=http://`, `?redirect=https://`, `?next=//evil.com`, `?return=//`), protocol-relative URLs (`//evil.com`) |
| **LDAP Injection** | Filter injection (`(&(`, `(|(`, `)(|(`, `)(&(`), URL-encoded variants (`%28%26%28`, `%28%7c%28`) |
| **XPath Injection** | Path manipulation (`]|//*`, `.//*`) |
| **CRLF / Log Injection** | Header injection (`%0d%0aContent-Length:`, `%0d%0aLocation:`, `%0d%0aSet-Cookie:`), literal CRLF (`\r\nHeader:`) |
| **Prototype Pollution** | `__proto__`, `constructor.prototype`, `[constructor].prototype`, JSON payloads (`"__proto__":`, `"constructor":{"prototype"`) |
| **SSI Injection** | Server-side include directives (`<!--#exec cmd=`, `<!--#include virtual=`, `<!--#echo var=`), short-form (`#exec cmd=`, `#include file=`, `#echo var=`) |
| **Scanner Tools** | `sqlmap`, `nikto`, `gobuster`, `wpscan`, `nuclei`, `httpx`, `ffuf`, `katana`, `dalfox`, `xsstrike`, `commix`, `tplmap`, `nosqlmap`, `whatweb`, `joomscan`, `droopescan`, `acunetix`, `netsparker`, `arachni`, `masscan`, `hydra`, `medusa`, `openvas`, `nessus`, `metasploit`, `beef`, `shodan`, `censys`, `zgrab`, `zmap`, `rustscan`, `amass`, `subfinder`, `gau` |

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
