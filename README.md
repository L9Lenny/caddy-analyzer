# caddy-analyze

CLI tool for analyzing Caddy v2 access logs. Supports files, stdin, Docker,
Kubernetes, and journalctl. Includes anomaly detection and auto-blocking.

## Installation

```bash
go install github.com/lenny/caddy-analyzer/cmd/caddy-analyze@latest
```

Or build from source:

```bash
git clone <repo>
cd caddy-analyzer
make build
```

## Usage

```
caddy-analyze [flags] [source...]
```

### Sources

| Source | Example | Description |
|--------|---------|-------------|
| File | `caddy-analyze /var/log/caddy/access.log` | Local file, supports glob |
| Stdin | `docker logs my-caddy \| caddy-analyze -` | Pipe from other commands |
| Docker | `caddy-analyze docker://my-caddy` | Logs from Docker container |
| Kubernetes | `caddy-analyze k8s://pod-name -n namespace` | Logs from K8s pod |
| Journalctl | `caddy-analyze journalctl://caddy` | Logs from systemd unit |
| Config | `caddy-analyze` (no args) | Uses source from config file |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--from` | | Filter from time (RFC3339 or relative: `5m`, `1h`, `2d`) |
| `--to` | | Filter to time (RFC3339) |
| `-s, --status` | | Filter by status code (e.g. `-s 200,404`) |
| `-m, --method` | | Filter by HTTP method |
| `-p, --path` | | Filter by path (glob: `/api/*`) |
| `-t, --top` | 10 | Show top N (0 to disable) |
| `-f, --format` | table | Output format: `table`, `json`, `csv` |
| `-F, --follow` | | Follow new logs in real time |
| `-n, --namespace` | | Kubernetes namespace |
| `-i, --interval` | | Aggregation interval (e.g. `5m`, `1h`) |
| `-w, --watch` | | Live dashboard (RPS, top IP, status) |
| `-d, --detect` | | Detect suspicious activity (SQLi, XSS, scanners, brute force) |
| `-o, --output` | | Write report to file instead of stdout |

### Examples

```bash
# Basic analysis
caddy-analyze /var/log/caddy/access.log

# Filter 5xx errors
caddy-analyze --status 500,502,503 /var/log/caddy/access.log

# Only POST requests, JSON output
caddy-analyze -m POST -f json /var/log/caddy/access.log

# Detect suspicious activity
caddy-analyze --detect /var/log/caddy/access.log

# Save report to file
caddy-analyze -o report.json -f json /var/log/caddy/access.log

# Top 5 paths
caddy-analyze --top 5 /var/log/caddy/access.log

# Docker logs, last 30 minutes
caddy-analyze docker://my-caddy --from 30m

# Live dashboard
caddy-analyze --watch docker://my-caddy

# Follow with anomaly detection
caddy-analyze --follow --detect /var/log/caddy/access.log

# Aggregate every 5 minutes
caddy-analyze -i 5m /var/log/caddy/access.log

# Filter by path
caddy-analyze --path '/api/*' /var/log/caddy/access.log
```

### Detection (`--detect`)

Scans every request for:

| Pattern | Detects |
|---------|---------|
| SQL injection | `UNION SELECT`, `OR 1=1`, `information_schema`, etc. |
| Path traversal | `../`, `/etc/passwd`, `php://filter`, etc. |
| XSS | `<script>`, `javascript:`, `onerror=`, etc. |
| Scanner tools | sqlmap, nikto, dirbuster, gobuster, nmap, burp, etc. |
| Auth failure surge | Many 401/403 from the same IP |
| Not found surge | Many 404 from the same IP (directory scanning) |

## Subcommands

### `guard [source]`

Auto-block malicious IPs in real time via iptables.

```
caddy-analyze guard /var/log/caddy/access.log --auth-limit 5
```

| Flag | Default | Description |
|------|---------|-------------|
| `-l, --limit` | 100 | Max requests before blocking |
| `-w, --window` | 1m | Monitoring time window |
| `-d, --duration` | 10m | Block duration (`0` = permanent) |
| `--auth-limit` | 10 | Max 401/403 before blocking |
| `--notfound-limit` | 50 | Max 404 before blocking |

Blocks an IP when _any_ threshold is exceeded.

### `block <ip> [ip...]`

Block IP via iptables.

```bash
caddy-analyze block 10.0.0.1
caddy-analyze block 192.168.1.1 10.0.0.2
```

### `unban <ip> [ip...]`

Remove IP from iptables.

```bash
caddy-analyze unban 192.168.1.1
caddy-analyze unban --all       # Unblock everyone
caddy-analyze unban --list      # Show blocked IPs
```

### `config [source]`

Set default log source in config file.

```bash
caddy-analyze config /var/log/caddy/access.log
caddy-analyze config docker://my-caddy
caddy-analyze config --global /var/log/caddy/access.log
```
