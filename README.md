# caddy-analyzer

Universal CLI tool for analyzing Caddy v2 access logs, supporting local files,
stdin, Docker, Kubernetes, and systemd journalctl.

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

### Supported sources

| Source | Example | Description |
|--------|---------|-------------|
| File | `caddy-analyze /var/log/caddy/access.log` | Local file, supports glob |
| Stdin | `docker logs my-caddy \| caddy-analyze -` | Pipe from other commands |
| Docker | `caddy-analyze docker://my-caddy` | Logs from Docker container |
| Kubernetes | `caddy-analyze k8s://pod-name -n namespace` | Logs from K8s pod |
| Journalctl | `caddy-analyze journalctl://caddy` | Logs from systemd unit |

### Examples

```bash
# Basic analysis from file
caddy-analyze /var/log/caddy/access.log

# Filter by status (5xx errors)
caddy-analyze --status 500,502,503 /var/log/caddy/access.log

# Only POST requests
caddy-analyze --method POST /var/log/caddy/access.log

# JSON output
caddy-analyze -f json /var/log/caddy/access.log

# Top 5 most requested paths
caddy-analyze --top 5 /var/log/caddy/access.log

# Docker logs with time filter
caddy-analyze docker://my-caddy --from 30m

# Follow logs in real time
caddy-analyze --follow docker://my-caddy

# Aggregate by 5-minute interval
caddy-analyze -i 5m /var/log/caddy/access.log

# Filter by path with glob
caddy-analyze --path '/api/*' /var/log/caddy/access.log
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--from` | | Filter from time (RFC3339 or relative: 5m, 1h, 2d) |
| `--to` | | Filter to time (RFC3339) |
| `-s, --status` | | Filter by status code (e.g. `-s 200,404`) |
| `-m, --method` | | Filter by HTTP method |
| `-p, --path` | | Filter by path (glob: `/api/*`) |
| `--host` | | Filter by host |
| `--min-latency` | | Minimum latency in seconds |
| `--max-latency` | | Maximum latency in seconds |
| `--remote-ip` | | Filter by remote IP |
| `-t, --top` | 10 | Show top N (0 to disable) |
| `-f, --format` | table | Output: table, json, csv |
| `-F, --follow` | | Follow new logs in real time |
| `-n, --namespace` | | Kubernetes namespace |
| `-i, --interval` | | Aggregation interval (5m, 1h) |
| `-w, --watch` | | Live dashboard (RPS, top IP, status) |
| `--init` | | Generate config template |

## Subcommands

| Command | Description |
|---------|-------------|
| `block <ip> [ip...]` | Block IP(s) via iptables |
| `unban <ip> [ip...]` | Remove IP(s) from iptables |
| `guard [source]` | Auto-block malicious IPs in real time |
| `config [source]` | Set default source in config file |
