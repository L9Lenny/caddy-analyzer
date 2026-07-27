# caddy-analyzer

CLI universale per analizzare i log di accesso di Caddy v2, supporta file locali,
stdin, Docker, Kubernetes e systemd journalctl.

## Installazione

```bash
go install github.com/lenny/caddy-analyzer/cmd/caddy-analyze@latest
```

Oppure build da sorgente:

```bash
git clone <repo>
cd caddy-analyzer
go build -o caddy-analyze ./cmd/caddy-analyze/
```

## Utilizzo

```
caddy-analyze [flags] [source...]
```

### Sorgenti supportate

| Sorgente | Esempio | Descrizione |
|----------|---------|-------------|
| File | `caddy-analyze /var/log/caddy/access.log` | File locale, supporta glob |
| Stdin | `docker logs my-caddy \| caddy-analyze -` | Pipe da altri comandi |
| Docker | `caddy-analyze docker://my-caddy` | Log da container Docker |
| Kubernetes | `caddy-analyze k8s://pod-name -n namespace` | Log da pod K8s |
| Journalctl | `caddy-analyze journalctl://caddy` | Log da systemd unit |

### Esempi

```bash
# Analisi base di un file di log
caddy-analyze /var/log/caddy/access.log

# Filtra per errori 5xx
caddy-analyze --status 500,502,503 /var/log/caddy/access.log

# Solo metodo POST
caddy-analyze --method POST /var/log/caddy/access.log

# Output JSON
caddy-analyze -f json /var/log/caddy/access.log

# Top 5 percorsi più chiamati
caddy-analyze --top 5 /var/log/caddy/access.log

# Log da Docker con filtro temporale
caddy-analyze docker://my-caddy --from 30m

# Segui i log in tempo reale
caddy-analyze --follow docker://my-caddy

# Aggregazione per intervallo di 5 minuti
caddy-analyze -i 5m /var/log/caddy/access.log

# Filtra per path con glob
caddy-analyze --path '/api/*' /var/log/caddy/access.log
```

### Flags

| Flag | Default | Descrizione |
|------|---------|-------------|
| `--from` | | Filtra da un time (RFC3339 o relativo: 5m, 1h, 2d) |
| `--to` | | Filtra fino a un time (RFC3339) |
| `-s, --status` | | Filtra per status code (es. `-s 200,404`) |
| `-m, --method` | | Filtra per metodo HTTP |
| `-p, --path` | | Filtra per path (glob: `/api/*`) |
| `--host` | | Filtra per host |
| `--min-latency` | | Latenza minima in secondi |
| `--max-latency` | | Latenza massima in secondi |
| `--remote-ip` | | Filtra per IP remoto |
| `-t, --top` | 10 | Mostra top N (0 per disabilitare) |
| `-f, --format` | table | Output: table, json, csv |
| `-F, --follow` | | Segui i log in tempo reale |
| `-n, --namespace` | | Namespace Kubernetes |
| `-i, --interval` | | Intervallo di aggregazione (5m, 1h) |
