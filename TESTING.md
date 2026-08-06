# Testing Guide

This document lists all commands you should run to verify caddy-analyzer works correctly after the latest changes.

## Prerequisites

```bash
# Build the binary
go build -o /tmp/caddy-analyze ./cmd/caddy-analyze

# Verify static checks pass
go vet ./...
gofmt -l .          # should output nothing
go test -race -count=1 ./...
```

All commands below use `/tmp/caddy-analyze` — replace with `./caddy-analyze` if you built locally.

## Test Logs

| File | Description |
|---|---|
| `caddy_access.log` | Real Caddy v2 log (1569 lines, real attacks from `2.58.137.2`) |
| `/tmp/opencode/bench_10000.log` | Synthetic 10K lines, 10% attack traffic |
| `/tmp/opencode/bench_100000.log` | Synthetic 100K lines |
| `/tmp/opencode/bench_1000000.log` | Synthetic 1M lines |

---

## 1. `tail --detect` (inline threat highlighting)

The new `--detect` / `-d` flag on `tail` runs the detection engine on each streamed entry.

### On a real log (TTY required for colors)

```bash
/tmp/caddy-analyze tail --detect caddy_access.log
```

**What to verify:**
- [ ] Attacker IP `2.58.137.2` is colored red (critical/high detections) or amber (medium)
- [ ] After the `[OS/Browser]` info, a dim `→` arrow appears with attack types: `→ XSS · RCE`, `→ WP`, `→ SQL`, etc.
- [ ] Clean entries (200 OK on `/`) have **no arrow, no marker** — identical to `tail` without `--detect`
- [ ] No extra lines, no borders, no badges — minimal visual noise

### Short flag

```bash
/tmp/caddy-analyze tail -d caddy_access.log
```

### With filters

```bash
/tmp/caddy-analyze tail --detect --ip 2.58.137.2 caddy_access.log
/tmp/caddy-analyze tail -d --4xx caddy_access.log
/tmp/caddy-analyze tail -d --no-bots caddy_access.log
```

### With `--defang` (IPs and URLs defanged)

```bash
/tmp/caddy-analyze tail --detect --defang caddy_access.log
```

**Verify:** IP appears as `2[.]58[.]137[.]2` but the `→` arrow and threat types still appear.

### Without `--detect` (regression check — should be identical to before)

```bash
/tmp/caddy-analyze tail caddy_access.log
```

**Verify:** No arrows, no color on IP (just the default), no threat types. Identical to pre-change behavior.

### Piped output (non-TTY — should have no colors)

```bash
/tmp/caddy-analyze tail --detect caddy_access.log | head -20
```

**Verify:** No ANSI escape codes, plain text. Arrow `→` may still appear as plain text.

---

## 2. Progress Bar

### Determinate bar on file analysis (TTY required)

```bash
/tmp/caddy-analyze --detect caddy_access.log
/tmp/caddy-analyze caddy_access.log
/tmp/caddy-analyze top ip caddy_access.log
/tmp/caddy-analyze diff caddy_access.log /tmp/opencode/bench_10000.log
```

**What to verify:**
- [ ] Progress bar appears: `[████████░░░░] 5000/10000 (50%)`
- [ ] For `diff`, the filename label is shown next to the bar
- [ ] Bar reaches 100% and disappears when done
- [ ] Bar shows on `top` and `diff` too, not just root command

### Auto-disabled on pipe/file redirect

```bash
/tmp/caddy-analyze --detect caddy_access.log 2>/dev/null | head
/tmp/caddy-analyze --detect caddy_access.log > /tmp/opencode/out.txt
```

**Verify:** No progress bar output (0 bytes written to stderr when piped).

### Indeterminate spinner on non-file sources

```bash
# If Docker is available:
/tmp/caddy-analyze tail docker://my-caddy

# From stdin:
cat caddy_access.log | /tmp/caddy-analyze --detect
```

**Verify:** Spinner appears (e.g. `⠹ 42 entries`) instead of determinate bar.

### Large file (performance check)

```bash
time /tmp/caddy-analyze --detect /tmp/opencode/bench_100000.log
```

**Verify:** Bar progresses smoothly, completes in ~14s. No stuttering.

---

## 3. `--defang` on all commands

```bash
# Root report
/tmp/caddy-analyze --detect --defang caddy_access.log

# Top
/tmp/caddy-analyze top ip --defang caddy_access.log

# Tail
/tmp/caddy-analyze tail --defang caddy_access.log
/tmp/caddy-analyze tail --detect --defang caddy_access.log

# Diff
/tmp/caddy-analyze diff --defang caddy_access.log /tmp/opencode/bench_10000.log

# JSON output
/tmp/caddy-analyze --detect --defang -f json caddy_access.log | head -20

# HTML output
/tmp/caddy-analyze --detect --defang -f html -o /tmp/opencode/defanged.html caddy_access.log
```

**Verify:** All IPs appear as `1[.]2[.]3[.]4`, URLs as `hxxp://` / `hxxps://`. No raw IPs or `http://` schemes in any output.

---

## 4. Detection Engine (26 categories)

### Full report with detection

```bash
/tmp/caddy-analyze --detect caddy_access.log
```

**Verify:**
- [ ] "Suspicious IPs" section appears with `2.58.137.2`
- [ ] 159 malicious requests detected
- [ ] Categories shown: SQL Injection, XSS, RCE, Path Traversal, WordPress Probes, Admin Probes, Scanner Tools, etc.
- [ ] Per-IP suspicious request details shown with `[category]` prefix

### JSON output

```bash
/tmp/caddy-analyze --detect -f json caddy_access.log | python3 -m json.tool | head -50
```

### CSV output

```bash
/tmp/caddy-analyze --detect -f csv caddy_access.log | head -10
```

### HTML report

```bash
/tmp/caddy-analyze --detect -f html -o /tmp/opencode/report.html caddy_access.log
```

Open in browser and verify suspicious IPs section renders correctly.

---

## 5. Sigma Export

```bash
/tmp/caddy-analyze export-sigma
/tmp/caddy-analyze export-sigma /tmp/opencode/rules.yml
/tmp/caddy-analyze export-sigma - | head -40
```

**Verify:**
- [ ] 23 rules generated (26 categories minus 3 behavioral: ua_rotation, object_enumeration, beaconing)
- [ ] Each rule has MITRE ATT&CK tags
- [ ] Each rule has a deterministic UUID
- [ ] YAML is valid (optionally validate with `sigma check` if available)

---

## 6. Guard Mode (requires root + iptables)

> ⚠️ These commands modify iptables rules. Run in a VM/container or with caution.

```bash
sudo /tmp/caddy-analyze guard --limit 5 --window 1m --duration 10m caddy_access.log
sudo /tmp/caddy-analyze guard --detect --detect-confidence 8 caddy_access.log
sudo /tmp/caddy-analyze block 192.168.1.100 --audit-log /tmp/opencode/audit.jsonl
sudo /tmp/caddy-analyze unban 192.168.1.100 --audit-log /tmp/opencode/audit.jsonl
sudo /tmp/caddy-analyze unban --all
```

**Verify:**
- [ ] Offending IPs appear in `iptables -L -n` after threshold exceeded
- [ ] Audit log written to `/tmp/opencode/audit.jsonl` with timestamp, IP, reason
- [ ] `unban` removes the IP from iptables
- [ ] `--all` clears all caddy-analyzer-managed blocks

---

## 7. Subcommands

### `top`

```bash
/tmp/caddy-analyze top ip caddy_access.log
/tmp/caddy-analyze top path caddy_access.log
/tmp/caddy-analyze top ua caddy_access.log
/tmp/caddy-analyze top status caddy_access.log
/tmp/caddy-analyze top method caddy_access.log
/tmp/caddy-analyze top host caddy_access.log
/tmp/caddy-analyze top bandwidth caddy_access.log
/tmp/caddy-analyze top ip -f csv caddy_access.log
/tmp/caddy-analyze top path --5xx caddy_access.log
```

### `diff`

```bash
/tmp/caddy-analyze diff caddy_access.log /tmp/opencode/bench_10000.log
/tmp/caddy-analyze diff caddy_access.log /tmp/opencode/bench_10000.log -f json
/tmp/caddy-analyze diff caddy_access.log /tmp/opencode/bench_10000.log -f html -o /tmp/opencode/diff.html
```

### `config`

```bash
/tmp/caddy-analyze config show
/tmp/caddy-analyze config set caddy_access.log
/tmp/caddy-analyze config show
/tmp/caddy-analyze config reset
```

---

## 8. Filters

```bash
/tmp/caddy-analyze --ip 2.58.137.2 caddy_access.log
/tmp/caddy-analyze --ip 2.58.0.0/16 caddy_access.log
/tmp/caddy-analyze --exclude-ip 2.58.137.2 caddy_access.log
/tmp/caddy-analyze --4xx caddy_access.log
/tmp/caddy-analyze --5xx caddy_access.log
/tmp/caddy-analyze --status 404 caddy_access.log
/tmp/caddy-analyze --method POST caddy_access.log
/tmp/caddy-analyze --path "/wp-*" caddy_access.log
/tmp/caddy-analyze --no-bots caddy_access.log
/tmp/caddy-analyze --bots-only caddy_access.log
/tmp/caddy-analyze --grep "sql_injection" --detect caddy_access.log
/tmp/caddy-analyze --slow 1s caddy_access.log
/tmp/caddy-analyze --from 2024-01-01 --to 2024-12-31 caddy_access.log
/tmp/caddy-analyze --compact caddy_access.log
```

---

## 9. TUI Dashboard

```bash
/tmp/caddy-analyze --watch caddy_access.log
/tmp/caddy-analyze --watch docker://my-caddy
```

**Verify:**
- [ ] 6-tab interface launches (Bubbletea)
- [ ] Tabs: Overview, Top IPs, Top Paths, Security, Live Stream, Help
- [ ] Security tab shows detected threats
- [ ] `q` or `Ctrl+C` exits cleanly

---

## 10. Performance Benchmarks

```bash
# Parse only
time /tmp/caddy-analyze /tmp/opencode/bench_100000.log

# With detection
time /tmp/caddy-analyze --detect /tmp/opencode/bench_100000.log

# 1M lines (patience required)
time /tmp/caddy-analyze --detect /tmp/opencode/bench_1000000.log
```

**Expected results:**
| Log size | `--detect` | Parse only |
|---|---|---|
| 10K | ~1.5s | ~0.2s |
| 100K | ~14s | ~1.4s |
| 1M | ~2m29s | ~14s |

If times are significantly slower, the detection engine optimizations may have regressed.

---

## 11. Error Handling

```bash
# Non-existent file
/tmp/caddy-analyze /nonexistent.log

# Invalid JSON
echo "not json" | /tmp/caddy-analyze

# Empty file
> /tmp/opencode/empty.log
/tmp/caddy-analyze /tmp/opencode/empty.log

# Invalid CIDR
/tmp/caddy-analyze --ip 999.999.999.999 caddy_access.log

# Invalid flag
/tmp/caddy-analyze --nonexistent caddy_access.log
```

**Verify:** All produce a clean error message and non-zero exit code. No panic, no stack trace.

---

## 12. File Output Permissions & Directory Creation

```bash
# -o creates parent directories
/tmp/caddy-analyze -o /tmp/opencode/subdir/report.html --detect caddy_access.log

# Check permissions (should be 0600)
ls -la /tmp/opencode/subdir/report.html

# -o with top
/tmp/caddy-analyze top ip -o /tmp/opencode/top.csv caddy_access.log
ls -la /tmp/opencode/top.csv

# -o with diff
/tmp/caddy-analyze diff -o /tmp/opencode/diff.json caddy_access.log /tmp/opencode/bench_10000.log
ls -la /tmp/opencode/diff.json
```

**Verify:**
- [ ] Parent directories created automatically
- [ ] File permissions are 0600 (not 0644/0666)
- [ ] No ANSI escape codes in the output file (check with `cat -v`)

---

## 13. `--top 0` Disables Top-N

```bash
# Root command: --top 0 should skip top sections
/tmp/caddy-analyze --top 0 caddy_access.log

# Top command: --top 0 should show nothing (or all, depending on interpretation)
/tmp/caddy-analyze top ip --top 0 caddy_access.log

# Compare with --top 5
/tmp/caddy-analyze top ip --top 5 caddy_access.log
```

**Verify:**
- [ ] `--top 0` on root command skips the "Top IPs/Paths/..." sections
- [ ] `--top 0` on `top` command shows 0 rows (not 10)

---

## 14. Tail SIGPIPE Handling

```bash
# tail | head should not leave caddy-analyze running at 100% CPU
/tmp/caddy-analyze tail caddy_access.log | head -5

# Check the process exited
sleep 1
pgrep -f "caddy-analyze tail" && echo "STILL RUNNING (BUG)" || echo "Clean exit"
```

**Verify:**
- [ ] `tail | head` produces output and both processes exit cleanly
- [ ] No caddy-analyze process lingering after `head` exits

---

## 15. Block/Unban State Sync

> Requires root + iptables

```bash
# Block an IP manually (synced to state file)
sudo /tmp/caddy-analyze block --state-file /tmp/opencode/blocked.json 192.0.2.1
sudo /tmp/caddy-analyze block --state-file /tmp/opencode/blocked.json 192.0.2.2

# Verify state file has both IPs
cat /tmp/opencode/blocked.json

# Block same IP again (idempotent — no duplicate rule)
sudo /tmp/caddy-analyze block --state-file /tmp/opencode/blocked.json 192.0.2.1

# Verify no duplicate in iptables
sudo iptables -S CADDY_ANALYZER | grep 192.0.2.1

# Unban one IP (synced to state file)
sudo /tmp/caddy-analyze unban --state-file /tmp/opencode/blocked.json 192.0.2.1

# Verify state file has only the remaining IP
cat /tmp/opencode/blocked.json

# Unban all
sudo /tmp/caddy-analyze unban --all --state-file /tmp/opencode/blocked.json

# Verify state file is empty
cat /tmp/opencode/blocked.json
```

**Verify:**
- [ ] `block` writes IP to state file
- [ ] Double-block does not create duplicate iptables rules
- [ ] `unban` removes IP from state file
- [ ] `unban --all` clears all IPs from state file and iptables

---

## 16. Audit Log Resilience

> Requires root + iptables

```bash
# Start guard with audit log
sudo /tmp/caddy-analyze guard --audit-log /tmp/opencode/audit.jsonl --limit 2 caddy_access.log &

# Wait for some blocks
sleep 5

# Send SIGINT (Ctrl+C)
sudo kill -INT $(pgrep -f "caddy-analyze guard")

# Wait for clean exit
wait

# Verify audit log has entries
cat /tmp/opencode/audit.jsonl | head -5
```

**Verify:**
- [ ] Audit log has JSON-lines entries
- [ ] Guard exits cleanly on SIGINT (no panic, no goroutine leak)
- [ ] State file reflects final blocked IPs (shutdown sync worked)

