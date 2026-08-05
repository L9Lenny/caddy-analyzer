# Changelog

All notable changes to `caddy-analyzer` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **JWT abuse detection** (`jwt_abuse`): detects JWT `alg:none` authentication bypass, JWT tokens leaked in URIs, `kid` header path traversal/injection, and Bearer token extraction from `Authorization` header. Tagged MITRE ATT&CK T1550.001, T1190.
- **Object enumeration / BOLA detection** (`object_enumeration`): detects sequential ID enumeration per path template (e.g. `/api/users/1`, `/api/users/2`, ...) — flags BOLA/IDOR attacks when ≥10 distinct IDs are requested on the same path template. Tagged MITRE ATT&CK T1595.002, T1190.
- **Beaconing / C2 detection** (`beaconing`): detects periodic callback patterns (C2 beaconing) by computing the coefficient of variation of inter-arrival times per path (CV < 0.25, 10-50 samples). Tagged MITRE ATT&CK T1071.001, T1573.
- **MITRE ATT&CK tags**: every detection now carries `Techniques []string` with MITRE ATT&CK technique IDs. Enables building ATT&CK Navigator coverage layers from caddy-analyzer output.
- **`export-sigma` subcommand**: exports 23 detection categories as Sigma YAML rules (multi-document) for SIEM import. Each rule includes deterministic UUID, MITRE ATT&CK tags, and dynamically-constructed `condition` fields. Validatable with `sigma check`.
- **`--defang` flag**: defangs IPs (`.` → `[.]`) and URL schemes (`http://` → `hxxp://`, `https://` → `hxxps://`) in all output formats for safe sharing of reports containing IOCs. Applied to map keys and values.
- **Threat-intel enrichment** (`pkg/enrich`): AbuseIPDB API v2 client with TTL cache (30 days), `MultiEnricher` (first-source-wins), `IsPrivateOrLoopback` skip. Guard flags: `--enrich` (requires `ABUSEIPDB_KEY` env var), `--enrich-threshold` (default 70). Enrichment capped at 20 lookups/tick.
- **Credential stuffing detection** (`--cred-stuffing-limit`): alerts when N distinct IPs fail auth (401/403) on the same path within the window — catches distributed credential stuffing where each IP stays under `--auth-limit`.
- **Streaming latency histogram**: replaced O(n) `[]float64` duration slice with fixed-memory log10-spaced histogram (1000 buckets, 1µs–10s). O(1) per insert, <2.5% relative error. Saves ~80MB on million-line logs.
- **Dedicated iptables chain** (`CADDY_ANALYZER`): all block rules live in a dedicated chain with comment marker `caddy-analyzer`. `unban` only touches rules created by this tool. IPv6 routed to `ip6tables` via `BinForIP()`.
- **Audit log rotation and flush**: audit log rotates at 10MB (5 rotated copies kept), with `reopenLocked()` recovery after rotation failure. Periodic `fsync` (1s interval) for crash durability.
- **Cosign signature verification in `install.sh`**: verifies cosign signature on `checksums.txt` when cosign is available, so a compromise of GitHub releases cannot replace both archive and checksums without also compromising the signer identity.
- **Dockerfile non-root user**: container now runs as unprivileged `caddy` user instead of root.
- **CI coverage gate**: total coverage <50% fails the CI build. gofmt check job added.
- **X-Forwarded-For / X-Real-IP support**: `--trust-forwarded` flag (on both `caddy-analyze` and `guard`) attributes requests to the first public hop in `X-Forwarded-For`, falling back to `X-Real-IP`, then the direct `remote_ip`. Enables correct client identification and blocking behind a reverse proxy / CDN.
- **Sliding-window rate limiting in `guard`**: per-IP, per-second buckets replace tumbling counters, so an attacker can no longer evade the limit by straddling a tick boundary. Old buckets are evicted lazily.
- **Distributed-scan defense (`--subnet-limit`)**: blocks a whole `/24` (IPv4) or `/64` (IPv6) when its combined requests exceed the threshold even if no single IP trips, catching subnet-rotating scanners.
- **RPS anomaly alerting (`--rps-anomaly`)**: EWMA-smoothed request-rate baseline; alerts (via audit log) when the current window's RPS exceeds a configurable factor over baseline. Catches volumetric spikes / DDoS that per-IP thresholds miss.
- **User-Agent rotation detection** (`ua_rotation`): flags IPs that send ≥10 distinct User-Agents, a hallmark of credential-stuffing and evasive scanners. Tagged MITRE ATT&CK T1595.001.
- **`--grep` as regex**: the `--grep` filter now accepts a regular expression (case-insensitive); invalid patterns fall back to substring matching.
- **Structured detections in JSON**: a `detections` field exposes per-IP `DetectionRecord` objects (type, description, confidence, method, URI, status) for machine consumption.
- **Pattern-detection blocking in `guard`**: `--detect-confidence` (default `8`, `0` disables) sets the minimum confidence required for a pattern detection (SQLi, XSS, RCE, etc.) to trigger an iptables block. Lower-confidence detections are reported but not blocked.
- **Subcommand flag inheritance**: shared root flags (`-t`, `-f`, `-o`, filters, `-n`) are now persistent and work on `top`, `diff`, `tail`, and `config` — e.g. `config k8s://pod -n production`, `top ip -f csv`.
- **`top`/`diff` output formats**: both subcommands support `-f json|csv` and `-o <file>` (bandwidth table included).
- **Dual-pass detection**: `DetectAll` matches both URL-decoded URIs and raw URIs, with per-category best-signal dedup and confidence upgrades in declaration order.
- **Parser hardening**: bracketed IPv6 (`[::1]:port`) and bare IPv6 remote addresses; numeric request fields parsed from non-string JSON values; Authorization header captured (truncated to 500 chars for JWT Bearer pattern matching).
- **New filter flags**: `--host` (substring, case-insensitive), `--max-latency` (upper bound counterpart to `--slow`), `--min-size`/`--max-size` (with `k`/`mb`/`gb` suffixes), `--max-cardinality` (memory bound, default 100k), `--ua-rotation` (configurable threshold).
- **Performance**: `grepCache` and `globCache` (sync.Map) compile patterns once; `compiledPatternsOnce` (sync.Once) compiles ~150 detection regexes once per process.
- **Detection engine 2x throughput**: three optimizations to `DetectAll` cut 100K-line `--detect` processing from 29s to 14s (~7,000 lines/sec): (1) case-fold elimination — regex patterns compiled with lowercased literals, matched against lowercased source, eliminating `unicode.SimpleFold` overhead; (2) per-source marker triage — `strings.Contains` pre-check on literal markers extracted from each regex, split by source type (URI/UA/Auth) to avoid cross-source false positives, skipping ~90% of regex evaluations on benign traffic; (3) literal fast path — pure-literal alternation patterns use `strings.Contains` instead of the regex engine.
- **Progress bar in offline analysis modes**: a progress bar (`pkg/progress`) appears on TTY when analyzing files, showing `[████████░░░░] 5000/10000 (50%)`. Active on `caddy-analyze` (offline mode), `top`, and `diff` (per-file with filename label). Auto-disabled when stderr is redirected (pipe/file). For non-file sources (stdin, docker, k8s, journalctl) an indeterminate spinner is shown. Pre-scan overhead <3%.
- **`tail --detect` inline threat highlighting**: the `tail` subcommand now accepts `--detect` (`-d`) to run the detection engine on each streamed entry. Suspicious entries have their IP colored by severity (red critical/high, amber medium, olive low) and the attack type appended after a `→` arrow (e.g. `2.58.137.2 → XSS · RCE`). Clean entries are unchanged — zero visual noise. Works with `--defang`.

### Fixed
- **JWT base64 decode**: JWT header was not base64-decoded before pattern matching; alg:none and kid traversal were missed.
- **Beaconing per-path**: beaconing detection was global, not per-path; now tracks per-path timestamp samples in a ring buffer (max 50).
- **Defang not wired in follow/interval modes**: `--defang` flag was parsed but `SetDefang()` was never called in `runFollowMode` and `runIntervalMode`.
- **authFailPaths map leak**: credential-stuffing tracking map was never reset between windows, growing unbounded.
- **Ring buffer off-by-one**: `(count-1)%max` produced wrong index when `count` was a multiple of `max`; fixed to `(count-1)%max` with correct initial fill.
- **yamlQuote backslash**: Sigma YAML string quoting did not escape backslashes, producing invalid YAML on Windows paths.
- **CIDR enrichment skip**: AbuseIPDB API expects single IPs; CIDR ranges were sent as-is, causing 400 errors. Now skipped via `IsPrivateOrLoopback`.
- **Defang incomplete**: `Defang()` only replaced dots, not URL schemes; `http://` URLs remained clickable. Now also defangs `http://` → `hxxp://`, `https://` → `hxxps://`.
- **Enrichment cap shared**: pre-block and audit enrichment loops had separate 20-lookup caps; now share a single counter to bound total API calls per tick.
- **parseInt overflow**: `strconv.Atoi` on large Content-Length values could overflow; switched to `strconv.ParseInt` with int64.
- **math.Sqrt on zero**: beaconing CV calculation called `math.Sqrt` on zero variance, producing NaN; now guarded.
- **Sigma condition undefined references**: `condition` field referenced selection blocks not always present; now built dynamically with `strings.Join(conds, " or ")`.
- **Defang double-defang in follow mode**: `Print()` defanged maps in place without restore; called every 5s, it re-defanged already-defanged values. Now uses save/restore via `defer`.
- **Uncapped second enrichment loop**: audit enrichment loop had its own 20-lookup cap, doubling API calls; now shares the `enrichLookups` counter.
- **Dirty flag cleared before write**: `saveState()` cleared `dirty` before `os.WriteFile`, so a write failure lost the dirty state; now cleared after successful write.
- **guard.Run() busy-loop on closed channel**: `for line := range linesCh` did not check `ok`, causing 100% CPU spin after channel close; added `ok` check.
- **runFollowMode data loss at window reset**: engine was reset before the final report was printed; now prints first, then resets.
- **readFileAndFollow partial lines at EOF**: partial lines (no trailing `\n`) were sent as complete; now seeks back to re-read at next tick via `bufio.Reader`.
- **JournalctlReader `--output=json`**: Caddy JSON was nested in `MESSAGE` field; switched to `--output=cat` for raw output.
- **runIntervalMode missing `--output` flag**: interval mode wrote to stdout, ignoring `-o`; now respects `-o` flag.
- **diff `applyForwarded` not called**: `applyForwarded()` was called in `runOnceMode` but not in `processLogFile` (used by diff); now called.
- **isTerminal() nil panic**: `os.Stdin.Stat()` can return nil FileInfo on closed stdin; now nil-safe.
- **defang values not defanged**: `defangMap` defanged keys but not values; `defangStringSliceMap` and `defangDetectionMap` now defang values (detail strings, URI, Desc).
- **BinForIP CIDR IPv6**: `net.ParseCIDR` returns `ipnet.IP` as 4-byte for IPv4-mapped IPv6; now checks `ipnet.IP.To4() == nil` correctly.
- **printHTML top 0 nil slices**: `--top 0` produced nil slices in HTML output, causing empty tables; now consistent with table/JSON/CSV.
- **HS256 false positive**: HS256 JWT header (`"alg":"HS256"`) was flagged as abuse; removed since HS256 is the legitimate default.
- **FormatDuration sentinel**: `time.Duration` values at `1<<63-1` (sentinel for "no data") printed as huge nanoseconds; now returns "N/A".
- **parseTime negative values**: `--from -5m` was accepted, producing a future timestamp; now rejected.
- **runFollowMode duplicate report**: `if`/`else if` logic printed two reports per tick when window elapsed; restructured to `else if`.
- **JWT Bearer truncation**: Authorization header was truncated to 100 chars, cutting JWT Bearer tokens before the pattern could match; increased to 500.
- **runFollowMode window never resets**: when entries were >5s apart, the window check was only in the `else if` branch; added window check in the first branch too.
- **guard --window 0 panic**: `time.NewTicker(0)` panics; now validated ≤0 with clear error.
- **Audit logger broken after rotation failure**: `maybeRotateLocked()` set `l.f = nil` on error but never recovered; added `reopenLocked()` recovery on next `Log()` call.
- **RCE backtick substitution**: the `command substitution` pattern required a word + space between backticks, missing the common `` `id` `` form. Now matches `` `<cmd>` `` with any command content.
- **SQLi inline-comment bypass**: `UNION/**/SELECT` and MySQL `/*!UNION*/` directives (which defeat naive keyword matching) are now detected.
- **SSRF decimal-IP host**: bare decimal IPs as URL hosts (e.g. `http://3232235521/`) are now flagged.
- **Guard iptables calls hung**: `BlockIP`/`UnblockIP`/`ListBlockedIPs` now use `exec.CommandContext` with a 10s timeout, so a stuck `iptables` can no longer freeze the guard.
- **Unbounded `ipStats` memory**: the detector caps tracked IPs at 100k (configurable via `Detector.SetIPCap`) with FIFO eviction, protecting long offline `--detect` runs on huge logs.
- **Flags not inherited by subcommands**: `top`, `diff`, and `tail` silently ignored `-f`, `-o`, `-t`, and filter flags (cobra local vs persistent flags). All shared flags are now persistent.
- **`--grep` shorthand collision**: `-g` was also used by `config --global`, which caused a cobra panic at runtime; `--grep` is now long-form only.
- **`--from`/`--to` validation**: `--from` later than `--to` now errors with a clear message.
- **`--follow` with `-o`**: followed output is written to the report file instead of stdout.
- **Malformed percent-escape evasion**: `decodeURI` no longer panics on invalid escapes; malformed-URI requests are still pattern-matched against the raw URI.
- **Duration histogram P99 bug**: `histBucketIndex` mapped all values `>= 10s` to bucket 999 (lower bound 9550s) instead of the correct bucket 700, and `histBucketLower` had an off-by-one in the formula (`i-1` instead of `i`). This caused P99 to report 106 minutes instead of 10.53 seconds on real logs. Fixed by removing the early `d >= 10` cap and correcting the formula.
- **`ListBlockedIPs` misleading error on fresh system**: returned `"iptables/ip6tables not found on PATH"` when the `CADDY_ANALYZER` chain didn't exist yet (fresh install), breaking `unban --list` and `unban --all`. Now distinguishes `*exec.ExitError` (chain missing — benign) from binary-not-found, returning an empty list instead.
- **Guard shutdown race**: `Run()` returned immediately on `ctx.Done()` without waiting for `runExpiryLoop`'s final `saveState()`, losing recent blocks from the state file on Ctrl+C. Now uses a `sync.WaitGroup` to wait for the expiry loop before returning.
- **`saveState` dirty flag race**: a concurrent `block()` call during the file write could set `dirty=true`, then `saveState` cleared it to `false`, losing the new block from the persisted state. Fixed with a `saveMu` mutex + `saveGen` generation counter: dirty is only cleared if no concurrent modification happened during the write.
- **`loadState` ran before `SetBlocker` in tests**: `New()` called `loadState()` with the real iptables blocker, so tests using `SetBlocker(fb)` after `New()` had expired-IP cleanup hit real iptables instead of the fake. Fixed by accepting an optional `Blocker` in `Config`; tests now pass the fake blocker via Config so `loadState` uses it.
- **Manual `block`/`unban` not synced to guard state**: manual blocks via `caddy-analyze block` added iptables rules but didn't update the guard's state file, so they weren't restored on restart. Added `--state-file` flag to `block` and `unban`, with `AddPermanentBlockToState`/`RemoveBlockFromState` functions to sync the state file.
- **`block`/`unban` always exit 0**: both commands returned `nil` even when all operations failed, breaking `set -e` in scripts. Now returns non-zero exit code if any IP failed.
- **Duplicate iptables rules on double-block**: `BlockIP` used `iptables -A` (append) unconditionally; calling it twice for the same IP created duplicate rules. Now checks `iptables -C` first and returns nil if the rule already exists (idempotent).
- **Zero timestamp corrupts StartTime**: when a log entry lacked `ts` (or had unparseable `ts`), the zero `time.Time{}` value (year 1) overwrote `StartTime`, corrupting RPS and all time-window reporting. Now guarded with `!entry.Timestamp.IsZero()`.
- **Unbounded `PathTimestamps` map per IP**: an attacker (or app with many endpoints) hitting 100K+ distinct paths from one IP caused unbounded memory growth. Now capped at `pathCapPerIP=1000` paths per IP.
- **FIFO eviction mislabeled as LRU**: the IP eviction policy was FIFO (first-inserted), not LRU — actively-used attacker IPs could be evicted, causing false negatives in beaconing/UA-rotation/object-enumeration detection. Now implements true LRU via `touchIP()` which moves the IP to the end of `ipOrder` on each access.
- **`extractPureLiterals` dropped 1-char alternatives**: alternation branches with `< 2` chars were silently dropped, causing the literal fast path to miss matches → false negatives. Now returns `false` (forcing regex fallback) if any branch is `< 2` chars.
- **`lowercaseFold` didn't handle `OpCharClass`**: regex character class ranges (e.g. `[A-Z]`) were not lowercased after `FoldCase` was cleared, so uppercase-only classes never matched lowercased source text → silent false negatives for future patterns using them. Now lowercases all `OpCharClass` ranges.
- **UA-rotation detection fired only once**: the heuristic triggered exactly when `len(UserAgents) == threshold` and never again, so ongoing rotation was invisible. Now re-fires at multiples of the threshold (`% threshold == 0`).
- **`MinDuration` corrupted by zero/negative durations**: entries with missing `duration`/`latency` fields produced `Duration = 0`, which overwrote `MinDuration` to 0 and stuck there. Now guarded with `entry.Duration > 0`.
- **SIGPIPE in `tail` follow mode**: `fmt.Printf` errors were silently dropped; piping `tail | head` left the process consuming 100% CPU after `head` exited. Now checks write errors and breaks the read loop on failure.
- **Audit `Close()` double-call panic**: `close(stopCh)` without a guard caused a panic on second `Close()` call. Fixed with `sync.Once`; also sets `l.f = nil` and always closes `stopCh` even after rotation failure (fixing a goroutine leak).
- **Audit `Log` didn't reopen after write error**: after an `Encode` failure (disk full, broken pipe), `l.f` was not set to nil, so every subsequent `Log` tried the same broken file and dropped entries. Now sets `l.f = nil` on error, triggering `reopenLocked()` on the next call.
- **Follow mode + multiple files only read first**: `readFileAndFollow` on the first path blocked forever, so paths[1:] were never read. Now reads multiple files concurrently with fan-in via `sync.WaitGroup`.
- **Signal goroutine leaks**: `signal.Notify` without `signal.Stop` caused goroutines to accumulate in `root.go`, `tail.go`, and `guard.go`. Switched to `signal.NotifyContext` which handles cleanup automatically.
- **Guard state loss on shutdown**: `cmd/guard.go`'s `select` returned immediately on `ctx.Done()` without waiting for `g.Run` to finish its cleanup. Now waits for `<-done` after `ctx.Done()`.
- **TUI `truncate(s, 0)` panic**: `string(r[:n-1])` with `n=0` produced a slice bounds error. Now guarded with `n <= 1`.
- **TUI negative table height on tiny terminals**: `m.height-10` went negative on terminals with `< 10` rows, passing a negative height to the table library. Now clamped with `max(1, ...)`.
- **TUI `StreamEndMsg` was no-op**: when the log stream closed (e.g. Docker container stopped), the dashboard froze showing stale data forever. Now returns `tea.Quit`.
- **ANSI codes leaked to `-o` files**: status-code labels used `lipgloss.Style.Render()` unconditionally; when stdout was a TTY but output went to a file via `-o`, the file contained raw ANSI escape sequences. Now gated on `useColor`.
- **`-o` flag: no directory creation, insecure permissions**: `os.Create` used 0666 (world-readable) and failed if the parent directory didn't exist. New `createOutputFile()` helper creates parent dirs with 0750 and the file with 0600.
- **`--top 0` ignored in `top` command**: help says "0 to disable" but `top` overrode `topN <= 0` to 10, showing 10 results instead of disabling. Now honors `topN = 0`.
- **Enrich cache unbounded growth**: long-running guard sessions with many distinct IPs caused memory growth without limit. Now bounded to `maxEntries=10000` with expired-entry eviction.
- **Enrich cache shared `*Reputation` pointer**: the cached pointer was returned directly to callers; mutations would race. Now returns a copy of the cached reputation.
- **`classifyUserAgent` rebuilt map every call + non-deterministic**: the 18-entry `bots` map was allocated on every `Parse` call (GC pressure) and Go's random map iteration order made `BotName` non-deterministic when multiple keys matched. Now a package-level `botList` slice with deterministic iteration order.
- **Silent error on Status/Size parse**: `raw.Status.Int64()` errors were silently discarded, setting `Status = 0` on malformed values. Now checks `err == nil` before assigning.

### Changed
- **Go version**: bumped `go 1.24.2` → `go 1.24.6` (23 stdlib vulnerabilities fixed in go1.24.6).
- **GoReleaser**: Migrated `archives.format` to `archives.formats` and `format_overrides.format` to `format_overrides.formats` (deprecated since v2.6).
- **install.sh**: Changed pipe command from `| sh` to `| bash` (script uses `pipefail`, not supported by `dash`). Added guard to detect non-bash execution with helpful error message. Fixed checksum verification matching SBOM files by anchoring grep to end of line. Added cosign signature verification.
- **Scanner detection**: `curl`, `wget`, `python-requests`, `python-urllib`, and `go-http-client` user agents are no longer flagged as scanners on their own (too many false positives); log4j patterns still match in both URI and User-Agent.
- **Narrowed false-positive patterns**: SSRF metadata paths (bare `metadata` removed), `.env` requires path/query delimiters, SSTI `${{7*7}}` regex-escaped, XSS raw encoded token cleanup.
- **Latency precedence**: `latency_seconds` preferred over `latency` (which is nanoseconds) when both are present.
- **CSV/table injection protection**: cells starting with `= + - @ \t \r` are prefixed with `'`, ANSI escape sequences stripped from all table/CSV cells; `Report.Print()` now returns write errors.
- **`--watch` requires a terminal**: errors out instead of producing garbage when stdout is piped (use `--follow` or `-o` instead).
- **Reader follow mode**: `--follow` only passes `-f`/`--follow` to Docker/journalctl when following; plain reads no longer attach to streams.
- **CI**: gofmt check job added before `go vet`. gosec now checks G104 (unhandled errors). Coverage gate enforces ≥50%.
- **IP eviction policy**: `Detector` now uses true LRU (previously FIFO mislabeled as LRU). Actively-used IPs are never evicted, improving detection accuracy on logs with >100K distinct client IPs.
- **Enrich cache bounded**: `pkg/enrich.Cache` now caps at 10,000 entries with expired-entry eviction. Previously grew unbounded in long-running guard sessions.
- **File output permissions**: `-o` flag now creates files with 0600 (previously 0666) and parent directories with 0750. Security reports containing IPs/detection data are no longer world-readable.
- **`block`/`unban` state sync**: both commands now accept `--state-file` (default `/var/lib/caddy-analyzer/blocked.json`) to sync manual blocks/unbans with the guard's persisted state. Manual blocks survive guard restarts; manual unbans prevent re-blocking on restart.

## [0.2.0] - 2026-08-01

### Added
- **Multi-category detection**: `DetectAll()` returns all matching attack categories per request instead of stopping at the first match. Polyglot payloads (e.g. SQLi+XSS) are now classified as both.
- **Confidence scoring**: Every detection pattern carries a 1-10 score based on specificity. Included in JSON output for filtering and prioritization.
- **Guard audit logging**: Structured JSON-lines audit log (timestamp, action, IP, reason, duration, user) via `--audit-log` on `guard`, `block`, and `unban`. File created with `0600` permissions.
- **Guard state persistence**: `--state-file` (default `/var/lib/caddy-analyzer/blocked.json`) survives restarts; expired entries cleaned on load.
- **Guard IP allowlist**: `--never-block` (comma-separated IPs/CIDRs) and `--never-block-file` (file, one per line, `#` comments) prevent banning trusted IPs. Flags are merged.
- **IP validation**: `validateIP()` accepts IPv4/IPv6/CIDR and rejects flag injection. Applied to all three iptables call sites.
- **Version injection via ldflags**: `Version` variable populated by GoReleaser, CI, and Dockerfile.
- **CI quality gates**: `go vet`, `golangci-lint`, `govulncheck`, coverage reporting. Actions SHA-pinned, `permissions: contents: read`. Secret scanning (gitleaks) and SAST (gosec, with G104/G204/G304 excluded as inherent to CLI design).
- **SBOM and release signing**: SPDX JSON SBOMs via Syft, cosign keyless signature uploaded as release asset.
- **CODEOWNERS**: Requires review on CI workflows, installers, and build config.

### Fixed
- **Regex false positives**: Removed 11 duplicate patterns, bounded 8 unbounded `.*` quantifiers, removed overly broad `/docs/` admin probe.
- **Race condition on `blocked` map**: `sync.Mutex` protection, fixed bypass where blocked IPs weren't removed after `iptables -D`, and false-positive marking on `iptables -A` failure.
- **`parseBlockedIPs` field index bug**: Read wrong column, returning garbage IPs.
- **Swallowed `ParseDuration` errors**: `--duration abc` and `--interval abc` now fail instead of silently using 0 (permanent block).
- **Goroutine leak and DoS**: `unblockAfter` now uses `select` with `ctx.Done()` (cancelled on Ctrl+C). Replaced per-IP `time.Sleep` goroutines with a single min-heap-based expiry loop.
- **File rotation data loss**: `readFileAndFollow` detects rotation via `os.SameFile()` and reopens.
- **`cmd.Wait()` errors ignored**: Now logged; zombie processes reaped after `Process.Kill()`.
- **`install.sh`**: Added `set -euo pipefail` and checksum verification.
- **Custom HTML escaper**: Replaced with `html.EscapeString` (also escapes `'`).
- **Scanner UA list duplicates**: Removed 5 duplicate entries.
- **Windows CI test failures**: File-permission tests now skip on Windows (Unix perms not honored). `cmd.Wait()` error explicitly discarded after `Process.Kill()`.

### Changed
- **Detection gap coverage**: 4 new pattern families (SSTI FreeMarker/ERB/Thymeleaf, Java/Node deserialization, CRLF Java ghost bits, open redirect backslash bypass).
- **Go 1.24 aligned** across `go.mod`, Dockerfile, CI matrix, and release workflow.
- **Dockerfile production image pinned** to `alpine:3.20` with SHA256 digest.
- **`listBlockedIPs` switched to `iptables -S`**: Stable one-rule-per-line format instead of locale-dependent `iptables -L`.
- **Config file permissions tightened**: Directory `0755`→`0750`, file `0644`→`0600` (gosec G301/G306).

## [0.1.3] - 2026-07-30

### Added
- **Expanded to 22 attack categories** (was 15): added XXE/XInclude, Open Redirect, LDAP Injection, XPath Injection, CRLF Injection, Prototype Pollution, SSI Injection, SSRF (cloud metadata / protocol smuggling), SSTI (Freemarker, Jinja2, MRO), NoSQL Injection (`$ne`, `$gt`, `$regex`, `$where`), GraphQL Introspection (`__schema`, `__type`), LFI Wrapper Abuse (`phar://`, `data://`, `compress.*`), WordPress probes, and CGI probes.
- **Raw URI matching**: Percent-encoded path traversal sequences (`%c0%ae%c0%ae%c0%af`, `%252e%252e%252f`) and internal host probes are checked against the raw URI before URL unescaping — closing evasion gaps.
- **Expanded existing signatures**: RCE now matches time-based exfiltration (`sleep`, `ping`, `/dev/tcp/`); Log4j catches obfuscated variants (`${lower:jndi`, `${${::-j}}`); path traversal catches null-byte tricks (`%00..`); sensitive file probes cover `.gitignore`, `composer.json`, `package.json`; admin probes cover `/h2-console`, `/heapdump`, `/jolokia`; scanner UA list includes `httpx`, `nuclei`, `ffuf`, `katana`, `dalfox`, `xsstrike`, `commix`, `tplmap`, `nosqlmap`.
- **Comprehensive test suite**: 55+ test cases covering all 22 categories, dual-pass matching, and false positives.
- **Security-first README**: Hero callout, Demo GIF at top, 22-row detection table with examples, restructured for immediate security impact.
- **docs/security.html**: Updated with all 22 categories and compact pattern table.

### Changed
- **Detection engine**: Introduced `rawPatterns` pre-compiled init block for rules that must match against the raw (non-unescaped) URI, executed before the main `patterns` block.
- **README reordered**: Hero security callout → Demo GIF → Security Detection → Quick Start → Why caddy-analyzer? → Features → Installation → Docs.
- **Help text**: `cmd/root.go` and `cmd/guard.go` now reference 22 categories and dual-pass engine.

## [0.1.2] - 2026-07-29

### Added
- **Per-IP & CIDR Filtering**: `--ip` now accepts both single IPs (`1.2.3.4`) and CIDR subnets (`10.0.0.0/8`). `--exclude-ip` also supports CIDR.
- **Smart Filter Listing**: When entry-level filters are active (`--ip`, `--5xx`, `--no-bots`, etc.), `caddy-analyze` now shows a color-coded log listing (like `tail`) instead of the aggregate report — making filtered output immediately actionable.
- **Filter Support for `tail`**: The `tail` subcommand now accepts all root-level filters (`--ip`, `--5xx`, `--no-bots`, etc.) for real-time filtered streaming.
- **Active Filter Display**: All active filters are shown in the report header for table, JSON, CSV, and HTML formats.
- **TUI Dashboard Colors**: The real-time stream tab (tab 2) in `--watch` mode now uses the same color scheme as `caddy-analyze tail` (2xx green, 3xx cyan, 4xx yellow, 5xx red, IP purple, etc.).
- **Suspicious Request Details in `--detect`**: The security report now shows the actual suspicious requests (detection type, description, method, path) per offending IP in all output formats.
- **Public `MatchEntry` API**: Exported `analysis.MatchEntry()` to allow external use of filter logic.

### Fixed
- **`--ip` filter not working**: The `--ip` flag was declared and parsed but the filtering logic was missing in `Engine.match()`. Now correctly filters by IP/CIDR.

### Changed
- **Help text**: Updated root command help with filter examples and expanded flag descriptions.

## [0.1.1] - 2026-07-28

### Added & Improved
- **Focused Security Inspection Mode (`--detect`)**: Running `--detect` now outputs a standalone, zero-noise Security Threat Inspection Report focused purely on attack alerts, offending IPs, and threat categories.
- **Enhanced `top` Command Usability**: Automatically defaults to `path` dimension when log source is passed directly (`caddy-analyze top access.log`). Added `-b, --by` flag.
- **Enhanced `config` Command Usability**: Added `show` and `reset` actions with clear user feedback for managing persistent default log sources.
- **Clean Unix Terminal Formatting**: Removed emojis from terminal outputs, adopting a crisp, high-contrast Unix developer aesthetic.
- **Documentation Suite**: Added complete multi-page documentation website (`docs/`) with comprehensive reference tables for all 19 CLI flags and options.
- **Permission Diagnostics**: Added friendly diagnostic hints when opening log files fails due to permission errors (`permission denied`), suggesting `sudo` or user group membership.

### Fixed
- **Windows PowerShell Installer**: Fixed asset filename pattern and encoding compatibility for PowerShell 5.1 in `install.ps1`.
- **POSIX Shell Installer**: Fixed release asset URL template and ASCII formatting in `install.sh`.

## [0.1.0] - 2026-07-28

### Initial Release 🚀

#### Core Features
- **Native Caddy v2 JSON Parsing**: Zero-config parsing of Caddy's structured log schema including nested TLS versions, request headers, float durations, and status codes.
- **Traffic Classification**: Automatic detection of human users vs search engine crawlers (Googlebot, Bingbot, Yandex, DuckDuckBot) and scrapers.
- **Percentile Latency Analysis**: Computes P50, P95, P99 latencies alongside average, min, and max durations.
- **Bandwidth Metrics**: Track bytes transferred per path and remote IP address.

#### Security & Anomaly Detection Engine
- **Threat Detection (`--detect`)**: Scans URIs and headers for SQL Injection, XSS, Path Traversal / LFI, Log4j / JNDI, RCE, sensitive file probes (`.env`, `.git/config`, `wp-config.php`, `id_rsa`), admin probes, and automated scanner User-Agents.
- **Real-time Firewall Guard (`guard`)**: Automatically monitors log streams and blocks offending malicious IPs in real time via `iptables` rules.
- **Manual Ban Tools**: Added `block <ip>` and `unban <ip>` commands.

#### CLI & Output Formats
- **Visual Terminal Bar Charts**: Displays Unicode proportion bars (`████████░░`) and status code badges directly in terminal output.
- **Real-time Streaming (`tail`)**: Colorized real-time log viewer for streaming logs from files, Docker, K8s, or stdin.
- **Metric Inspector (`top`)**: Quick top-N metric inspector by dimension (`path`, `ip`, `ua`, `status`, `bandwidth`).
- **Comparative Log Diff (`diff`)**: Compare two log files side-by-side (baseline vs target) to detect 5xx error spikes, RPS shifts, and latency regressions.
- **Standalone Offline HTML Report (`-f html`)**: Single-file dark-mode HTML report generator.
- **6-Tab Interactive TUI (`--watch`)**: Live Bubbletea terminal user interface featuring Summary, Realtime Stream, Security Alerts, Top IPs, Top Paths, and User Agents.

#### Multi-Source Reader
- Supports reading from local files, stdin pipe (`-`), Docker containers (`docker://container`), Kubernetes pods (`k8s://pod`), and systemd journalctl (`journalctl://unit`).

#### Cross-Platform Installers & Automation
- 1-Line installer scripts for Linux/macOS (`install.sh`) and Windows PowerShell (`install.ps1`).
- GitHub Actions CI matrix testing on Ubuntu, macOS, and Windows.
- GoReleaser automated static binary build matrix for `linux/amd64`, `linux/arm64`, `linux/armv7`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.
- GitHub Pages documentation site with live interactive HTML report demo.
