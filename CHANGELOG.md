# Changelog

All notable changes to `caddy-analyzer` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **P0-1: Regex false positives and duplicate patterns** (`pkg/analysis/detect.go`): Removed 11 exact duplicate patterns (Log4j JNDI lookup/protocol/encoded lookup, WordPress content/REST/core/XML-RPC/misc/plugin/backup/sensitive probes) that matched every request twice for no reason. Bounded 8 unbounded `.*` quantifiers in SQL injection (UNION SELECT, destructive), Log4j encoded lookup, RCE command substitution, XXE internal DTD, LFI user home, GraphQL introspection/operation, CRLF header injection, and Log4j URL-encoded JNDI raw pattern — reducing false positives on legitimate English words (`selecting`, `from`, `delete`, `sleep`, `information`) and cutting CPU cost. Removed overly broad `/docs/` from admin probe (matched any documentation path). Added `TestDetectorFalsePositives` with 20 negative fixtures verifying legitimate URIs no longer trigger detections.

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
