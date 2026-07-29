# Changelog

All notable changes to `caddy-analyzer` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
