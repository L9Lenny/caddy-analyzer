package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/L9Lenny/caddy-analyzer/pkg/analysis"
	"github.com/L9Lenny/caddy-analyzer/pkg/config"
	"github.com/L9Lenny/caddy-analyzer/pkg/output"
	"github.com/L9Lenny/caddy-analyzer/pkg/parser"
	"github.com/L9Lenny/caddy-analyzer/pkg/reader"
	"github.com/L9Lenny/caddy-analyzer/pkg/tui"
	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

var (
	flagFrom      string
	flagTo        string
	flagStatus    []string
	flagMethod    string
	flagPath      string
	flagTop       int
	flagFormat    string
	flagFollow    bool
	flagK8sNS     string
	flagInterval  string
	flagWatch     bool
	flagDetect    bool
	flagOutput    string
	flag2xx       bool
	flag3xx       bool
	flag4xx       bool
	flag5xx       bool
	flagErrors    bool
	flagSlow      string
	flagIP        string
	flagExcludeIP string
	flagNoBots    bool
	flagBotsOnly  bool
	flagGrep      string
	flagCompact   bool
)

var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "caddy-analyze [flags] [source...]",
	Short: "Analyze Caddy access logs from files, stdin, Docker, Kubernetes, or journalctl",
	Args:  cobra.ArbitraryArgs,
	Long: `Analyze Caddy v2 access logs with security detection across 22 attack categories (SQLi, NoSQLi, XSS, SSTI, SSRF, RCE, LFI, GraphQL, Log4j/JNDI, XXE, open redirect, LDAP/XPath/CRLF/SSI injection, prototype pollution, probes, scanners) using a dual-pass evasion-resistant engine.

Sources:
  /path/to/file          Local file (supports glob patterns)
  -                      Stdin (pipe)
  docker://container     Docker container
  k8s://pod              Kubernetes pod  (-n namespace)
  journalctl://unit      systemd unit

Subcommands:
  tail [source...]       Colorized real-time log viewer
  top <dimension>        Quick top-N metric inspector (path, ip, ua, status, bandwidth)
  diff <log1> <log2>     Compare two log files for RPS shifts, 5xx spikes, and latency changes

Filtering (activate colored log listing instead of report):
  --ip <ip/CIDR>         Filter by client IP or subnet
  -s, --status <codes>   Filter by HTTP status code(s)
  -m, --method <verb>    Filter by HTTP method
  -p, --path <glob>      Filter by request path (glob pattern)
  --slow <duration>      Filter requests slower than duration
  --2xx..--5xx           Filter by status class
  -e, --errors-only      Filter server errors only
  --no-bots / --bots-only Filter by traffic type
  -g, --grep <pattern>   Search across URI, User-Agent, IP

Config (auto-detected):
  ./caddy-analyzer.json        Local config
  ~/.config/caddy-analyzer/config.json  Global config

Examples:
  caddy-analyze /var/log/caddy/access.log
  caddy-analyze --detect /var/log/caddy/access.log
  caddy-analyze --ip 10.0.0.0/8 access.log
  caddy-analyze --5xx --no-bots access.log
  caddy-analyze tail --ip 192.168.1.100 docker://caddy
  caddy-analyze top ip --5xx -t 20 access.log
  caddy-analyze diff base.log current.log
`,
	RunE: runAnalysis,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	flags := rootCmd.Flags()

	flags.StringVarP(&flagFrom, "from", "", "", "From (RFC3339 or relative: 5m, 1h, 2d)")
	flags.StringVarP(&flagTo, "to", "", "", "To (RFC3339)")
	flags.StringArrayVarP(&flagStatus, "status", "s", nil, "Filter by status code (e.g. -s 200,404)")
	flags.StringVarP(&flagMethod, "method", "m", "", "Filter by HTTP method")
	flags.StringVarP(&flagPath, "path", "p", "", "Filter by path (glob: /api/*)")
	flags.IntVarP(&flagTop, "top", "t", 10, "Show top N (0 to disable)")
	flags.StringVarP(&flagFormat, "format", "f", "table", "Output format: table, json, csv, html")
	flags.BoolVarP(&flagFollow, "follow", "F", false, "Follow new logs in real time")
	flags.StringVarP(&flagK8sNS, "namespace", "n", "", "Kubernetes namespace")
	flags.StringVarP(&flagInterval, "interval", "i", "", "Aggregation interval (e.g. 5m, 1h)")
	flags.BoolVarP(&flagWatch, "watch", "w", false, "Live dashboard (RPS, top IP, status)")
	flags.BoolVarP(&flagDetect, "detect", "d", false, "Detect suspicious activity (SQLi, XSS, scanners, etc.)")
	flags.StringVarP(&flagOutput, "output", "o", "", "Write report to file instead of stdout")
	flags.BoolVarP(&flag2xx, "2xx", "", false, "Filter 2xx status codes")
	flags.BoolVarP(&flag3xx, "3xx", "", false, "Filter 3xx status codes")
	flags.BoolVarP(&flag4xx, "4xx", "", false, "Filter 4xx status codes")
	flags.BoolVarP(&flag5xx, "5xx", "", false, "Filter 5xx status codes")
	flags.BoolVarP(&flagErrors, "errors-only", "e", false, "Filter 5xx server errors only")
	flags.StringVarP(&flagSlow, "slow", "", "", "Filter requests slower than duration (e.g. 500ms, 1s)")
	flags.StringVarP(&flagIP, "ip", "", "", "Filter by Remote IP")
	flags.StringVarP(&flagExcludeIP, "exclude-ip", "", "", "Exclude Remote IP")
	flags.BoolVarP(&flagNoBots, "no-bots", "", false, "Exclude automated bot and crawler traffic")
	flags.BoolVarP(&flagBotsOnly, "bots-only", "", false, "Include only automated bot traffic")
	flags.StringVarP(&flagGrep, "grep", "g", "", "Search pattern across URI, User-Agent, Remote IP")
	flags.BoolVarP(&flagCompact, "compact", "c", false, "Compact output mode")

	rootCmd.Flags().BoolP("version", "v", false, "Version")
	rootCmd.Version = Version
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	addHiddenCompletionCmd()
}

func addHiddenCompletionCmd() {
	c := &cobra.Command{
		Use:    "completion [bash|zsh|fish]",
		Short:  "Generate shell completion script",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			}
			return fmt.Errorf("unsupported shell: %s", args[0])
		},
	}
	rootCmd.AddCommand(c)
}

func runAnalysis(cmd *cobra.Command, args []string) error {
	sources := resolveSources(args)

	filters, err := buildFilters()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if flagWatch {
		return runWatch(ctx, sources)
	}

	interval, _ := time.ParseDuration(flagInterval)
	if interval > 0 {
		return runIntervalMode(ctx, sources, filters, interval)
	}
	if flagFollow {
		return runFollowMode(ctx, sources, filters)
	}
	return runOnceMode(ctx, sources, filters)
}

func runOnceMode(ctx context.Context, sources []types.LogSource, filters types.Filters) error {
	engine := analysis.New(filters)
	if flagDetect {
		engine.SetDetector(analysis.NewDetector())
	}
	sections := types.DefaultTopSections()
	var parseErrors, processed int64
	var entries []*types.LogEntry
	showListing := output.HasEntryFilters(filters) && flagFormat == "table" && flagOutput == "" && !flagDetect

	for _, src := range sources {
		r := reader.FromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", r.Name(), err)
			continue
		}
		for line := range lines {
			entry, err := parser.Parse(line)
			if err != nil {
				parseErrors++
				continue
			}
			if entry == nil {
				continue
			}
			if !analysis.MatchEntry(entry, filters) {
				continue
			}
			engine.Process(entry)
			processed++
			if showListing {
				entries = append(entries, entry)
			}
		}
	}

	if processed == 0 && parseErrors == 0 {
		fmt.Fprintln(os.Stderr, "no log entries found")
		return nil
	}

	if showListing {
		fmt.Fprintf(os.Stderr, "%d entries matched\n\n", len(entries))
		output.PrintLogEntries(entries, os.Stdout)
		return nil
	}

	engine.Stats().ParseErrors = parseErrors
	engine.Finalize()
	report := output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections)
	report.SetDetect(flagDetect)
	report.SetFilters(filters)
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		report.SetWriter(f)
	}
	report.Print()
	return nil
}

func runFollowMode(ctx context.Context, sources []types.LogSource, filters types.Filters) error {
	engine := analysis.New(filters)
	if flagDetect {
		engine.SetDetector(analysis.NewDetector())
	}
	sections := types.DefaultTopSections()
	last := time.Now()

	for _, src := range sources {
		r := reader.FromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", r.Name(), err)
			continue
		}
		for line := range lines {
			entry, err := parser.Parse(line)
			if err != nil || entry == nil {
				continue
			}
			engine.Process(entry)
			if time.Since(last) > 5*time.Second {
				engine.Finalize()
				report := output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections)
				report.SetDetect(flagDetect)
				report.SetFilters(filters)
				report.Print()
				last = time.Now()
			}
		}
	}
	return nil
}

func runIntervalMode(ctx context.Context, sources []types.LogSource, filters types.Filters, interval time.Duration) error {
	var current time.Time
	var engine *analysis.Engine
	sections := types.DefaultTopSections()
	initial := true
	reportFn := func(e *analysis.Engine, t time.Time) {
		e.Finalize()
		fmt.Printf("\n--- %s ---\n", t.Format(time.RFC3339))
		report := output.NewReportWithSections(e, output.ParseFormat(flagFormat), flagTop, sections)
		report.SetDetect(flagDetect)
		report.SetFilters(filters)
		report.Print()
	}

	for _, src := range sources {
		r := reader.FromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", r.Name(), err)
			continue
		}
		for line := range lines {
			entry, err := parser.Parse(line)
			if err != nil || entry == nil {
				continue
			}
			bucket := entry.Timestamp.Truncate(interval)
			if initial {
				current = bucket
				engine = analysis.New(filters)
				if flagDetect {
					engine.SetDetector(analysis.NewDetector())
				}
				initial = false
			}
			if bucket != current {
				reportFn(engine, current)
				engine = analysis.New(filters)
				if flagDetect {
					engine.SetDetector(analysis.NewDetector())
				}
				current = bucket
			}
			engine.Process(entry)
		}
	}
	if engine != nil && engine.Count() > 0 {
		reportFn(engine, current)
	}
	return nil
}

func runWatch(ctx context.Context, sources []types.LogSource) error {
	linesCh := make(chan string, 10000)
	for _, src := range sources {
		r := reader.FromSourceFollow(src)
		lines, err := r.Read(ctx)
		if err != nil {
			return err
		}
		go func() {
			for l := range lines {
				select {
				case linesCh <- l:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	p := tea.NewProgram(tui.NewModel(linesCh), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func resolveSources(args []string) []types.LogSource {
	if len(args) > 0 {
		return parseSources(args)
	}
	cfg, cfgPath, err := config.Load()
	if err == nil && cfg != nil && cfg.Source != "" {
		fmt.Fprintf(os.Stderr, "using config: %s\n", cfgPath)
		return []types.LogSource{reader.ParseSource(cfg.Source)}
	}

	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		return []types.LogSource{{Type: types.SourceStdin}}
	}

	candidates := []string{
		"access.log",
		"caddy.log",
		"caddy-access.log",
		"/var/log/caddy/access.log",
		"/var/log/caddy/caddy.log",
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			fmt.Fprintf(os.Stderr, "auto-detected log file: %s\n", candidate)
			return []types.LogSource{{Type: types.SourceFile, Path: candidate}}
		}
	}

	return []types.LogSource{{Type: types.SourceStdin}}
}

func parseSources(args []string) []types.LogSource {
	s := make([]types.LogSource, 0, len(args))
	for _, a := range args {
		src := reader.ParseSource(a)
		if src.Type == types.SourceK8s && flagK8sNS != "" && src.Namespace == "" {
			src.Namespace = flagK8sNS
		}
		s = append(s, src)
	}
	return s
}

func buildFilters() (types.Filters, error) {
	var f types.Filters
	if flagFrom != "" {
		t, err := parseTime(flagFrom)
		if err != nil {
			return f, fmt.Errorf("--from: %w", err)
		}
		f.From = t
		f.HasFrom = true
	}
	if flagTo != "" {
		t, err := parseTime(flagTo)
		if err != nil {
			return f, fmt.Errorf("--to: %w", err)
		}
		f.To = t
		f.HasTo = true
	}
	for _, s := range flagStatus {
		for _, ss := range strings.Split(s, ",") {
			code, err := strconv.Atoi(strings.TrimSpace(ss))
			if err != nil {
				return f, fmt.Errorf("invalid status: %s", ss)
			}
			f.Status = append(f.Status, code)
		}
	}
	f.Method = flagMethod
	f.PathGlob = flagPath
	f.Only2xx = flag2xx
	f.Only3xx = flag3xx
	f.Only4xx = flag4xx
	f.Only5xx = flag5xx
	f.ErrorsOnly = flagErrors
	f.NoBots = flagNoBots
	f.BotsOnly = flagBotsOnly
	f.RemoteIP = flagIP
	f.ExcludeIP = flagExcludeIP
	f.GrepPattern = flagGrep
	f.Compact = flagCompact

	if flagSlow != "" {
		dur, err := time.ParseDuration(flagSlow)
		if err != nil {
			return f, fmt.Errorf("invalid --slow duration: %w", err)
		}
		f.MinLatency = dur.Seconds()
	}

	return f, nil
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	unit := s[len(s)-1:]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time: %s", s)
	}
	now := time.Now()
	switch unit {
	case "s":
		return now.Add(-time.Duration(n) * time.Second), nil
	case "m":
		return now.Add(-time.Duration(n) * time.Minute), nil
	case "h":
		return now.Add(-time.Duration(n) * time.Hour), nil
	case "d":
		return now.Add(-time.Duration(n) * 24 * time.Hour), nil
	}
	return time.Time{}, fmt.Errorf("unknown time unit: %s", unit)
}
