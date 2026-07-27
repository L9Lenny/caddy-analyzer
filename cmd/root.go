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

	"github.com/spf13/cobra"

	"github.com/lenny/caddy-analyzer/pkg/analysis"
	"github.com/lenny/caddy-analyzer/pkg/config"
	"github.com/lenny/caddy-analyzer/pkg/output"
	"github.com/lenny/caddy-analyzer/pkg/parser"
	"github.com/lenny/caddy-analyzer/pkg/reader"
	"github.com/lenny/caddy-analyzer/pkg/types"
)

var (
	flagFrom     string
	flagTo       string
	flagStatus   []string
	flagMethod   string
	flagPath     string
	flagHost     string
	flagMinLat   float64
	flagMaxLat   float64
	flagMinSize  int64
	flagMaxSize  int64
	flagRemoteIP string
	flagFile     string
	flagTop      int
	flagTopBy    string
	flagFormat   string
	flagFollow   bool
	flagK8sNS    string
	flagInterval string
	flagInit     bool
	flagWatch bool
)

var rootCmd = &cobra.Command{
	Use:   "caddy-analyze [flags] [source...]",
	Short: "Analyze Caddy access logs from files, stdin, Docker, Kubernetes, or journalctl",
	Args:  cobra.ArbitraryArgs,
	Long: `Analyze Caddy v2 access logs.

Sources:
  /path/to/file          Local file (supports glob patterns)
  -                      Stdin (pipe)
  docker://container     Docker container
  k8s://pod              Kubernetes pod  (-n namespace)
  journalctl://unit      systemd unit

Config (auto-detected):
  ./caddy-analyzer.json        Local config
  ~/.config/caddy-analyzer/config.json  Global config
  Format: { "source": "/var/log/caddy/access.log" }

Examples:
  caddy-analyze /var/log/caddy/access.log
  docker logs my-caddy | caddy-analyze -
  caddy-analyze docker://my-caddy --watch
  caddy-analyze block 10.0.0.1
  caddy-analyze guard docker://my-caddy --limit 100
  caddy-analyze config /var/log/caddy/access.log
  caddy-analyze unban 192.168.1.1
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
	flags.StringVarP(&flagHost, "host", "", "", "Filter by host")
	flags.Float64VarP(&flagMinLat, "min-latency", "", 0, "Minimum latency (s)")
	flags.Float64VarP(&flagMaxLat, "max-latency", "", 0, "Maximum latency (s)")
	flags.Int64VarP(&flagMinSize, "min-size", "", 0, "Minimum response size (bytes)")
	flags.Int64VarP(&flagMaxSize, "max-size", "", 0, "Maximum response size (bytes)")
	flags.StringVarP(&flagRemoteIP, "remote-ip", "", "", "Filter by remote IP")
	flags.StringVarP(&flagFile, "file", "", "", "Read from file (overrides config)")
	flags.IntVarP(&flagTop, "top", "t", 10, "Show top N (0 to disable)")
	flags.StringVarP(&flagTopBy, "top-by", "", "path,ip,ua", "Top sections: path,ip,ua,method,status,host")
	flags.StringVarP(&flagFormat, "format", "f", "table", "Output format: table, json, csv")
	flags.BoolVarP(&flagFollow, "follow", "F", false, "Follow new logs in real time")
	flags.StringVarP(&flagK8sNS, "namespace", "n", "", "Kubernetes namespace")
	flags.StringVarP(&flagInterval, "interval", "i", "", "Aggregation interval (e.g. 5m, 1h)")
	flags.BoolVarP(&flagInit, "init", "", false, "Generate config template")
	flags.BoolVarP(&flagWatch, "watch", "w", false, "Live dashboard (RPS, top IP, status)")

	rootCmd.Flags().BoolP("version", "v", false, "Version")
	rootCmd.Version = "0.1.0"
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
	if flagInit {
		return runInit()
	}

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

func runInit() error {
	path := config.LocalConfigPath()
	if err := config.CreateDefault(path); err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	fmt.Fprintf(os.Stderr, "config created: %s\n", path)
	return nil
}

func runOnceMode(ctx context.Context, sources []types.LogSource, filters types.Filters) error {
	engine := analysis.New(filters)
	sections := parseTopSections(flagTopBy)
	var parseErrors, processed int64

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
			engine.Process(entry)
			processed++
		}
	}

	if processed == 0 && parseErrors == 0 {
		fmt.Fprintln(os.Stderr, "no log entries found")
		return nil
	}

	engine.Stats().ParseErrors = parseErrors
	engine.Finalize()
	output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections).Print()
	return nil
}

func runFollowMode(ctx context.Context, sources []types.LogSource, filters types.Filters) error {
	engine := analysis.New(filters)
	sections := parseTopSections(flagTopBy)
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
				output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections).Print()
				last = time.Now()
			}
		}
	}
	return nil
}

func runIntervalMode(ctx context.Context, sources []types.LogSource, filters types.Filters, interval time.Duration) error {
	var current time.Time
	var engine *analysis.Engine
	sections := parseTopSections(flagTopBy)
	initial := true

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
				initial = false
			}
			if bucket != current {
				engine.Finalize()
				fmt.Printf("\n--- %s ---\n", current.Format(time.RFC3339))
				output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections).Print()
				engine = analysis.New(filters)
				current = bucket
			}
			engine.Process(entry)
		}
	}
	if engine != nil && engine.Count() > 0 {
		engine.Finalize()
		fmt.Printf("\n--- %s ---\n", current.Format(time.RFC3339))
		output.NewReportWithSections(engine, output.ParseFormat(flagFormat), flagTop, sections).Print()
	}
	return nil
}

func runWatch(ctx context.Context, sources []types.LogSource) error {
	engine := analysis.New(types.Filters{})
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	linesCh := make(chan string, 10000)
	for _, src := range sources {
		r := reader.FromSource(src)
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

	fmt.Print("\033[2J")
	fmt.Println(" Caddy Monitor (Ctrl+C to exit)")
	fmt.Println(strings.Repeat("━", 50))

	for {
		select {
		case line := <-linesCh:
			entry, err := parser.Parse(line)
			if err == nil && entry != nil {
				engine.Process(entry)
			}
		case <-ticker.C:
			engine.Finalize()
			s := engine.Stats()
			elapsed := s.EndTime.Sub(s.StartTime).Seconds()
			if elapsed <= 0 {
				elapsed = 2
			}
			rps := float64(s.TotalRequests) / elapsed

			fmt.Printf("\033[4H\033[J")
			fmt.Printf(" Requests: %d   RPS: %.1f   Errors: %d\n", s.TotalRequests, rps, s.Errors)
			fmt.Printf(" Status: 2xx:%d  3xx:%d  4xx:%d  5xx:%d\n\n", s.Status2xx, s.Status3xx, s.Status4xx, s.Status5xx)

			fmt.Printf(" Top IP:\n")
			ips := analysis.TopN(s.RemoteIPCounts, 10)
			for i, ip := range ips {
				fmt.Printf("  %d. %-15s %s %d\n", i+1, ip.Key, bar(ip, ips), ip.Count)
			}

			engine = analysis.New(types.Filters{})
			if !s.EndTime.IsZero() {
				engine.Stats().StartTime = s.EndTime
			}
		case <-ctx.Done():
			fmt.Println()
			return nil
		}
	}
}

func bar(item types.CountItem, items []types.CountItem) string {
	max := int64(20)
	if len(items) > 0 && items[0].Count > 0 {
		n := item.Count * max / items[0].Count
		if n > max {
			n = max
		}
		return "\033[44m" + strings.Repeat(" ", int(n)) + "\033[0m" + strings.Repeat(" ", int(max-n))
	}
	return strings.Repeat(" ", int(max))
}

func resolveSources(args []string) []types.LogSource {
	if len(args) > 0 {
		return parseSources(args)
	}
	if flagFile != "" {
		return []types.LogSource{reader.ParseSource(flagFile)}
	}
	cfg, cfgPath, err := config.Load()
	if err == nil && cfg != nil && cfg.Source != "" {
		fmt.Fprintf(os.Stderr, "using config: %s\n", cfgPath)
		return []types.LogSource{reader.ParseSource(cfg.Source)}
	}
	return []types.LogSource{{Type: types.SourceStdin}}
}

func parseTopSections(s string) types.TopSections {
	if s == "" {
		return types.DefaultTopSections()
	}
	var sec types.TopSections
	for _, f := range strings.Split(s, ",") {
		switch strings.TrimSpace(f) {
		case "path":
			sec.Path = true
		case "ip":
			sec.IP = true
		case "ua":
			sec.UA = true
		case "method":
			sec.Method = true
		case "status":
			sec.Status = true
		case "host":
			sec.Host = true
		}
	}
	return sec
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
	f.Host = flagHost
	f.MinLatency = flagMinLat
	f.MaxLatency = flagMaxLat
	f.MinSize = flagMinSize
	f.MaxSize = flagMaxSize
	f.RemoteIP = flagRemoteIP
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
