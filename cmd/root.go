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
	Short: "Analizza log di Caddy da file, stdin, Docker, Kubernetes o journalctl",
	Args:  cobra.ArbitraryArgs,
	Long: `Analizza i log di accesso di Caddy v2.

Sorgenti:
  /path/to/file          File locale (supporta glob)
  -                      Stdin (pipe)
  docker://container     Container Docker
  k8s://pod              Pod Kubernetes  (-n namespace)
  journalctl://unit      Unità systemd

Config:
  ./caddy-analyzer.json  o  ~/.config/caddy-analyzer/config.json
  Formato: { "source": "/var/log/caddy/access.log" }

Esempi:
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

	flags.StringVarP(&flagFrom, "from", "", "", "Da (RFC3339 o relativo: 5m, 1h, 2d)")
	flags.StringVarP(&flagTo, "to", "", "", "A (RFC3339)")
	flags.StringArrayVarP(&flagStatus, "status", "s", nil, "Filtra per status code (es. -s 200,404)")
	flags.StringVarP(&flagMethod, "method", "m", "", "Filtra per metodo HTTP")
	flags.StringVarP(&flagPath, "path", "p", "", "Filtra per path (glob: /api/*)")
	flags.StringVarP(&flagHost, "host", "", "", "Filtra per host")
	flags.Float64VarP(&flagMinLat, "min-latency", "", 0, "Latenza minima (s)")
	flags.Float64VarP(&flagMaxLat, "max-latency", "", 0, "Latenza massima (s)")
	flags.Int64VarP(&flagMinSize, "min-size", "", 0, "Dimensione minima risposta (byte)")
	flags.Int64VarP(&flagMaxSize, "max-size", "", 0, "Dimensione massima risposta (byte)")
	flags.StringVarP(&flagRemoteIP, "remote-ip", "", "", "Filtra per IP remoto")
	flags.StringVarP(&flagFile, "file", "", "", "Leggi da file (sovrascrive la config)")
	flags.IntVarP(&flagTop, "top", "t", 10, "Mostra top N (0 per disabilitare)")
	flags.StringVarP(&flagTopBy, "top-by", "", "path,ip,ua", "Sezioni top: path,ip,ua,method,status,host")
	flags.StringVarP(&flagFormat, "format", "f", "table", "Formato output: table, json, csv")
	flags.BoolVarP(&flagFollow, "follow", "F", false, "Segui nuovi log in tempo reale")
	flags.StringVarP(&flagK8sNS, "namespace", "n", "", "Namespace Kubernetes")
	flags.StringVarP(&flagInterval, "interval", "i", "", "Intervallo aggregazione (es. 5m, 1h)")
	flags.BoolVarP(&flagInit, "init", "", false, "Genera file di config template")
	flags.BoolVarP(&flagWatch, "watch", "w", false, "Dashboard live (RPS, top IP, status)")

	rootCmd.Flags().BoolP("version", "v", false, "Versione")
	rootCmd.Version = "0.1.0"
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
	fmt.Fprintf(os.Stderr, "config creato: %s\n", path)
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
		fmt.Fprintln(os.Stderr, "nessun log trovato")
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
	fmt.Println(" Caddy Monitor (Ctrl+C per uscire)")
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
			fmt.Printf(" Richieste: %d   RPS: %.1f   Errori: %d\n", s.TotalRequests, rps, s.Errors)
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
		fmt.Fprintf(os.Stderr, "usando config: %s\n", cfgPath)
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
				return f, fmt.Errorf("status invalido: %s", ss)
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
		return time.Time{}, fmt.Errorf("time non valido: %s", s)
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
	return time.Time{}, fmt.Errorf("unità tempo sconosciuta: %s", unit)
}
