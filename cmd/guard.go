package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lenny/caddy-analyzer/pkg/analysis"
	"github.com/lenny/caddy-analyzer/pkg/parser"
	"github.com/lenny/caddy-analyzer/pkg/reader"
	"github.com/lenny/caddy-analyzer/pkg/types"
)

var (
	guardLimit    int
	guardWindow   string
	guardDuration string
)

var guardCmd = &cobra.Command{
	Use:   "guard [source]",
	Short: "Auto-block malicious IPs in real time",
	Long: `Monitor logs in real time and automatically block IPs that exceed
the request threshold within the time window (via iptables).

Blockade is temporary (default 10m). For permanent block: --duration 0.
To unblock manually: caddy-analyze unban <ip> or --all.

Examples:
  caddy-analyze guard /var/log/caddy/access.log
  caddy-analyze guard docker://my-caddy --limit 200 --window 5m
  caddy-analyze guard docker://my-caddy --duration 1h
  caddy-analyze guard k8s://caddy-pod -n production --limit 50
`,
	Args: cobra.ArbitraryArgs,
	RunE: runGuard,
}

func init() {
	guardCmd.Flags().IntVarP(&guardLimit, "limit", "l", 100, "Max requests before blocking")
	guardCmd.Flags().StringVarP(&guardWindow, "window", "w", "1m", "Monitoring time window")
	guardCmd.Flags().StringVarP(&guardDuration, "duration", "d", "10m", "Block duration (e.g. 10m, 1h). 0 = permanent")
	rootCmd.AddCommand(guardCmd)
}

func runGuard(cmd *cobra.Command, args []string) error {
	sources := resolveSources(args)

	window, err := time.ParseDuration(guardWindow)
	if err != nil {
		return fmt.Errorf("invalid window: %w", err)
	}

	duration, _ := time.ParseDuration(guardDuration)
	if guardDuration == "0" || guardDuration == "" {
		duration = 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	engine := analysis.New(types.Filters{})
	ticker := time.NewTicker(window)
	defer ticker.Stop()

	linesCh := make(chan string, 10000)
	for _, src := range sources {
		r := reader.FromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading %s: %w", r.Name(), err)
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

	blocked := make(map[string]bool)

	durMsg := duration.String()
	if duration <= 0 {
		durMsg = "permanent"
	}
	fmt.Fprintf(os.Stderr, "Guard active — threshold: %d requests / %s | block: %s\n", guardLimit, guardWindow, durMsg)
	fmt.Fprintf(os.Stderr, "Ctrl+C to stop\n\n")

	for {
		select {
		case line := <-linesCh:
			entry, err := parser.Parse(line)
			if err == nil && entry != nil {
				if blocked[entry.RemoteIP] {
					continue
				}
				engine.Process(entry)
			}

		case <-ticker.C:
			now := time.Now()
			s := engine.Stats()

			var candidates []struct {
				IP    string
				Count int64
			}
			for ip, count := range s.RemoteIPCounts {
				if count >= int64(guardLimit) && !blocked[ip] {
					candidates = append(candidates, struct {
						IP    string
						Count int64
					}{ip, count})
				}
			}
			sort.Slice(candidates, func(i, j int) bool {
				return candidates[i].Count > candidates[j].Count
			})

			if len(candidates) > 0 {
				for _, c := range candidates {
					blocked[c.IP] = true
					cmd := exec.Command("iptables", "-A", "INPUT", "-s", c.IP, "-j", "DROP")
					if err := cmd.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[%s] ✗ %s (%d req): %v\n", now.Format("15:04:05"), c.IP, c.Count, err)
					} else {
						fmt.Fprintf(os.Stderr, "[%s] ✓ %s blocked (%d requests)\n", now.Format("15:04:05"), c.IP, c.Count)
						if duration > 0 {
							go unblockAfter(c.IP, duration)
						}
					}
				}
			}

			engine = analysis.New(types.Filters{})
			engine.Stats().StartTime = now
		case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\nGuard stopped.")
		if len(blocked) > 0 {
			fmt.Fprintf(os.Stderr, "IPs blocked this session: %d\n", len(blocked))
			}
			return nil
		}
	}
}

func unblockAfter(ip string, duration time.Duration) {
	time.Sleep(duration)
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[unblock] ✗ %s: %v\n", ip, err)
	} else {
		fmt.Fprintf(os.Stderr, "[unblock] ✓ %s unblocked (duration expired)\n", ip)
	}
}
