package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/L9Lenny/caddy-analyzer/pkg/audit"
	"github.com/L9Lenny/caddy-analyzer/pkg/guard"
	"github.com/L9Lenny/caddy-analyzer/pkg/reader"
)

var (
	guardLimit          int
	guardWindow         string
	guardDuration       string
	guardAuthLimit     int
	guardNotFoundLimit int
	guardAuditLog       string
	guardStateFile      string
	guardNeverBlock     []string
	guardNeverBlockFile string
)

func init() {
	guardCmd.Flags().IntVarP(&guardLimit, "limit", "l", 100, "Max requests before blocking")
	guardCmd.Flags().StringVarP(&guardWindow, "window", "w", "1m", "Monitoring time window")
	guardCmd.Flags().StringVarP(&guardDuration, "duration", "d", "10m", "Block duration (e.g. 10m, 1h). 0 = permanent")
	guardCmd.Flags().IntVarP(&guardAuthLimit, "auth-limit", "", 10, "Max auth failures (401/403) before blocking")
	guardCmd.Flags().IntVarP(&guardNotFoundLimit, "notfound-limit", "", 50, "Max not found (404) before blocking")
	guardCmd.Flags().StringVarP(&guardAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	guardCmd.Flags().StringVarP(&guardStateFile, "state-file", "", "/var/lib/caddy-analyzer/blocked.json", "State file for crash recovery (empty to disable)")
	guardCmd.Flags().StringSliceVarP(&guardNeverBlock, "never-block", "", nil, "IPs/CIDRs that will never be blocked (e.g. 10.0.0.0/8,192.168.1.1)")
	guardCmd.Flags().StringVarP(&guardNeverBlockFile, "never-block-file", "", "", "File with IPs/CIDRs to never block (one per line, # comments allowed)")
	rootCmd.AddCommand(guardCmd)
}

var guardCmd = &cobra.Command{
	Use:   "guard [source]",
	Short: "Auto-block malicious IPs in real time",
	Long: `Monitor logs in real time and automatically block malicious IPs via iptables.

Detection:
  • Auth failure surge (401/403) — brute force / credential stuffing
  • 404 surge — directory scanning / enumeration
  • Request threshold — generic high-volume
  • Pattern detection — 22 categories: SQLi, NoSQLi, XSS, SSTI, SSRF, RCE, LFI, LFI wrappers, GraphQL, Log4j/JNDI, XXE, open redirect, LDAP/XPath/CRLF/SSI injection, prototype pollution, probes, scanners

Blockade is temporary (default 10m). For permanent block: --duration 0.
To unblock manually: caddy-analyze unban <ip> or --all.

Examples:
  caddy-analyze guard /var/log/caddy/access.log
  caddy-analyze guard docker://my-caddy --limit 200 --window 5m
  caddy-analyze guard docker://my-caddy --duration 1h
  caddy-analyze guard k8s://caddy-pod -n production --auth-limit 5
  caddy-analyze guard /var/log/caddy/access.log --never-block 10.0.0.0/8,192.168.1.1
  caddy-analyze guard /var/log/caddy/access.log --never-block-file /etc/caddy-analyzer/allowlist.txt
`,
	Args: cobra.ArbitraryArgs,
	RunE: runGuard,
}

func runGuard(cmd *cobra.Command, args []string) error {
	sources := resolveSources(args)

	window, err := time.ParseDuration(guardWindow)
	if err != nil {
		return fmt.Errorf("invalid window: %w", err)
	}

	duration, err := time.ParseDuration(guardDuration)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", guardDuration, err)
	}
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

	linesCh := make(chan string, 10000)
	for _, src := range sources {
		r := reader.FromSourceFollow(src)
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

	var onAudit func(action, ip, reason, duration string)
	if guardAuditLog != "" {
		al, err := audit.New(guardAuditLog)
		if err != nil {
			return fmt.Errorf("audit log: %w", err)
		}
		defer func() { _ = al.Close() }()
		onAudit = al.Log
	}

	neverBlock := guardNeverBlock
	if guardNeverBlockFile != "" {
		ips, err := loadIPList(guardNeverBlockFile)
		if err != nil {
			return fmt.Errorf("never-block-file: %w", err)
		}
		neverBlock = append(neverBlock, ips...)
	}

	g := guard.New(guard.Config{
		Limit:         guardLimit,
		AuthLimit:     guardAuthLimit,
		NotFoundLimit: guardNotFoundLimit,
		Window:        window,
		BlockDuration: duration,
		IPValidator:   validateIP,
		OnAudit:       onAudit,
		StatePath:      guardStateFile,
		NeverBlock:    neverBlock,
	})

	durMsg := duration.String()
	if duration <= 0 {
		durMsg = "permanent"
	}
	fmt.Fprintf(os.Stderr, "Guard active — auth: >%d | 404: >%d | total: >%d / %s | block: %s\n",
		guardAuthLimit, guardNotFoundLimit, guardLimit, guardWindow, durMsg)
	fmt.Fprintf(os.Stderr, "Ctrl+C to stop\n\n")

	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, format, args...)
	}

	go g.Run(ctx, linesCh, logf)

	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "\nGuard stopped.")
	if n := g.Count(); n > 0 {
		fmt.Fprintf(os.Stderr, "IPs blocked this session: %d\n", n)
	}
	return nil
}

func loadIPList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line)
	}
	return ips, scanner.Err()
}
