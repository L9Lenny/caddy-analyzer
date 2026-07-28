package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/L9Lenny/caddy-analyzer/pkg/analysis"
	"github.com/L9Lenny/caddy-analyzer/pkg/output"
	"github.com/L9Lenny/caddy-analyzer/pkg/parser"
	"github.com/L9Lenny/caddy-analyzer/pkg/reader"
	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

var flagTopBy string

var topCmd = &cobra.Command{
	Use:   "top [dimension] [source...]",
	Short: "Quickly display top-N metrics for a specific dimension (path, ip, ua, status, bandwidth)",
	Long: `Quickly inspect the top N requests for a specific dimension without generating a full analysis report.

Dimensions:
  path        Top requested HTTP URIs / endpoints (default)
  ip          Top client IP addresses (useful for identifying scrapers & DoS)
  ua          Top User-Agent strings (useful for bot/browser classification)
  status      Top HTTP status codes (200, 404, 500, etc.)
  method      Top HTTP methods (GET, POST, PUT, DELETE, etc.)
  host        Top request domain hosts
  bandwidth   Top paths sorted by total byte bandwidth transferred

Useful Flags:
  -t, --top <N>      Number of top entries to display (default: 10)
  -b, --by <dim>     Specify dimension via flag (path, ip, ua, status, bandwidth)
  --5xx              Filter only 5xx server error requests
  --slow <duration>  Filter requests taking longer than duration (e.g. 500ms, 1s)
  --no-bots          Exclude search engine crawlers and automated bots

Examples:
  caddy-analyze top /var/log/caddy/access.log
  caddy-analyze top ip /var/log/caddy/access.log
  caddy-analyze top ip /var/log/caddy/access.log --5xx
  caddy-analyze top bandwidth /var/log/caddy/access.log -t 20
  caddy-analyze top /var/log/caddy/access.log --by status --slow 500ms
  caddy-analyze top docker://my-caddy
`,
	Args: cobra.ArbitraryArgs,
	RunE: runTopCmd,
}

func init() {
	topCmd.Flags().StringVarP(&flagTopBy, "by", "b", "", "Dimension to group by (path, ip, ua, status, method, host, bandwidth)")
	rootCmd.AddCommand(topCmd)
}

func runTopCmd(cmd *cobra.Command, args []string) error {
	var dimension string
	var sourceArgs []string

	if flagTopBy != "" {
		dimension = flagTopBy
		sourceArgs = args
	} else if len(args) > 0 && isSupportedDimension(args[0]) {
		dimension = args[0]
		sourceArgs = args[1:]
	} else {
		dimension = "path"
		sourceArgs = args
	}

	sources := resolveSources(sourceArgs)

	filters, err := buildFilters()
	if err != nil {
		return err
	}

	engine := analysis.New(filters)
	ctx := context.Background()

	for _, src := range sources {
		r := reader.FromSource(src)
		lines, err := r.Read(ctx)
		if err != nil {
			continue
		}
		for line := range lines {
			entry, err := parser.Parse(line)
			if err != nil || entry == nil {
				continue
			}
			engine.Process(entry)
		}
	}

	engine.Finalize()
	s := engine.Stats()

	topN := flagTop
	if topN <= 0 {
		topN = 10
	}

	switch strings.ToLower(dimension) {
	case "path", "paths":
		output.TopFieldAnalysis(engine, types.TopPath, topN)
	case "ip", "ips":
		output.TopFieldAnalysis(engine, types.TopRemoteIP, topN)
	case "ua", "useragent", "user-agent":
		output.TopFieldAnalysis(engine, types.TopUserAgent, topN)
	case "status":
		output.TopFieldAnalysis(engine, types.TopStatus, topN)
	case "method", "methods":
		output.TopFieldAnalysis(engine, types.TopMethod, topN)
	case "host", "hosts":
		output.TopFieldAnalysis(engine, types.TopHost, topN)
	case "bandwidth", "bytes":
		items := analysis.TopN(s.PathBytesMap, topN)
		fmt.Printf("Top Bandwidth Paths:\n")
		for i, item := range items {
			fmt.Printf("  %d.  %-40s  (%s)\n", i+1, item.Key, output.FormatBytes(item.Count))
		}
	default:
		return fmt.Errorf("unknown dimension: %s (supported: path, ip, ua, status, method, host, bandwidth)", dimension)
	}

	return nil
}

func isSupportedDimension(s string) bool {
	switch strings.ToLower(s) {
	case "path", "paths", "ip", "ips", "ua", "useragent", "user-agent", "status", "method", "methods", "host", "hosts", "bandwidth", "bytes":
		return true
	}
	return false
}
