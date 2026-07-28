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
	Short: "Quickly display top metrics for a specific dimension",
	Long: `Quickly display top metrics by dimension (default: path).

Dimensions:
  path        Top requested HTTP paths (default)
  ip          Top client IP addresses
  ua          Top User-Agent strings
  status      Top HTTP status codes
  method      Top HTTP methods
  host        Top request hosts
  bandwidth   Top paths by total byte bandwidth

Examples:
  caddy-analyze top /var/log/caddy/access.log
  caddy-analyze top ip /var/log/caddy/access.log
  caddy-analyze top /var/log/caddy/access.log --by status
  caddy-analyze top bandwidth docker://my-caddy
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
