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

var topCmd = &cobra.Command{
	Use:   "top [path|ip|ua|status|method|host|bandwidth] [source...]",
	Short: "Quickly display top metrics for a specific dimension",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTopCmd,
}

func init() {
	rootCmd.AddCommand(topCmd)
}

func runTopCmd(cmd *cobra.Command, args []string) error {
	dimension := strings.ToLower(args[0])
	sourceArgs := args[1:]
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

	switch dimension {
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
		return fmt.Errorf("unknown top field: %s (supported: path, ip, ua, status, method, host, bandwidth)", dimension)
	}

	return nil
}
