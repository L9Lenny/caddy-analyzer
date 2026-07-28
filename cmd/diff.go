package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/lenny/caddy-analyzer/pkg/analysis"
	"github.com/lenny/caddy-analyzer/pkg/output"
	"github.com/lenny/caddy-analyzer/pkg/parser"
	"github.com/lenny/caddy-analyzer/pkg/reader"
)

var (
	styleDiffTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	styleDiffGood  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleDiffBad   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleDiffWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleDiffDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

var diffCmd = &cobra.Command{
	Use:   "diff <baseline_log> <target_log>",
	Short: "Compare two log files to detect RPS shifts, 5xx error spikes, and latency changes",
	Args:  cobra.ExactArgs(2),
	RunE:  runDiffCmd,
}

func init() {
	rootCmd.AddCommand(diffCmd)
}

func runDiffCmd(cmd *cobra.Command, args []string) error {
	baseFile := args[0]
	currFile := args[1]

	ctx := context.Background()

	baseEngine, err := processLogFile(ctx, baseFile)
	if err != nil {
		return fmt.Errorf("baseline file %s: %w", baseFile, err)
	}

	currEngine, err := processLogFile(ctx, currFile)
	if err != nil {
		return fmt.Errorf("target file %s: %w", currFile, err)
	}

	diff := analysis.CompareStats(baseEngine, currEngine)

	fmt.Println(styleDiffTitle.Render("🔍 Caddy Log Comparative Diff"))
	fmt.Println(styleDiffDim.Render("Baseline: ") + baseFile)
	fmt.Println(styleDiffDim.Render("Target:   ") + currFile)
	fmt.Println(styleDiffDim.Render(strings.Repeat("━", 50)))

	fmt.Printf("\n%-22s  %-15s  %-15s  %-15s\n", "Metric", "Baseline", "Target", "Difference")
	fmt.Println(styleDiffDim.Render(strings.Repeat("─", 68)))

	fmt.Printf("%-22s  %-15d  %-15d  %s\n", "Total Requests", diff.BaseRequests, diff.CurrRequests, formatDeltaInt(diff.RequestsDelta))
	fmt.Printf("%-22s  %-15.2f  %-15.2f  %s\n", "Requests / Sec", diff.BaseRPS, diff.CurrRPS, formatDeltaFloat(diff.RPSDelta, "req/s"))

	errStr := formatDeltaInt(diff.ErrorsDelta)
	if diff.ErrorsDelta > 0 {
		errStr = styleDiffBad.Render(fmt.Sprintf("+%d ⚠️", diff.ErrorsDelta))
	} else if diff.ErrorsDelta < 0 {
		errStr = styleDiffGood.Render(fmt.Sprintf("%d", diff.ErrorsDelta))
	}
	fmt.Printf("%-22s  %-15d  %-15d  %s\n", "5xx Server Errors", diff.BaseErrors, diff.CurrErrors, errStr)

	latStr := formatDurationDelta(diff.AvgDurDelta)
	fmt.Printf("%-22s  %-15s  %-15s  %s\n", "Avg Latency", output.FormatDuration(diff.BaseAvgDuration), output.FormatDuration(diff.CurrAvgDuration), latStr)

	if len(diff.NewErrorPaths) > 0 {
		fmt.Printf("\n%s:\n", styleDiffBad.Render("🚨 New Error Paths Detected in Target"))
		for i, p := range diff.NewErrorPaths {
			fmt.Printf("  %d. %s\n", i+1, p)
		}
	} else {
		fmt.Printf("\n%s\n", styleDiffGood.Render("✔ No new error paths detected."))
	}

	return nil
}

func processLogFile(ctx context.Context, path string) (*analysis.Engine, error) {
	filters, _ := buildFilters()
	engine := analysis.New(filters)

	src := reader.ParseSource(path)
	r := reader.FromSource(src)
	lines, err := r.Read(ctx)
	if err != nil {
		return nil, err
	}
	for line := range lines {
		entry, err := parser.Parse(line)
		if err != nil || entry == nil {
			continue
		}
		engine.Process(entry)
	}
	engine.Finalize()
	return engine, nil
}

func formatDeltaInt(d int64) string {
	if d > 0 {
		return styleDiffWarn.Render(fmt.Sprintf("+%d", d))
	}
	if d < 0 {
		return styleDiffGood.Render(fmt.Sprintf("%d", d))
	}
	return "0"
}

func formatDeltaFloat(d float64, unit string) string {
	if d > 0 {
		return styleDiffGood.Render(fmt.Sprintf("+%.2f %s", d, unit))
	}
	if d < 0 {
		return styleDiffWarn.Render(fmt.Sprintf("%.2f %s", d, unit))
	}
	return fmt.Sprintf("0 %s", unit)
}

func formatDurationDelta(d float64) string {
	durStr := output.FormatDuration(d)
	if d > 0 {
		return styleDiffBad.Render("+" + durStr)
	}
	if d < 0 {
		return styleDiffGood.Render("-" + output.FormatDuration(-d))
	}
	return "0ms"
}
