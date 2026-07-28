package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/lenny/caddy-analyzer/pkg/output"
	"github.com/lenny/caddy-analyzer/pkg/parser"
	"github.com/lenny/caddy-analyzer/pkg/reader"
	"github.com/lenny/caddy-analyzer/pkg/types"
)

var (
	styleTail2xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	styleTail3xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Bold(true)
	styleTail4xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	styleTail5xx  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	styleTailDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleTailIP   = lipgloss.NewStyle().Foreground(lipgloss.Color("141"))
	styleTailPath = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
)

var tailCmd = &cobra.Command{
	Use:   "tail [source...]",
	Short: "Stream and colorize Caddy access logs in real time",
	RunE:  runTail,
}

func init() {
	rootCmd.AddCommand(tailCmd)
}

func runTail(cmd *cobra.Command, args []string) error {
	sources := resolveSources(args)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	for _, src := range sources {
		r := reader.FromSourceFollow(src)
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
			printColorizedLog(entry)
		}
	}
	return nil
}

func printColorizedLog(e *types.LogEntry) {
	timeStr := styleTailDim.Render(e.Timestamp.Format("15:04:05"))
	statusStr := formatStatus(e.Status)
	methodStr := lipgloss.NewStyle().Bold(true).Render(e.Method)
	pathStr := styleTailPath.Render(e.Path())
	ipStr := styleTailIP.Render(e.RemoteIP)
	sizeStr := output.FormatBytes(e.Size)
	durStr := output.FormatDuration(e.Duration)

	uaInfo := ""
	if e.IsBot {
		uaInfo = fmt.Sprintf(" [%s]", lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("🤖 "+e.BotName))
	} else if e.Browser != "" || e.OS != "" {
		uaInfo = fmt.Sprintf(" [%s/%s]", e.OS, e.Browser)
	}

	fmt.Printf("%s  %s  %s %s  (%s, %s) - %s%s\n",
		timeStr, statusStr, methodStr, pathStr, sizeStr, durStr, ipStr, uaInfo)
}

func formatStatus(s int) string {
	str := fmt.Sprintf("%d", s)
	switch {
	case s >= 200 && s < 300:
		return styleTail2xx.Render(str + " OK")
	case s >= 300 && s < 400:
		return styleTail3xx.Render(str + " REDIR")
	case s >= 400 && s < 500:
		return styleTail4xx.Render(str + " WARN")
	case s >= 500:
		return styleTail5xx.Render(str + " ERR")
	default:
		return str
	}
}
