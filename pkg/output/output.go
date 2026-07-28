package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/L9Lenny/caddy-analyzer/pkg/analysis"
	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
	FormatHTML  Format = "html"
)

var (
	styleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	styleLabel   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	styleOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleError   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleInfo    = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleSuspect = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	styleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleBar     = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
)

func ParseFormat(s string) Format {
	switch strings.ToLower(s) {
	case "json":
		return FormatJSON
	case "csv":
		return FormatCSV
	case "html":
		return FormatHTML
	default:
		return FormatTable
	}
}

type Report struct {
	engine   *analysis.Engine
	format   Format
	top      int
	sections types.TopSections
	writer   io.Writer
	detect   bool
}

func NewReport(engine *analysis.Engine, format Format, top int) *Report {
	return &Report{
		engine:   engine,
		format:   format,
		top:      top,
		sections: types.DefaultTopSections(),
		writer:   os.Stdout,
	}
}

func NewReportWithSections(engine *analysis.Engine, format Format, top int, sections types.TopSections) *Report {
	return &Report{
		engine:   engine,
		format:   format,
		top:      top,
		sections: sections,
		writer:   os.Stdout,
	}
}

func (r *Report) SetWriter(w io.Writer) {
	r.writer = w
}

func (r *Report) SetDetect(d bool) {
	r.detect = d
}

func (r *Report) Print() {
	switch r.format {
	case FormatJSON:
		r.printJSON()
	case FormatCSV:
		r.printCSV()
	case FormatHTML:
		r.printHTML()
	default:
		r.printTable()
	}
}

func (r *Report) printTable() {
	s := r.engine.Stats()
	total := s.TotalRequests
	useColor := r.useColor()

	if useColor {
		fmt.Fprintln(r.writer, styleHeader.Render("⚡ Caddy Log Analysis Report"))
		fmt.Fprintln(r.writer, styleDim.Render(strings.Repeat("━", 45)))
	} else {
		fmt.Fprintln(r.writer, "Caddy Log Analysis Report")
		fmt.Fprintln(r.writer, strings.Repeat("=", 45))
	}
	fmt.Fprintln(r.writer)

	w := tabwriter.NewWriter(r.writer, 0, 0, 3, ' ', 0)

	duration := "N/A"
	if !s.EndTime.IsZero() && !s.StartTime.IsZero() {
		duration = s.EndTime.Sub(s.StartTime).Round(time.Second).String()
	}

	label := "Period:"
	if useColor {
		label = styleLabel.Render("Period:")
	}
	fmt.Fprintf(w, "%s\t%s — %s (%s)\n", label, formatTime(s.StartTime), formatTime(s.EndTime), duration)

	label = "Total Requests:"
	if useColor {
		label = styleLabel.Render("Total Requests:")
	}
	fmt.Fprintf(w, "%s\t%d\n", label, total)

	label = "Requests/sec:"
	if useColor {
		label = styleLabel.Render("Requests/sec:")
	}
	fmt.Fprintf(w, "%s\t%.2f\n\n", label, r.engine.RPS())

	statusLabel := "Status Codes Breakdown"
	if useColor {
		statusLabel = styleLabel.Render("Status Codes Breakdown")
	}
	fmt.Fprintf(w, "%s:\n", statusLabel)

	fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", styleOK.Render("2xx Success:"), s.Status2xx, pct(s.Status2xx, total), renderBarGraph(s.Status2xx, total, 15, useColor))
	fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", styleInfo.Render("3xx Redirect:"), s.Status3xx, pct(s.Status3xx, total), renderBarGraph(s.Status3xx, total, 15, useColor))
	fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", styleWarn.Render("4xx Client Err:"), s.Status4xx, pct(s.Status4xx, total), renderBarGraph(s.Status4xx, total, 15, useColor))
	fmt.Fprintf(w, "  %s\t%d (%.1f%%)\t%s\n", styleError.Render("5xx Server Err:"), s.Status5xx, pct(s.Status5xx, total), renderBarGraph(s.Status5xx, total, 15, useColor))

	errStyle := styleOK
	if s.Errors > 0 {
		errStyle = styleError
	}
	fmt.Fprintf(w, "  %s\t%d (%.1f%%)\n\n", errStyle.Render("Total Errors (5xx):"), s.Errors, pct(s.Errors, total))

	szLabel := "Response Size & Bandwidth"
	if useColor {
		szLabel = styleLabel.Render("Response Size & Bandwidth")
	}
	fmt.Fprintf(w, "%s:\n", szLabel)
	fmt.Fprintf(w, "  %s\t%s\n", "Total Transferred:", FormatBytes(s.TotalBytes))
	fmt.Fprintf(w, "  %s\t%s\n\n", "Avg Response Size:", FormatBytes(avgSize(s.TotalBytes, total)))

	durLabel := "Duration & Latency"
	if useColor {
		durLabel = styleLabel.Render("Duration & Latency")
	}
	fmt.Fprintf(w, "%s:\n", durLabel)
	fmt.Fprintf(w, "  %s\t%s\n", "Avg Latency:", FormatDuration(r.engine.AvgDuration()))
	fmt.Fprintf(w, "  %s\t%s\n", "Min Latency:", FormatDuration(s.MinDuration))
	fmt.Fprintf(w, "  %s\t%s\n", "Max Latency:", FormatDuration(s.MaxDuration))
	fmt.Fprintf(w, "  %s\t%s\n", "P50 Latency:", FormatDuration(s.Percentile50))
	fmt.Fprintf(w, "  %s\t%s\n", "P95 Latency:", FormatDuration(s.Percentile95))
	fmt.Fprintf(w, "  %s\t%s\n\n", "P99 Latency:", FormatDuration(s.Percentile99))

	botLabel := "Traffic & User-Agent Classification"
	if useColor {
		botLabel = styleLabel.Render("Traffic & User-Agent Classification")
	}
	fmt.Fprintf(w, "%s:\n", botLabel)
	fmt.Fprintf(w, "  %s\t%d (%.1f%%)\n", "Human Requests:", s.HumanRequests, pct(s.HumanRequests, total))
	fmt.Fprintf(w, "  %s\t%d (%.1f%%)\n\n", "Bot / Crawler Requests:", s.BotRequests, pct(s.BotRequests, total))

	if s.ParseErrors > 0 {
		fmt.Fprintf(w, "%s\t%d\n\n", styleError.Render("Parse Errors:"), s.ParseErrors)
	}

	if r.detect && len(s.SuspiciousIPs) > 0 {
		susLabel := "🚨 Suspicious Activity Detected"
		if useColor {
			susLabel = styleError.Render("🚨 Suspicious Activity Detected")
		}
		fmt.Fprintf(w, "%s:\n", susLabel)
		items := analysis.TopN(s.SuspiciousIPs, 20)
		for _, item := range items {
			line := fmt.Sprintf("  ⚠ %-15s %d suspicious requests", item.Key, item.Count)
			if useColor {
				line = styleSuspect.Render(line)
			}
			fmt.Fprintf(w, "%s\n", line)
		}
		fmt.Fprintf(w, "\n")
	}

	if r.top > 0 {
		if r.sections.Path {
			title := fmt.Sprintf("Top %d Paths", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.PathCounts, r.top), total, useColor)
		}
		if r.sections.IP {
			fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Remote IPs", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.RemoteIPCounts, r.top), total, useColor)
		}
		if r.sections.UA {
			fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d User Agents", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.UserAgentCounts, r.top), total, useColor)
		}
		if r.sections.Method {
			fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Methods", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.MethodCounts, r.top), total, useColor)
		}
		if r.sections.Status {
			fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Status Codes", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			fmt.Fprintf(w, "%s:\n", title)
			printTopIntN(w, analysis.TopNInt(s.StatusCounts, r.top))
		}
		if r.sections.Host {
			fmt.Fprintf(w, "\n")
			title := fmt.Sprintf("Top %d Hosts", r.top)
			if useColor {
				title = styleLabel.Render(title)
			}
			fmt.Fprintf(w, "%s:\n", title)
			printTopNWithBar(w, analysis.TopN(s.HostCounts, r.top), total, useColor)
		}
	}

	w.Flush()
}

func (r *Report) useColor() bool {
	return r.format == FormatTable && r.writer == os.Stdout
}

func renderBarGraph(count, total int64, width int, useColor bool) string {
	if total <= 0 || count <= 0 {
		return strings.Repeat("░", width)
	}
	ratio := float64(count) / float64(total)
	filled := int(ratio * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 1 && count > 0 {
		filled = 1
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if useColor {
		return styleBar.Render(bar)
	}
	return bar
}

func printTopNWithBar(w io.Writer, items []types.CountItem, total int64, useColor bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		bar := renderBarGraph(item.Count, total, 12, useColor)
		fmt.Fprintf(tw, "  %d.\t%-35s\t(%d)\t%s\n", i+1, item.Key, item.Count, bar)
	}
	tw.Flush()
}

func (r *Report) printJSON() {
	s := r.engine.Stats()
	total := s.TotalRequests

	data := map[string]interface{}{
		"total_requests": total,
		"period": map[string]interface{}{
			"start": s.StartTime,
			"end":   s.EndTime,
		},
		"requests_per_second": r.engine.RPS(),
		"status_codes": map[string]interface{}{
			"2xx":     s.Status2xx,
			"3xx":     s.Status3xx,
			"4xx":     s.Status4xx,
			"5xx":     s.Status5xx,
			"errors":  s.Errors,
			"by_code": s.StatusCounts,
		},
		"traffic": map[string]interface{}{
			"human": s.HumanRequests,
			"bot":   s.BotRequests,
		},
		"response_size": map[string]int64{
			"total": s.TotalBytes,
			"avg":   avgSize(s.TotalBytes, total),
		},
		"duration": map[string]float64{
			"avg": r.engine.AvgDuration(),
			"min": s.MinDuration,
			"max": s.MaxDuration,
			"p50": s.Percentile50,
			"p95": s.Percentile95,
			"p99": s.Percentile99,
		},
		"parse_errors": s.ParseErrors,
	}

	if r.detect && len(s.SuspiciousIPs) > 0 {
		data["suspicious_ips"] = analysis.TopN(s.SuspiciousIPs, 20)
	}

	if r.top > 0 {
		if r.sections.Path {
			data["top_paths"] = analysis.TopN(s.PathCounts, r.top)
		}
		if r.sections.IP {
			data["top_ips"] = analysis.TopN(s.RemoteIPCounts, r.top)
		}
		if r.sections.UA {
			data["top_user_agents"] = analysis.TopN(s.UserAgentCounts, r.top)
		}
		if r.sections.Method {
			data["top_methods"] = analysis.TopN(s.MethodCounts, r.top)
		}
		if r.sections.Status {
			data["top_statuses"] = analysis.TopNInt(s.StatusCounts, r.top)
		}
		if r.sections.Host {
			data["top_hosts"] = analysis.TopN(s.HostCounts, r.top)
		}
	}

	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

func (r *Report) printCSV() {
	s := r.engine.Stats()
	total := s.TotalRequests

	w := csv.NewWriter(r.writer)

	w.Write([]string{"metric", "value"})
	w.Write([]string{"total_requests", fmt.Sprintf("%d", total)})
	w.Write([]string{"rps", fmt.Sprintf("%.2f", r.engine.RPS())})
	w.Write([]string{"avg_duration_seconds", fmt.Sprintf("%.6f", r.engine.AvgDuration())})
	w.Write([]string{"status_2xx", fmt.Sprintf("%d", s.Status2xx)})
	w.Write([]string{"status_3xx", fmt.Sprintf("%d", s.Status3xx)})
	w.Write([]string{"status_4xx", fmt.Sprintf("%d", s.Status4xx)})
	w.Write([]string{"status_5xx", fmt.Sprintf("%d", s.Status5xx)})
	w.Write([]string{"errors", fmt.Sprintf("%d", s.Errors)})
	w.Write([]string{"human_requests", fmt.Sprintf("%d", s.HumanRequests)})
	w.Write([]string{"bot_requests", fmt.Sprintf("%d", s.BotRequests)})
	w.Write([]string{"total_bytes", fmt.Sprintf("%d", s.TotalBytes)})
	w.Write([]string{"parse_errors", fmt.Sprintf("%d", s.ParseErrors)})
	w.Write([]string{"duration_p50", fmt.Sprintf("%.6f", s.Percentile50)})
	w.Write([]string{"duration_p95", fmt.Sprintf("%.6f", s.Percentile95)})
	w.Write([]string{"duration_p99", fmt.Sprintf("%.6f", s.Percentile99)})

	if r.detect && len(s.SuspiciousIPs) > 0 {
		w.Write(nil)
		w.Write([]string{"suspicious_ips:ip", "count"})
		for _, item := range analysis.TopN(s.SuspiciousIPs, 20) {
			w.Write([]string{item.Key, fmt.Sprintf("%d", item.Count)})
		}
	}

	if r.top > 0 {
		if r.sections.Path {
			w.Write(nil)
			w.Write([]string{"top_paths:path", "count"})
			for _, item := range analysis.TopN(s.PathCounts, r.top) {
				w.Write([]string{item.Key, fmt.Sprintf("%d", item.Count)})
			}
		}
		if r.sections.IP {
			w.Write(nil)
			w.Write([]string{"top_ips:ip", "count"})
			for _, item := range analysis.TopN(s.RemoteIPCounts, r.top) {
				w.Write([]string{item.Key, fmt.Sprintf("%d", item.Count)})
			}
		}
	}

	w.Flush()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func avgSize(total int64, count int64) int64 {
	if count == 0 {
		return 0
	}
	return total / count
}

func FormatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.2f KB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.2f MB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
	}
}

func FormatDuration(d float64) string {
	switch {
	case d < 0.001:
		return fmt.Sprintf("%.0f\xc2\xb5s", d*1_000_000)
	case d < 1:
		return fmt.Sprintf("%.2fms", d*1000)
	case d < 60:
		return fmt.Sprintf("%.2fs", d)
	default:
		return fmt.Sprintf("%.1fm", d/60)
	}
}

func printTopN(w io.Writer, items []types.CountItem) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		fmt.Fprintf(tw, "  %d.\t%s\t(%d)\n", i+1, item.Key, item.Count)
	}
	tw.Flush()
}

func printTopIntN(w io.Writer, items []types.CountIntItem) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		fmt.Fprintf(tw, "  %d.\t%d\t(%d)\n", i+1, item.Key, item.Count)
	}
	tw.Flush()
}

func TopFieldAnalysis(engine *analysis.Engine, field types.TopField, n int) {
	s := engine.Stats()

	switch field {
	case types.TopPath:
		printTop(os.Stdout, "Paths", analysis.TopN(s.PathCounts, n))
	case types.TopMethod:
		printTop(os.Stdout, "Methods", analysis.TopN(s.MethodCounts, n))
	case types.TopStatus:
		printTopInt(os.Stdout, "Status Codes", analysis.TopNInt(s.StatusCounts, n))
	case types.TopHost:
		printTop(os.Stdout, "Hosts", analysis.TopN(s.HostCounts, n))
	case types.TopRemoteAddr:
		printTop(os.Stdout, "Remote Addresses", analysis.TopN(s.RemoteAddrCounts, n))
	case types.TopRemoteIP:
		printTop(os.Stdout, "Remote IPs", analysis.TopN(s.RemoteIPCounts, n))
	case types.TopUserAgent:
		printTop(os.Stdout, "User Agents", analysis.TopN(s.UserAgentCounts, n))
	}
}

func printTop(w io.Writer, title string, items []types.CountItem) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(w, "Top %s:\n", title)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		fmt.Fprintf(tw, "  %d.\t%s\t(%d)\n", i+1, item.Key, item.Count)
	}
	tw.Flush()
}

func printTopInt(w io.Writer, title string, items []types.CountIntItem) {
	if len(items) == 0 {
		return
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})

	fmt.Fprintf(w, "Top %s:\n", title)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, item := range items {
		fmt.Fprintf(tw, "  %d.\t%d\t(%d)\n", i+1, item.Key, item.Count)
	}
	tw.Flush()
}
