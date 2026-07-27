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

	"github.com/lenny/caddy-analyzer/pkg/analysis"
	"github.com/lenny/caddy-analyzer/pkg/types"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
)

func ParseFormat(s string) Format {
	switch strings.ToLower(s) {
	case "json":
		return FormatJSON
	case "csv":
		return FormatCSV
	default:
		return FormatTable
	}
}

type Report struct {
	engine *analysis.Engine
	format Format
	top    int
	sections types.TopSections
}

func NewReport(engine *analysis.Engine, format Format, top int) *Report {
	return &Report{engine: engine, format: format, top: top, sections: types.DefaultTopSections()}
}

func NewReportWithSections(engine *analysis.Engine, format Format, top int, sections types.TopSections) *Report {
	return &Report{engine: engine, format: format, top: top, sections: sections}
}

func (r *Report) Print() {
	switch r.format {
	case FormatJSON:
		r.printJSON()
	case FormatCSV:
		r.printCSV()
	default:
		r.printTable()
	}
}

func (r *Report) printTable() {
	s := r.engine.Stats()
	total := s.TotalRequests

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Fprintf(w, "Caddy Log Analysis Report\n")
	fmt.Fprintf(w, "========================\n\n")

	duration := "N/A"
	if !s.EndTime.IsZero() && !s.StartTime.IsZero() {
		duration = s.EndTime.Sub(s.StartTime).Round(time.Second).String()
	}
	fmt.Fprintf(w, "Period:\t%s — %s (%s)\n", formatTime(s.StartTime), formatTime(s.EndTime), duration)
	fmt.Fprintf(w, "Total Requests:\t%d\n", total)
	fmt.Fprintf(w, "Requests/sec:\t%.2f\n\n", r.engine.RPS())

	fmt.Fprintf(w, "Status Codes:\n")
	fmt.Fprintf(w, "  2xx:\t%d (%.1f%%)\n", s.Status2xx, pct(s.Status2xx, total))
	fmt.Fprintf(w, "  3xx:\t%d (%.1f%%)\n", s.Status3xx, pct(s.Status3xx, total))
	fmt.Fprintf(w, "  4xx:\t%d (%.1f%%)\n", s.Status4xx, pct(s.Status4xx, total))
	fmt.Fprintf(w, "  5xx:\t%d (%.1f%%)\n", s.Status5xx, pct(s.Status5xx, total))
	fmt.Fprintf(w, "  Errors (5xx):\t%d (%.1f%%)\n\n", s.Errors, pct(s.Errors, total))

	fmt.Fprintf(w, "Response Size:\n")
	fmt.Fprintf(w, "  Total:\t%s\n", formatBytes(s.TotalBytes))
	fmt.Fprintf(w, "  Avg:\t%s\n\n", formatBytes(avgSize(s.TotalBytes, total)))

	fmt.Fprintf(w, "Duration:\n")
	fmt.Fprintf(w, "  Avg:\t%s\n", formatDuration(r.engine.AvgDuration()))
	fmt.Fprintf(w, "  Min:\t%s\n", formatDuration(s.MinDuration))
	fmt.Fprintf(w, "  Max:\t%s\n", formatDuration(s.MaxDuration))
	fmt.Fprintf(w, "  P50:\t%s\n", formatDuration(s.Percentile50))
	fmt.Fprintf(w, "  P95:\t%s\n", formatDuration(s.Percentile95))
	fmt.Fprintf(w, "  P99:\t%s\n\n", formatDuration(s.Percentile99))

	if s.ParseErrors > 0 {
		fmt.Fprintf(w, "Parse Errors:\t%d\n\n", s.ParseErrors)
	}

	if r.top > 0 {
		if r.sections.Path {
			fmt.Fprintf(w, "Top %d Paths:\n", r.top)
			printTopN(w, analysis.TopN(s.PathCounts, r.top))
		}
		if r.sections.IP {
			fmt.Fprintf(w, "\nTop %d Remote IPs:\n", r.top)
			printTopN(w, analysis.TopN(s.RemoteIPCounts, r.top))
		}
		if r.sections.UA {
			fmt.Fprintf(w, "\nTop %d User Agents:\n", r.top)
			printTopN(w, analysis.TopN(s.UserAgentCounts, r.top))
		}
		if r.sections.Method {
			fmt.Fprintf(w, "\nTop %d Methods:\n", r.top)
			printTopN(w, analysis.TopN(s.MethodCounts, r.top))
		}
		if r.sections.Status {
			fmt.Fprintf(w, "\nTop %d Status Codes:\n", r.top)
			printTopIntN(w, analysis.TopNInt(s.StatusCounts, r.top))
		}
		if r.sections.Host {
			fmt.Fprintf(w, "\nTop %d Hosts:\n", r.top)
			printTopN(w, analysis.TopN(s.HostCounts, r.top))
		}
	}

	w.Flush()
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
			"2xx":    s.Status2xx,
			"3xx":    s.Status3xx,
			"4xx":    s.Status4xx,
			"5xx":    s.Status5xx,
			"errors": s.Errors,
			"by_code": s.StatusCounts,
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

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

func (r *Report) printCSV() {
	s := r.engine.Stats()
	total := s.TotalRequests

	w := csv.NewWriter(os.Stdout)

	w.Write([]string{"metric", "value"})
	w.Write([]string{"total_requests", fmt.Sprintf("%d", total)})
	w.Write([]string{"rps", fmt.Sprintf("%.2f", r.engine.RPS())})
	w.Write([]string{"avg_duration_seconds", fmt.Sprintf("%.6f", r.engine.AvgDuration())})
	w.Write([]string{"status_2xx", fmt.Sprintf("%d", s.Status2xx)})
	w.Write([]string{"status_3xx", fmt.Sprintf("%d", s.Status3xx)})
	w.Write([]string{"status_4xx", fmt.Sprintf("%d", s.Status4xx)})
	w.Write([]string{"status_5xx", fmt.Sprintf("%d", s.Status5xx)})
	w.Write([]string{"errors", fmt.Sprintf("%d", s.Errors)})
	w.Write([]string{"total_bytes", fmt.Sprintf("%d", s.TotalBytes)})
	w.Write([]string{"parse_errors", fmt.Sprintf("%d", s.ParseErrors)})
	w.Write([]string{"duration_p50", fmt.Sprintf("%.6f", s.Percentile50)})
	w.Write([]string{"duration_p95", fmt.Sprintf("%.6f", s.Percentile95)})
	w.Write([]string{"duration_p99", fmt.Sprintf("%.6f", s.Percentile99)})

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

func formatBytes(b int64) string {
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

func formatDuration(d float64) string {
	switch {
	case d < 0.001:
		return fmt.Sprintf("%.0fµs", d*1_000_000)
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
