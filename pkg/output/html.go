package output

import (
	"fmt"
	"io"

	"github.com/lenny/caddy-analyzer/pkg/analysis"
	"github.com/lenny/caddy-analyzer/pkg/types"
)

func (r *Report) printHTML() {
	s := r.engine.Stats()
	total := s.TotalRequests

	topPaths := analysis.TopN(s.PathCounts, r.top)
	topIPs := analysis.TopN(s.RemoteIPCounts, r.top)
	topUAs := analysis.TopN(s.UserAgentCounts, r.top)
	topMethods := analysis.TopN(s.MethodCounts, r.top)
	topProtos := analysis.TopN(s.ProtoCounts, 5)
	topTLS := analysis.TopN(s.TLSVersionCounts, 5)
	topBots := analysis.TopN(s.BotCounts, 5)
	topReferers := analysis.TopN(s.RefererCounts, 5)
	topPathBytes := analysis.TopN(s.PathBytesMap, 5)
	suspicious := analysis.TopN(s.SuspiciousIPs, 20)

	html := generateHTMLReport(s, total, r.engine.RPS(), r.engine.AvgDuration(),
		topPaths, topIPs, topUAs, topMethods, topProtos, topTLS, topBots, topReferers, topPathBytes, suspicious, r.detect)

	fmt.Fprint(r.writer, html)
}

func generateHTMLReport(
	s *types.Stats,
	total int64,
	rps float64,
	avgDur float64,
	topPaths, topIPs, topUAs, topMethods, topProtos, topTLS, topBots, topReferers, topPathBytes, suspicious []types.CountItem,
	detect bool,
) string {
	errPct := float64(0)
	if total > 0 {
		errPct = float64(s.Errors) / float64(total) * 100
	}
	botPct := float64(0)
	if total > 0 {
		botPct = float64(s.BotRequests) / float64(total) * 100
	}

	durationStr := "N/A"
	if !s.EndTime.IsZero() && !s.StartTime.IsZero() {
		durationStr = s.EndTime.Sub(s.StartTime).String()
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caddy Log Analysis Dashboard</title>
    <style>
        :root {
            --bg: #0f172a;
            --card-bg: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --success: #4ade80;
            --warning: #fbbf24;
            --danger: #f87171;
            --purple: #c084fc;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 2rem; }
        header { margin-bottom: 2rem; }
        h1 { font-size: 1.8rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 0.75rem; }
        h1 span { font-size: 0.9rem; font-weight: 400; padding: 0.25rem 0.6rem; background: var(--border); border-radius: 999px; color: var(--accent); }
        .meta { margin-top: 0.5rem; color: var(--text-muted); font-size: 0.9rem; }
        
        .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; }
        .stat-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); font-weight: 600; }
        .stat-value { font-size: 1.8rem; font-weight: 700; margin-top: 0.3rem; color: var(--accent); }
        .stat-card.danger .stat-value { color: var(--danger); }
        .stat-card.success .stat-value { color: var(--success); }
        
        .grid-main { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.5rem; }
        .card h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; color: var(--text); }
        
        table { width: 100%%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.9rem; }
        th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); }
        th { color: var(--text-muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
        td.count { text-align: right; font-weight: 600; font-family: monospace; color: var(--accent); }
        td.bar-cell { width: 30%%; }

        .progress-bar { background: var(--border); border-radius: 4px; height: 8px; overflow: hidden; width: 100%%; }
        .progress-fill { background: var(--accent); height: 100%%; border-radius: 4px; }
        .progress-fill.danger { background: var(--danger); }
        .progress-fill.success { background: var(--success); }
        .progress-fill.warning { background: var(--warning); }
        
        .alert-item { background: rgba(248, 113, 113, 0.1); border-left: 4px solid var(--danger); padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 0.5rem; font-size: 0.9rem; font-family: monospace; }
    </style>
</head>
<body>
    <header>
        <h1>⚡ Caddy Log Analysis Dashboard <span>Caddy v2</span></h1>
        <div class="meta">Period: %s — %s (%s)</div>
    </header>

    <div class="grid-stats">
        <div class="stat-card">
            <div class="stat-label">Total Requests</div>
            <div class="stat-value">%d</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Requests / Sec</div>
            <div class="stat-value">%.2f</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Avg Duration</div>
            <div class="stat-value">%s</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Total Bandwidth</div>
            <div class="stat-value">%s</div>
        </div>
        <div class="stat-card %s">
            <div class="stat-label">Error Rate (5xx)</div>
            <div class="stat-value">%.1f%%</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Bot Traffic</div>
            <div class="stat-value">%.1f%%</div>
        </div>
    </div>

    <div class="grid-main">
        <!-- Top Paths -->
        <div class="card">
            <h2>🔥 Top Requested Paths</h2>
            <table>
                <thead><tr><th>Path</th><th>Count</th><th class="bar-cell">Distribution</th></tr></thead>
                <tbody>%s</tbody>
            </table>
        </div>

        <!-- Top IPs -->
        <div class="card">
            <h2>🌐 Top Client IP Addresses</h2>
            <table>
                <thead><tr><th>IP Address</th><th>Requests</th><th class="bar-cell">Distribution</th></tr></thead>
                <tbody>%s</tbody>
            </table>
        </div>

        <!-- Status Codes -->
        <div class="card">
            <h2>📊 Status Codes Breakdown</h2>
            <table>
                <thead><tr><th>Code Class</th><th>Requests</th><th>Ratio</th></tr></thead>
                <tbody>
                    <tr><td>2xx Success</td><td class="count">%d</td><td>%.1f%%</td></tr>
                    <tr><td>3xx Redirect</td><td class="count">%d</td><td>%.1f%%</td></tr>
                    <tr><td>4xx Client Error</td><td class="count">%d</td><td>%.1f%%</td></tr>
                    <tr><td>5xx Server Error</td><td class="count">%d</td><td>%.1f%%</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Protocol & TLS -->
        <div class="card">
            <h2>🔒 Protocols & TLS Handshake</h2>
            <table>
                <thead><tr><th>Protocol / TLS</th><th>Requests</th></tr></thead>
                <tbody>%s</tbody>
            </table>
        </div>

        <!-- Security Alerts -->
        %s
    </div>
</body>
</html>`,
		formatTime(s.StartTime), formatTime(s.EndTime), durationStr,
		total, rps, FormatDuration(avgDur), FormatBytes(s.TotalBytes),
		cardClass(errPct), errPct, botPct,
		renderTableRows(topPaths, total),
		renderTableRows(topIPs, total),
		s.Status2xx, pct(s.Status2xx, total),
		s.Status3xx, pct(s.Status3xx, total),
		s.Status4xx, pct(s.Status4xx, total),
		s.Status5xx, pct(s.Status5xx, total),
		renderMixedRows(topProtos, topTLS),
		renderSecurityAlertsHTML(suspicious, detect),
	)
}

func cardClass(errPct float64) string {
	if errPct > 5 {
		return "danger"
	}
	return "success"
}

func renderTableRows(items []types.CountItem, total int64) string {
	var rows string
	for _, item := range items {
		ratio := float64(0)
		if total > 0 {
			ratio = float64(item.Count) / float64(total) * 100
		}
		rows += fmt.Sprintf(`<tr><td>%s</td><td class="count">%d</td><td class="bar-cell"><div class="progress-bar"><div class="progress-fill" style="width: %.1f%%"></div></div></td></tr>`,
			escapeHTML(item.Key), item.Count, ratio)
	}
	return rows
}

func renderMixedRows(protos, tls []types.CountItem) string {
	var rows string
	for _, p := range protos {
		rows += fmt.Sprintf(`<tr><td>Proto: %s</td><td class="count">%d</td></tr>`, escapeHTML(p.Key), p.Count)
	}
	for _, t := range tls {
		rows += fmt.Sprintf(`<tr><td>TLS: %s</td><td class="count">%d</td></tr>`, escapeHTML(t.Key), t.Count)
	}
	return rows
}

func renderSecurityAlertsHTML(suspicious []types.CountItem, detect bool) string {
	if !detect || len(suspicious) == 0 {
		return `<div class="card"><h2>🛡️ Security & Anomaly Report</h2><p style="color:var(--text-muted); font-size:0.9rem;">No suspicious activities detected.</p></div>`
	}
	var alerts string
	for _, item := range suspicious {
		alerts += fmt.Sprintf(`<div class="alert-item">⚠️ IP: <strong>%s</strong> — %d suspicious requests triggered</div>`, escapeHTML(item.Key), item.Count)
	}
	return fmt.Sprintf(`<div class="card"><h2>🛡️ Security & Anomaly Alerts</h2>%s</div>`, alerts)
}

func escapeHTML(s string) string {
	s = stringReplace(s, "&", "&amp;")
	s = stringReplace(s, "<", "&lt;")
	s = stringReplace(s, ">", "&gt;")
	s = stringReplace(s, "\"", "&quot;")
	return s
}

func stringReplace(s, old, newStr string) string {
	var result string
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += newStr
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}

func writeHTML(w io.Writer, content string) {
	fmt.Fprint(w, content)
}
