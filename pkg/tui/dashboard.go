package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lenny/caddy-analyzer/pkg/analysis"
	"github.com/lenny/caddy-analyzer/pkg/parser"
	"github.com/lenny/caddy-analyzer/pkg/types"
)

type TickMsg time.Time
type LineMsg string
type StreamEndMsg struct{}

type view int

const (
	viewSummary view = iota
	viewTopIPs
	viewTopPaths
	viewTopUA
)

type Model struct {
	engine   *analysis.Engine
	linesCh  chan string
	ready    bool
	width    int
	height   int
	current  view
	err      error
	stats    *types.Stats
	rps      float64

	ipTable   table.Model
	pathTable table.Model
	uaItems   []types.CountItem
}

var (
	styleTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	styleLabel  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleError  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	styleInfo   = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	styleHelp   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleActive = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")).Underline(true)
)

func NewModel(linesCh chan string) Model {
	return Model{
		engine:  analysis.New(types.Filters{}),
		linesCh: linesCh,
		current: viewSummary,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		waitForLines(m.linesCh),
		tickEvery(2*time.Second),
	)
}

func waitForLines(ch chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return StreamEndMsg{}
		}
		return LineMsg(line)
	}
}

func tickEvery(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		m.initTables()
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "1":
			m.current = viewSummary
		case "2":
			m.current = viewTopIPs
			m.refreshTables()
		case "3":
			m.current = viewTopPaths
			m.refreshTables()
		case "4":
			m.current = viewTopUA
		case "tab", "right":
			if m.current < viewTopUA {
				m.current++
				m.refreshTables()
			}
		case "shift+tab", "left":
			if m.current > viewSummary {
				m.current--
				m.refreshTables()
			}
		case "r":
			m.engine = analysis.New(types.Filters{})
			m.stats = nil
		}

	case LineMsg:
		entry, err := parser.Parse(string(msg))
		if err == nil && entry != nil {
			m.engine.Process(entry)
		}
		return m, waitForLines(m.linesCh)

	case StreamEndMsg:
		return m, nil

	case TickMsg:
		m.engine.Finalize()
		s := m.engine.Stats()
		m.stats = s
		elapsed := s.EndTime.Sub(s.StartTime).Seconds()
		if elapsed <= 0 {
			elapsed = 2
		}
		m.rps = float64(s.TotalRequests) / elapsed
		m.uaItems = analysis.TopN(s.UserAgentCounts, 15)
		m.refreshTables()

		m.engine = analysis.New(types.Filters{})
		if !s.EndTime.IsZero() {
			m.engine.Stats().StartTime = s.EndTime
		}

		return m, tickEvery(2 * time.Second)
	}

	return m, nil
}

func (m *Model) initTables() {
	columns := []table.Column{
		{Title: "#", Width: 4},
		{Title: "IP", Width: 18},
		{Title: "Requests", Width: 10},
	}

	m.ipTable = table.New(
		table.WithColumns(columns),
		table.WithFocused(false),
		table.WithHeight(min(15, m.height-10)),
	)

	pathCols := []table.Column{
		{Title: "#", Width: 4},
		{Title: "Path", Width: 40},
		{Title: "Requests", Width: 10},
	}

	m.pathTable = table.New(
		table.WithColumns(pathCols),
		table.WithFocused(false),
		table.WithHeight(min(15, m.height-10)),
	)
}

func (m *Model) refreshTables() {
	if !m.ready || m.stats == nil {
		return
	}

	s := m.stats

	ips := analysis.TopN(s.RemoteIPCounts, 20)
	var ipRows []table.Row
	for i, ip := range ips {
		ipRows = append(ipRows, table.Row{
			fmt.Sprintf("%d", i+1),
			ip.Key,
			fmt.Sprintf("%d", ip.Count),
		})
	}
	m.ipTable.SetRows(ipRows)

	paths := analysis.TopN(s.PathCounts, 20)
	var pathRows []table.Row
	for i, p := range paths {
		pathRows = append(pathRows, table.Row{
			fmt.Sprintf("%d", i+1),
			truncate(p.Key, 38),
			fmt.Sprintf("%d", p.Count),
		})
	}
	m.pathTable.SetRows(pathRows)
}

func (m Model) View() string {
	if !m.ready {
		return " Caddy Monitor — loading...\n"
	}

	var b strings.Builder

	b.WriteString(styleTitle.Render(" Caddy Monitor"))
	b.WriteString(styleHelp.Render("  [q] quit  [1-4] views  [tab] next  [r] reset"))
	b.WriteString("\n")
	b.WriteString(styleDimLine())
	b.WriteString("\n\n")

	switch m.current {
	case viewSummary:
		m.renderSummary(&b)
	case viewTopIPs:
		m.renderIPs(&b)
	case viewTopPaths:
		m.renderPaths(&b)
	case viewTopUA:
		m.renderUA(&b)
	}

	b.WriteString("\n")
	b.WriteString(m.viewTabs())

	return b.String()
}

func (m Model) viewTabs() string {
	tabs := []string{"Summary", "Top IPs", "Top Paths", "User Agents"}
	var parts []string
	for i, t := range tabs {
		if view(i) == m.current {
			parts = append(parts, styleActive.Render(t))
		} else {
			parts = append(parts, t)
		}
	}
	return styleHelp.Render(" [") + strings.Join(parts, styleHelp.Render(" | ")) + styleHelp.Render("]")
}

func (m Model) renderSummary(b *strings.Builder) {
	s := m.stats
	if s == nil {
		fmt.Fprintf(b, "  Waiting for data...\n")
		return
	}

	total := s.TotalRequests

	fmt.Fprintf(b, "  %s %d\n", styleLabel.Render("Total Requests:"), total)
	fmt.Fprintf(b, "  %s %.1f\n\n", styleLabel.Render("Requests/sec:"), m.rps)

	fmt.Fprintf(b, "  %s:\n", styleLabel.Render("Status Codes"))
	fmt.Fprintf(b, "    2xx: %s\n", styleOK.Render(fmt.Sprintf("%d (%.1f%%)", s.Status2xx, pct(s.Status2xx, total))))
	fmt.Fprintf(b, "    3xx: %s\n", styleInfo.Render(fmt.Sprintf("%d (%.1f%%)", s.Status3xx, pct(s.Status3xx, total))))
	fmt.Fprintf(b, "    4xx: %s\n", styleWarn.Render(fmt.Sprintf("%d (%.1f%%)", s.Status4xx, pct(s.Status4xx, total))))
	fmt.Fprintf(b, "    5xx: %s\n\n", styleError.Render(fmt.Sprintf("%d (%.1f%%)", s.Status5xx, pct(s.Status5xx, total))))

	fmt.Fprintf(b, "  %s %s\n", styleLabel.Render("Response Size:"), formatBytes(s.TotalBytes))
	fmt.Fprintf(b, "  %s %s\n\n", styleLabel.Render("Avg Size:"), formatBytes(avgSize(s.TotalBytes, total)))

	fmt.Fprintf(b, "  %s:\n", styleLabel.Render("Duration"))
	if s.MinDuration < 1<<62 {
		fmt.Fprintf(b, "    Min: %s\n", formatDuration(s.MinDuration))
	}
	fmt.Fprintf(b, "    Avg: %s\n", formatDuration(s.DurationSum/float64(max(s.TotalRequests, 1))))
	fmt.Fprintf(b, "    Max: %s\n", formatDuration(s.MaxDuration))
	fmt.Fprintf(b, "    P50: %s\n", formatDuration(s.Percentile50))
	fmt.Fprintf(b, "    P95: %s\n", formatDuration(s.Percentile95))
}

func (m Model) renderIPs(b *strings.Builder) {
	if m.stats == nil {
		return
	}
	fmt.Fprintf(b, "  %s\n\n", styleLabel.Render("Top Remote IPs"))
	b.WriteString(m.ipTable.View())
}

func (m Model) renderPaths(b *strings.Builder) {
	if m.stats == nil {
		return
	}
	fmt.Fprintf(b, "  %s\n\n", styleLabel.Render("Top Paths"))
	b.WriteString(m.pathTable.View())
}

func (m Model) renderUA(b *strings.Builder) {
	if len(m.uaItems) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s\n\n", styleLabel.Render("Top User Agents"))
	for i, item := range m.uaItems {
		fmt.Fprintf(b, "  %d. %-40s %d\n", i+1, truncate(item.Key, 38), item.Count)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
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

func styleDimLine() string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("236")).Render(strings.Repeat("━", 50))
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
