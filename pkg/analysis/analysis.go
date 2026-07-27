package analysis

import (
	"sort"
	"strings"

	"github.com/lenny/caddy-analyzer/pkg/types"
)

type Engine struct {
	filters  types.Filters
	entries  int
	stats    *types.Stats
	detector *Detector
}

func New(filters types.Filters) *Engine {
	return &Engine{
		filters: filters,
		stats:   types.NewStats(),
	}
}

func (e *Engine) SetDetector(d *Detector) {
	e.detector = d
}

func (e *Engine) Process(entry *types.LogEntry) {
	if !e.match(entry) {
		return
	}

	if e.detector != nil {
		if det := e.detector.Detect(entry); det != nil {
			e.stats.SuspiciousIPs[entry.RemoteIP]++
		}
	}

	e.entries++
	s := e.stats
	s.TotalRequests++

	if s.StartTime.IsZero() || entry.Timestamp.Before(s.StartTime) {
		s.StartTime = entry.Timestamp
	}
	if entry.Timestamp.After(s.EndTime) {
		s.EndTime = entry.Timestamp
	}

	s.StatusCounts[entry.Status]++
	s.MethodCounts[entry.Method]++
	s.PathCounts[entry.Path()]++
	s.HostCounts[entry.Host]++
	s.RemoteAddrCounts[entry.RemoteAddr]++
	s.UserAgentCounts[entry.UserAgent]++
	s.TotalBytes += entry.Size

	if entry.RemoteIP != "" {
		s.RemoteIPCounts[entry.RemoteIP]++
	}

	if entry.Status >= 500 {
		s.Errors++
	}
	switch {
	case entry.Status >= 200 && entry.Status < 300:
		s.Status2xx++
	case entry.Status >= 300 && entry.Status < 400:
		s.Status3xx++
	case entry.Status >= 400 && entry.Status < 500:
		s.Status4xx++
	case entry.Status >= 500:
		s.Status5xx++
	}

	s.DurationSum += entry.Duration
	if entry.Duration > s.MaxDuration {
		s.MaxDuration = entry.Duration
	}
	if entry.Duration < s.MinDuration {
		s.MinDuration = entry.Duration
	}
	s.AddDuration(entry.Duration)
}

func (e *Engine) Finalize() {
	e.stats.ComputePercentiles()
}

func (e *Engine) Stats() *types.Stats {
	return e.stats
}

func (e *Engine) Count() int {
	return e.entries
}

func (e *Engine) AvgDuration() float64 {
	if e.entries == 0 {
		return 0
	}
	return e.stats.DurationSum / float64(e.entries)
}

func (e *Engine) RPS() float64 {
	if e.stats.EndTime.IsZero() || e.stats.StartTime.IsZero() {
		return 0
	}
	elapsed := e.stats.EndTime.Sub(e.stats.StartTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(e.entries) / elapsed
}

func TopN(m map[string]int64, n int) []types.CountItem {
	var items []types.CountItem
	for k, v := range m {
		if k == "" {
			continue
		}
		items = append(items, types.CountItem{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if n > 0 && len(items) > n {
		items = items[:n]
	}
	return items
}

func TopNInt(m map[int]int64, n int) []types.CountIntItem {
	var items []types.CountIntItem
	for k, v := range m {
		items = append(items, types.CountIntItem{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if n > 0 && len(items) > n {
		items = items[:n]
	}
	return items
}

func (e *Engine) match(entry *types.LogEntry) bool {
	f := e.filters

	if f.HasFrom && entry.Timestamp.Before(f.From) {
		return false
	}
	if f.HasTo && entry.Timestamp.After(f.To) {
		return false
	}
	if len(f.Status) > 0 {
		found := false
		for _, s := range f.Status {
			if entry.Status == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.Method != "" && !strings.EqualFold(entry.Method, f.Method) {
		return false
	}
	if f.PathGlob != "" && !matchGlob(f.PathGlob, entry.Path()) {
		return false
	}
	if f.Host != "" && !strings.Contains(entry.Host, f.Host) {
		return false
	}
	if f.MinLatency > 0 && entry.Duration < f.MinLatency {
		return false
	}
	if f.MaxLatency > 0 && entry.Duration > f.MaxLatency {
		return false
	}
	if f.MinSize > 0 && entry.Size < f.MinSize {
		return false
	}
	if f.MaxSize > 0 && entry.Size > f.MaxSize {
		return false
	}
	if f.RemoteIP != "" && entry.RemoteIP != f.RemoteIP {
		return false
	}

	return true
}

func matchGlob(pattern, s string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		sub := pattern[1 : len(pattern)-1]
		return strings.Contains(s, sub)
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(s, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return s == pattern
}
