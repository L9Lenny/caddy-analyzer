package types

import (
	"sort"
	"strings"
	"time"
)

type LogEntry struct {
	Timestamp   time.Time
	Level       string
	Logger      string
	Method      string
	URI         string
	Host        string
	RemoteAddr  string
	RemoteIP    string
	Proto       string
	UserAgent   string
	Referer     string
	Status      int
	Size        int64
	Duration    float64
	Raw         string
}

type SourceType string

const (
	SourceFile       SourceType = "file"
	SourceStdin      SourceType = "stdin"
	SourceDocker     SourceType = "docker"
	SourceK8s        SourceType = "k8s"
	SourceJournalctl SourceType = "journalctl"
)

type LogSource struct {
	Type      SourceType
	Path      string
	Namespace string
}

type Filters struct {
	From       time.Time
	To         time.Time
	HasFrom    bool
	HasTo      bool
	Status     []int
	Method     string
	PathGlob   string
	Host       string
	MinLatency float64
	MaxLatency float64
	MinSize    int64
	MaxSize    int64
	RemoteIP   string
}

type TopField string

const (
	TopPath       TopField = "path"
	TopMethod     TopField = "method"
	TopStatus     TopField = "status"
	TopHost       TopField = "host"
	TopRemoteAddr TopField = "remote_addr"
	TopUserAgent  TopField = "user_agent"
	TopRemoteIP   TopField = "remote_ip"
)

type Stats struct {
	TotalRequests    int64
	StatusCounts     map[int]int64
	MethodCounts     map[string]int64
	PathCounts       map[string]int64
	HostCounts       map[string]int64
	RemoteAddrCounts map[string]int64
	RemoteIPCounts   map[string]int64
	UserAgentCounts  map[string]int64
	TotalBytes       int64
	DurationSum      float64
	MaxDuration      float64
	MinDuration      float64
	Percentile50     float64
	Percentile95     float64
	Percentile99     float64
	StartTime        time.Time
	EndTime          time.Time
	Errors           int64
	ParseErrors      int64
	Status2xx        int64
	Status3xx        int64
	Status4xx        int64
	Status5xx        int64

	SuspiciousIPs map[string]int64

	durations []float64
}

type CountItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type CountIntItem struct {
	Key   int   `json:"key"`
	Count int64 `json:"count"`
}

type TopSections struct {
	Path   bool
	IP     bool
	UA     bool
	Method bool
	Status bool
	Host   bool
}

func DefaultTopSections() TopSections {
	return TopSections{Path: true, IP: true, UA: true, Method: true, Status: true, Host: true}
}

func (e *LogEntry) Path() string {
	if idx := strings.Index(e.URI, "?"); idx >= 0 {
		return e.URI[:idx]
	}
	return e.URI
}

func NewStats() *Stats {
	return &Stats{
		StatusCounts:     make(map[int]int64),
		MethodCounts:     make(map[string]int64),
		PathCounts:       make(map[string]int64),
		HostCounts:       make(map[string]int64),
		RemoteAddrCounts: make(map[string]int64),
		RemoteIPCounts:   make(map[string]int64),
		UserAgentCounts:  make(map[string]int64),
		SuspiciousIPs:    make(map[string]int64),
		MinDuration:      1<<63 - 1,
		durations:        make([]float64, 0, 10000),
	}
}

func (s *Stats) AddDuration(d float64) {
	s.durations = append(s.durations, d)
}

func (s *Stats) ComputePercentiles() {
	n := len(s.durations)
	if n == 0 {
		return
	}
	sort.Float64s(s.durations)
	s.Percentile50 = percentile(s.durations, 50, n)
	s.Percentile95 = percentile(s.durations, 95, n)
	s.Percentile99 = percentile(s.durations, 99, n)
	s.durations = nil
}

func percentile(sorted []float64, p int, n int) float64 {
	if n == 0 {
		return 0
	}
	idx := (p * n / 100)
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}
