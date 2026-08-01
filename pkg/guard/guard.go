package guard

import (
	"container/heap"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/L9Lenny/caddy-analyzer/pkg/analysis"
	"github.com/L9Lenny/caddy-analyzer/pkg/parser"
	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

type Blocker interface {
	Block(ip string) error
	Unblock(ip string) error
}

type iptablesBlocker struct{}

func (iptablesBlocker) Block(ip string) error {
	return exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP").Run()
}

func (iptablesBlocker) Unblock(ip string) error {
	return exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
}

type Config struct {
	Limit         int
	AuthLimit     int
	NotFoundLimit int
	Window        time.Duration
	BlockDuration time.Duration
	IPValidator   func(string) error
	OnAudit       func(action, ip, reason, duration string)
}

type expiryEntry struct {
	ip   string
	when time.Time
}

type expiryHeap []expiryEntry

func (h expiryHeap) Len() int            { return len(h) }
func (h expiryHeap) Less(i, j int) bool  { return h[i].when.Before(h[j].when) }
func (h expiryHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)         { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

type Guard struct {
	mu       sync.Mutex
	blocked  map[string]bool
	detector *analysis.Detector
	engine   *analysis.Engine
	blocker  Blocker
	cfg      Config
	expCh    chan expiryEntry
}

func New(cfg Config) *Guard {
	return &Guard{
		blocked:  make(map[string]bool),
		detector: analysis.NewDetector(),
		engine:   analysis.New(types.Filters{}),
		blocker:  iptablesBlocker{},
		cfg:      cfg,
		expCh:    make(chan expiryEntry, 10000),
	}
}

func (g *Guard) SetBlocker(b Blocker) {
	g.blocker = b
}

func (g *Guard) IsBlocked(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.blocked[ip]
}

func (g *Guard) setBlocked(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked[ip] = true
}

func (g *Guard) removeBlocked(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.blocked, ip)
}

func (g *Guard) Count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.blocked)
}

func (g *Guard) Detector() *analysis.Detector {
	return g.detector
}

func (g *Guard) Engine() *analysis.Engine {
	return g.engine
}

func (g *Guard) Evaluate(line string) {
	entry, err := parser.Parse(line)
	if err != nil || entry == nil {
		return
	}
	if g.IsBlocked(entry.RemoteIP) {
		return
	}
	g.detector.Detect(entry)
	g.engine.Process(entry)
}

type Candidate struct {
	IP    string
	Count int64
	Why   string
}

func (g *Guard) Tick(ctx context.Context) []Candidate {
	now := time.Now()
	s := g.engine.Stats()
	ipStats := g.detector.IPStats()

	var candidates []Candidate
	seen := make(map[string]bool)

	for ip, count := range s.RemoteIPCounts {
		if g.IsBlocked(ip) {
			continue
		}
		stats := ipStats[ip]
		why := ""
		if stats != nil && stats.AuthFailures >= g.cfg.AuthLimit {
			why = fmt.Sprintf("%d auth failures", stats.AuthFailures)
		} else if stats != nil && stats.NotFound >= g.cfg.NotFoundLimit {
			why = fmt.Sprintf("%d not found", stats.NotFound)
		} else if count >= int64(g.cfg.Limit) {
			why = fmt.Sprintf("%d requests", count)
		}
		if why != "" {
			candidates = append(candidates, Candidate{ip, count, why})
			seen[ip] = true
		}
	}

	for ip, stats := range ipStats {
		if g.IsBlocked(ip) || seen[ip] {
			continue
		}
		why := ""
		if stats.AuthFailures >= g.cfg.AuthLimit {
			why = fmt.Sprintf("%d auth failures", stats.AuthFailures)
		} else if stats.NotFound >= g.cfg.NotFoundLimit {
			why = fmt.Sprintf("%d not found", stats.NotFound)
		}
		if why != "" {
			candidates = append(candidates, Candidate{ip, int64(stats.Total), why})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Count > candidates[j].Count
	})

	var blocked []Candidate
	for _, c := range candidates {
		if g.cfg.IPValidator != nil {
			if err := g.cfg.IPValidator(c.IP); err != nil {
				continue
			}
		}
		if g.block(ctx, c, now) {
			blocked = append(blocked, c)
		}
	}

	g.detector = analysis.NewDetector()
	g.engine = analysis.New(types.Filters{})
	g.engine.Stats().StartTime = now

	return blocked
}

func (g *Guard) block(ctx context.Context, c Candidate, now time.Time) bool {
	g.setBlocked(c.IP)
	if err := g.blocker.Block(c.IP); err != nil {
		g.removeBlocked(c.IP)
		return false
	}
	if g.cfg.OnAudit != nil {
		dur := g.cfg.BlockDuration.String()
		if g.cfg.BlockDuration <= 0 {
			dur = "permanent"
		}
		g.cfg.OnAudit("block", c.IP, c.Why, dur)
	}
	if g.cfg.BlockDuration > 0 {
		select {
		case g.expCh <- expiryEntry{ip: c.IP, when: now.Add(g.cfg.BlockDuration)}:
		case <-ctx.Done():
		}
	}
	return true
}

func (g *Guard) runExpiryLoop(ctx context.Context) {
	var h expiryHeap
	var timer *time.Timer
	var timerC <-chan time.Time

	for {
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}
		if h.Len() > 0 {
			d := time.Until(h[0].when)
			if d < 0 {
				d = 0
			}
			timer = time.NewTimer(d)
			timerC = timer.C
		}

		select {
		case e := <-g.expCh:
			heap.Push(&h, e)
		case <-timerC:
			for h.Len() > 0 && !h[0].when.After(time.Now()) {
				e := heap.Pop(&h).(expiryEntry)
				if err := g.blocker.Unblock(e.ip); err == nil {
					g.removeBlocked(e.ip)
					if g.cfg.OnAudit != nil {
						g.cfg.OnAudit("unblock", e.ip, "block duration expired", g.cfg.BlockDuration.String())
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (g *Guard) Run(ctx context.Context, linesCh <-chan string, logf func(string, ...interface{})) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go g.runExpiryLoop(ctx)

	ticker := time.NewTicker(g.cfg.Window)
	defer ticker.Stop()

	for {
		select {
		case line := <-linesCh:
			g.Evaluate(line)

		case <-ticker.C:
			blocked := g.Tick(ctx)
			now := time.Now()
			for _, c := range blocked {
				logf("[%s] + %s blocked (%s)\n", now.Format("15:04:05"), c.IP, c.Why)
			}

		case <-ctx.Done():
			return
		}
	}
}
