package guard

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeBlocker struct {
	mu       sync.Mutex
	blocked  map[string]bool
	blockErr error
}

func newFakeBlocker() *fakeBlocker {
	return &fakeBlocker{blocked: make(map[string]bool)}
}

func (f *fakeBlocker) Block(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blockErr != nil {
		return f.blockErr
	}
	f.blocked[ip] = true
	return nil
}

func (f *fakeBlocker) Unblock(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blocked, ip)
	return nil
}

func newTestGuard() *Guard {
	return New(Config{
		Limit:         100,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration:  0,
		IPValidator:   func(string) error { return nil },
	})
}

func TestGuardConcurrent(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	var wg sync.WaitGroup
	const workers = 100
	const opsPerWorker = 200

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				ip := fmt.Sprintf("10.0.%d.%d", id, i%256)
				switch i % 4 {
				case 0:
					g.setBlocked(ip)
				case 1:
					g.IsBlocked(ip)
				case 2:
					g.removeBlocked(ip)
				case 3:
					g.Count()
				}
			}
		}(w)
	}

	wg.Wait()

	g2 := newTestGuard()
	g2.SetBlocker(newFakeBlocker())
	g2.setBlocked("192.168.1.1")
	g2.setBlocked("192.168.1.2")
	if !g2.IsBlocked("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be blocked")
	}
	g2.removeBlocked("192.168.1.1")
	if g2.IsBlocked("192.168.1.1") {
		t.Error("expected 192.168.1.1 to be unblocked")
	}
	if g2.Count() != 1 {
		t.Errorf("expected count=1, got %d", g2.Count())
	}
}

func TestGuardEvaluateSkipsBlockedIP(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())
	g.setBlocked("1.2.3.4")

	before := g.Engine().Count()
	g.Evaluate(caddyLine("1.2.3.4", "/test", "GET", 200))
	after := g.Engine().Count()

	if after != before {
		t.Errorf("blocked IP should be skipped, engine count changed from %d to %d", before, after)
	}
}

func caddyLine(ip, uri, method string, status int) string {
	return fmt.Sprintf(`{"level":"info","ts":1785148418.35,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"%s","proto":"HTTP/1.1","method":"%s","uri":"%s","headers":{"User-Agent":["Mozilla/5.0"]}},"status":%d}`, ip, method, uri, status)
}

func TestGuardEvaluateProcessesValidLine(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	g.Evaluate(caddyLine("1.2.3.4", "/test", "GET", 200))

	if g.Engine().Count() != 1 {
		t.Errorf("expected engine count=1, got %d", g.Engine().Count())
	}
}

func TestGuardEvaluateSkipsInvalidJSON(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	g.Evaluate(`not json at all`)

	if g.Engine().Count() != 0 {
		t.Errorf("expected engine count=0 for invalid JSON, got %d", g.Engine().Count())
	}
}

func TestGuardTickBlocksOnAuthThreshold(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.AuthLimit = 2

	for i := 0; i < 3; i++ {
		g.Evaluate(caddyLine("1.2.3.4", "/login", "POST", 401))
	}

	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("expected 1 candidate blocked, got %d", len(blocked))
	}
	if blocked[0].IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", blocked[0].IP)
	}
	if !g.IsBlocked("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be in blocked map")
	}
	if !fb.blocked["1.2.3.4"] {
		t.Error("expected fake blocker to have blocked 1.2.3.4")
	}
}

func TestGuardTickBlocksOnNotFoundThreshold(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.NotFoundLimit = 3

	for i := 0; i < 4; i++ {
		g.Evaluate(caddyLine("5.6.7.8", "/nonexistent", "GET", 404))
	}

	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("expected 1 candidate blocked, got %d", len(blocked))
	}
	if blocked[0].IP != "5.6.7.8" {
		t.Errorf("expected IP 5.6.7.8, got %s", blocked[0].IP)
	}
}

func TestGuardTickBlocksOnRequestLimit(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 5

	for i := 0; i < 6; i++ {
		g.Evaluate(caddyLine("9.10.11.12", "/api", "GET", 200))
	}

	blocked := g.Tick(context.Background())

	if len(blocked) != 1 {
		t.Fatalf("expected 1 candidate blocked, got %d", len(blocked))
	}
	if blocked[0].IP != "9.10.11.12" {
		t.Errorf("expected IP 9.10.11.12, got %s", blocked[0].IP)
	}
}

func TestGuardTickSkipsAlreadyBlocked(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 3

	for i := 0; i < 5; i++ {
		g.Evaluate(caddyLine("1.1.1.1", "/api", "GET", 200))
	}
	g.setBlocked("1.1.1.1")

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Errorf("expected 0 candidates (already blocked), got %d", len(blocked))
	}
}

func TestGuardTickResetsDetectorAndEngine(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	for i := 0; i < 3; i++ {
		g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))
	}
	if g.Engine().Count() != 3 {
		t.Fatalf("expected count=3 before tick, got %d", g.Engine().Count())
	}

	g.Tick(context.Background())

	if g.Engine().Count() != 0 {
		t.Errorf("expected count=0 after tick (reset), got %d", g.Engine().Count())
	}
}

func TestGuardBlockFailsRemovesFromBlocked(t *testing.T) {
	fb := newFakeBlocker()
	fb.blockErr = fmt.Errorf("iptables failed")
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 1

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Errorf("expected 0 blocked (iptables failed), got %d", len(blocked))
	}
	if g.IsBlocked("1.2.3.4") {
		t.Error("IP should not be in blocked map when iptables fails")
	}
}

func TestGuardAuditOnBlock(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 1

	var audits []struct {
		action, ip, reason, duration string
	}
	g.cfg.OnAudit = func(action, ip, reason, duration string) {
		audits = append(audits, struct {
			action, ip, reason, duration string
		}{action, ip, reason, duration})
	}
	g.cfg.BlockDuration = 0

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))
	g.Tick(context.Background())

	if len(audits) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audits))
	}
	if audits[0].action != "block" || audits[0].ip != "1.2.3.4" {
		t.Errorf("unexpected audit: %+v", audits[0])
	}
	if audits[0].duration != "permanent" {
		t.Errorf("expected permanent duration, got %s", audits[0].duration)
	}
}

func TestGuardNeverBlockAllowlist(t *testing.T) {
	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		NeverBlock:    []string{"10.0.0.0/8", "192.168.1.1"},
	}
	g := New(cfg)
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("10.0.0.5", "/api", "GET", 200))
	g.Tick(context.Background())

	if g.IsBlocked("10.0.0.5") {
		t.Error("10.0.0.5 should not be blocked (in 10.0.0.0/8 allowlist)")
	}
	if fb.blocked["10.0.0.5"] {
		t.Error("iptables should not have been called for allowlisted IP")
	}
}

func TestGuardNeverBlockSingleIP(t *testing.T) {
	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		NeverBlock:    []string{"192.168.1.1"},
	}
	g := New(cfg)
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("192.168.1.1", "/api", "GET", 200))
	g.Tick(context.Background())

	if g.IsBlocked("192.168.1.1") {
		t.Error("192.168.1.1 should not be blocked (in allowlist)")
	}
}

func TestGuardNeverBlockDoesNotAffectOthers(t *testing.T) {
	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		NeverBlock:    []string{"10.0.0.0/8"},
	}
	g := New(cfg)
	g.SetBlocker(fb)

	g.Evaluate(caddyLine("8.8.8.8", "/api", "GET", 200))
	g.Tick(context.Background())

	if !g.IsBlocked("8.8.8.8") {
		t.Error("8.8.8.8 should be blocked (not in allowlist)")
	}
}

func TestGuardTickRejectsInvalidIP(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.Limit = 1
	g.cfg.IPValidator = func(ip string) error { return fmt.Errorf("invalid") }

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))

	blocked := g.Tick(context.Background())

	if len(blocked) != 0 {
		t.Errorf("expected 0 blocked (IP rejected), got %d", len(blocked))
	}
}

func TestGuardEvaluateDetectsSQLi(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	g.Evaluate(caddyLine("1.2.3.4", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "GET", 200))

	ipStats := g.Detector().IPStats()
	stats := ipStats["1.2.3.4"]
	if stats == nil {
		t.Fatal("expected IP stats for 1.2.3.4")
	}
	if stats.Total != 1 {
		t.Errorf("expected 1 total detection, got %d", stats.Total)
	}
}

func TestGuardRunStopsOnContextCancel(t *testing.T) {
	g := newTestGuard()
	g.SetBlocker(newFakeBlocker())

	ctx, cancel := context.WithCancel(context.Background())
	linesCh := make(chan string, 1)

	done := make(chan struct{})
	go func() {
		g.Run(ctx, linesCh, func(string, ...interface{}) {})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}

func TestGuardExpiryLoopUnblocksExpiredIPs(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.BlockDuration = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go g.runExpiryLoop(ctx)

	g.setBlocked("1.2.3.4")
	fb.blocked["1.2.3.4"] = true

	select {
	case g.expCh <- expiryEntry{ip: "1.2.3.4", when: time.Now().Add(20 * time.Millisecond)}:
	case <-time.After(time.Second):
		t.Fatal("timed out sending to expCh")
	}

	time.Sleep(100 * time.Millisecond)

	if g.IsBlocked("1.2.3.4") {
		t.Error("expected IP to be unblocked after expiry")
	}
	if fb.blocked["1.2.3.4"] {
		t.Error("expected fake blocker to have unblocked IP")
	}
}

func TestGuardExpiryLoopStopsOnContextCancel(t *testing.T) {
	fb := newFakeBlocker()
	g := newTestGuard()
	g.SetBlocker(fb)
	g.cfg.BlockDuration = 1 * time.Hour

	ctx, cancel := context.WithCancel(context.Background())

	g.setBlocked("1.2.3.4")
	fb.blocked["1.2.3.4"] = true
	go g.runExpiryLoop(ctx)

	select {
	case g.expCh <- expiryEntry{ip: "1.2.3.4", when: time.Now().Add(1 * time.Hour)}:
	case <-time.After(time.Second):
		t.Fatal("timed out sending to expCh")
	}

	cancel()
	time.Sleep(50 * time.Millisecond)

	if !g.IsBlocked("1.2.3.4") {
		t.Error("IP should still be blocked — expiry loop should exit without unblocking on context cancel")
	}
	if _, ok := fb.blocked["1.2.3.4"]; !ok {
		t.Error("fake blocker should not have been unblocked on context cancel")
	}
}

