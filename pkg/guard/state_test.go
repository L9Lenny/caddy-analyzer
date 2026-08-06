package guard

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStateSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 1 * time.Hour,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
		Blocker:       fb,
	}
	g := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))
	g.Tick(ctx)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("state file not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("state file is empty")
	}

	g2 := New(cfg)
	if !g2.IsBlocked("1.2.3.4") {
		t.Error("expected IP to be restored from state file on restart")
	}
}

func TestStateCleanupExpiredOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	fb := newFakeBlocker()
	fb.blocked["1.2.3.4"] = true

	sf := newStateFile(path)
	pastExpiry := time.Now().Add(-1 * time.Hour)
	_ = sf.saveEntries([]stateEntry{
		{IP: "1.2.3.4", When: pastExpiry},
	})

	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 1 * time.Hour,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
		Blocker:       fb,
	}
	g := New(cfg)

	if g.IsBlocked("1.2.3.4") {
		t.Error("expired IP should have been cleaned up on load")
	}
	fb.mu.Lock()
	_, unblocked := fb.blocked["1.2.3.4"]
	fb.mu.Unlock()
	if unblocked {
		t.Error("fake blocker should have had Unblock called for expired IP")
	}
}

func TestStateNoStateFile(t *testing.T) {
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		StatePath:     "",
	}
	g := New(cfg)
	g.SetBlocker(newFakeBlocker())

	if g.Count() != 0 {
		t.Errorf("expected 0 blocked, got %d", g.Count())
	}
}

func TestStateFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions not supported on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
		Blocker:       fb,
	}
	g := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g.Evaluate(caddyLine("1.2.3.4", "/api", "GET", 200))
	g.Tick(ctx)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %v", info.Mode().Perm())
	}
}

func TestStateRestoresPermanentBlockOnRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	sf := newStateFile(path)
	_ = sf.saveEntries([]stateEntry{
		{IP: "1.2.3.4", When: time.Time{}},
	})

	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 1 * time.Hour,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
		Blocker:       fb,
	}
	g := New(cfg)

	if !g.IsBlocked("1.2.3.4") {
		t.Error("permanent block must survive a restart even with a finite BlockDuration")
	}
}

func TestStateRestoresTemporaryAsPermanentInPermanentMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	sf := newStateFile(path)
	_ = sf.saveEntries([]stateEntry{
		{IP: "1.2.3.4", When: time.Now().Add(1 * time.Hour)},
	})

	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 0,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
		Blocker:       fb,
	}
	g := New(cfg)

	if !g.IsBlocked("1.2.3.4") {
		t.Error("previous temporary block should be preserved when restarting in permanent mode")
	}
}

func TestStateLoadReportsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	if err := os.WriteFile(path, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 1 * time.Hour,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
	}
	var reported error
	cfg.OnError = func(err error) { reported = err }
	fb := newFakeBlocker()
	cfg.Blocker = fb
	g := New(cfg)

	if reported == nil {
		t.Error("expected corrupt state file to be reported via OnError")
	}
	if g.Count() != 0 {
		t.Errorf("expected 0 blocked with corrupt state, got %d", g.Count())
	}
}

func TestAddPermanentBlockToState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	if err := AddPermanentBlockToState(path, "1.2.3.4"); err != nil {
		t.Fatalf("AddPermanentBlockToState: %v", err)
	}
	if err := AddPermanentBlockToState(path, "5.6.7.8"); err != nil {
		t.Fatalf("AddPermanentBlockToState second: %v", err)
	}

	sf := newStateFile(path)
	entries, err := sf.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Idempotent: adding the same IP again should not duplicate.
	if err := AddPermanentBlockToState(path, "1.2.3.4"); err != nil {
		t.Fatalf("AddPermanentBlockToState duplicate: %v", err)
	}
	entries, _ = sf.load()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after duplicate add, got %d", len(entries))
	}
}

func TestRemoveBlockFromState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	_ = AddPermanentBlockToState(path, "1.2.3.4")
	_ = AddPermanentBlockToState(path, "5.6.7.8")

	if err := RemoveBlockFromState(path, "1.2.3.4"); err != nil {
		t.Fatalf("RemoveBlockFromState: %v", err)
	}

	sf := newStateFile(path)
	entries, _ := sf.load()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after remove, got %d", len(entries))
	}
	if entries[0].IP != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8 to remain, got %s", entries[0].IP)
	}
}

func TestRunFlushesStateOnShutdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.json")

	fb := newFakeBlocker()
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration: 1 * time.Hour,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
		Blocker:       fb,
	}
	g := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	linesCh := make(chan string, 1)

	done := make(chan struct{})
	go func() {
		g.Run(ctx, linesCh, func(string, ...interface{}) {})
		close(done)
	}()

	// Block an IP with an expiry so runExpiryLoop has pending state. Feed the
	// line through Run's own pipeline: calling Tick() directly here would race
	// with Run's ticker (which fires every Window), so wait for Run's tick to
	// process the candidate instead.
	linesCh <- caddyLine("1.2.3.4", "/api", "GET", 200)
	deadline := time.Now().Add(2 * time.Second)
	for !g.IsBlocked("1.2.3.4") {
		if time.Now().After(deadline) {
			t.Fatal("IP 1.2.3.4 was not blocked within 2s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cancel and wait for Run to return — it should flush state.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancel")
	}

	// Verify state file was written (Run waited for expiry loop's save).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("state file not written on shutdown: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("state file is empty after shutdown")
	}
}
