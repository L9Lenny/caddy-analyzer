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
		BlockDuration:  1 * time.Hour,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
	}
	g := New(cfg)
	g.SetBlocker(fb)

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
	g2.SetBlocker(fb)
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
		BlockDuration:  1 * time.Hour,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
	}
	g := New(cfg)
	g.SetBlocker(fb)

	if g.IsBlocked("1.2.3.4") {
		t.Error("expired IP should have been cleaned up on load")
	}
}

func TestStateNoStateFile(t *testing.T) {
	cfg := Config{
		Limit:         1,
		AuthLimit:     10,
		NotFoundLimit: 50,
		Window:        50 * time.Millisecond,
		BlockDuration:  0,
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
		BlockDuration:  0,
		IPValidator:   func(string) error { return nil },
		StatePath:     path,
	}
	g := New(cfg)
	g.SetBlocker(fb)

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
