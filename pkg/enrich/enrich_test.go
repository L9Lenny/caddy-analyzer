package enrich

import (
	"fmt"
	"testing"
	"time"
)

func TestIsPrivateOrLoopback(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		if got := IsPrivateOrLoopback(tt.ip); got != tt.want {
			t.Errorf("IsPrivateOrLoopback(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

type mockEnricher struct {
	rep *Reputation
	err error
}

func (m *mockEnricher) Lookup(ip string) (*Reputation, error) {
	return m.rep, m.err
}

func (m *mockEnricher) Name() string { return "mock" }

func TestCache(t *testing.T) {
	rep := &Reputation{IP: "1.2.3.4", Score: 50, Source: "mock"}
	mock := &mockEnricher{rep: rep}
	cache := NewCache(mock, 1*time.Hour)

	r1, err := cache.Lookup("1.2.3.4")
	if err != nil || r1 == nil || r1.Score != 50 {
		t.Fatalf("first lookup failed: %v %v", r1, err)
	}

	r2, err := cache.Lookup("1.2.3.4")
	if err != nil || r2 == nil || r2.Score != 50 {
		t.Fatalf("cached lookup failed: %v %v", r2, err)
	}
}

func TestCacheExpiry(t *testing.T) {
	rep := &Reputation{IP: "1.2.3.4", Score: 50, Source: "mock"}
	mock := &mockEnricher{rep: rep}
	cache := NewCache(mock, 50*time.Millisecond)

	_, _ = cache.Lookup("1.2.3.4")
	time.Sleep(60 * time.Millisecond)
	_, _ = cache.Lookup("1.2.3.4")

	if len(cache.store) != 1 {
		t.Errorf("expected 1 entry in cache, got %d", len(cache.store))
	}
}

func TestMultiEnricher(t *testing.T) {
	rep := &Reputation{IP: "1.2.3.4", Score: 80}
	m1 := &mockEnricher{rep: rep}
	m2 := &mockEnricher{rep: nil}
	multi := NewMultiEnricher(m1, m2)
	r, err := multi.Lookup("1.2.3.4")
	if err != nil || r == nil || r.Score != 80 {
		t.Fatalf("expected score 80, got %v %v", r, err)
	}
}

func TestMultiEnricherAllFail(t *testing.T) {
	m1 := &mockEnricher{rep: nil}
	m2 := &mockEnricher{rep: nil}
	multi := NewMultiEnricher(m1, m2)
	r, err := multi.Lookup("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil, got %v", r)
	}
}

func TestCacheErrorNotCached(t *testing.T) {
	mock := &mockEnricher{err: fmt.Errorf("api down")}
	cache := NewCache(mock, 1*time.Hour)

	r, err := cache.Lookup("1.2.3.4")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if r != nil {
		t.Fatalf("expected nil rep, got %v", r)
	}

	if len(cache.store) != 0 {
		t.Fatalf("error should not be cached, store has %d entries", len(cache.store))
	}
}

func TestCacheNilRepNotCached(t *testing.T) {
	mock := &mockEnricher{rep: nil}
	cache := NewCache(mock, 1*time.Hour)

	_, _ = cache.Lookup("1.2.3.4")

	if len(cache.store) != 1 {
		t.Fatalf("nil rep should be cached, store has %d entries", len(cache.store))
	}

	r, err := cache.Lookup("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error on cached nil: %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil from cache, got %v", r)
	}
}

func TestMultiEnricherName(t *testing.T) {
	multi := NewMultiEnricher()
	if multi.Name() != "multi" {
		t.Fatalf("expected 'multi', got %q", multi.Name())
	}
}

func TestMultiEnricherEmpty(t *testing.T) {
	multi := NewMultiEnricher()
	r, err := multi.Lookup("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil, got %v", r)
	}
}

func TestCacheName(t *testing.T) {
	mock := &mockEnricher{rep: nil}
	cache := NewCache(mock, 1*time.Hour)
	if cache.Name() != "mock" {
		t.Fatalf("expected 'mock', got %q", cache.Name())
	}
}
