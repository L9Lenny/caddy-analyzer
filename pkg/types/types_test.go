package types

import "testing"

func TestEffectiveClientIP_NotTrusted(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "8.8.8.8",
		ForwardedFor: []string{"1.1.1.1"},
		RealIP:       "9.9.9.9",
	}
	if got := e.EffectiveClientIP(false); got != "8.8.8.8" {
		t.Fatalf("not trusted: want RemoteIP 8.8.8.8, got %s", got)
	}
}

// TestEffectiveClientIP_LastHopSelected: the rightmost public hop is the one
// added by the trusted reverse proxy; the leftmost is client-controlled and
// must NOT be returned or an attacker can spoof it (rate-limit evasion,
// third-party ban DoS).
func TestEffectiveClientIP_LastHopSelected(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1", // Caddy's direct peer (the reverse proxy)
		ForwardedFor: []string{"8.8.8.8", "203.0.113.5"},
	}
	// 203.0.113.5 is the rightmost public hop → the trusted one.
	if got := e.EffectiveClientIP(true); got != "203.0.113.5" {
		t.Fatalf("trusted: want last public hop 203.0.113.5, got %s", got)
	}
}

// TestEffectiveClientIP_SpoofedFirstHopIgnored: regression test for the
// XFF spoofing bug — the first hop is client-controlled and must be ignored.
func TestEffectiveClientIP_SpoofedFirstHopIgnored(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1",
		ForwardedFor: []string{"8.8.8.8", "203.0.113.5"}, // 8.8.8.8 spoofed by client
	}
	if got := e.EffectiveClientIP(true); got == "8.8.8.8" {
		t.Fatalf("spoofed first hop must NOT be returned (got %s) — this reopens CVE-style XFF spoofing", got)
	}
}

func TestEffectiveClientIP_FallsBackToRealIP(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1",
		ForwardedFor: nil,
		RealIP:       "198.51.100.7",
	}
	if got := e.EffectiveClientIP(true); got != "198.51.100.7" {
		t.Fatalf("want RealIP 198.51.100.7, got %s", got)
	}
}

func TestEffectiveClientIP_FallsBackToRemoteIP(t *testing.T) {
	e := LogEntry{
		RemoteIP:     "10.0.0.1",
		ForwardedFor: []string{"127.0.0.1", "10.0.0.2"}, // all private
		RealIP:       "127.0.0.1",
	}
	if got := e.EffectiveClientIP(true); got != "10.0.0.1" {
		t.Fatalf("want RemoteIP 10.0.0.1, got %s", got)
	}
}

func TestEffectiveClientIP_Empty(t *testing.T) {
	e := LogEntry{}
	if got := e.EffectiveClientIP(true); got != "" {
		t.Fatalf("want empty, got %s", got)
	}
}
