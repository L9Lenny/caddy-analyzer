package parser

import (
	"strings"
	"testing"
)

func TestParseValidCaddyLog(t *testing.T) {
	line := `{"level":"info","ts":1785148418.3535235,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"192.168.1.254","remote_port":"59301","client_ip":"192.168.1.254","proto":"HTTP/2.0","method":"GET","host":"lusvecciatore.duckdns.org","uri":"/favicon.svg","headers":{"User-Agent":["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"],"Referer":["https://lusvecciatore.duckdns.org/"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"lusvecciatore.duckdns.org"}},"bytes_read":0,"duration":0.001686612,"size":140,"status":200}`

	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}

	if entry.Method != "GET" {
		t.Errorf("expected GET, got %s", entry.Method)
	}
	if entry.URI != "/favicon.svg" {
		t.Errorf("expected /favicon.svg, got %s", entry.URI)
	}
	if entry.Status != 200 {
		t.Errorf("expected 200, got %d", entry.Status)
	}
	if entry.Size != 140 {
		t.Errorf("expected 140, got %d", entry.Size)
	}
	if entry.TLSVersion != "TLS 1.3" {
		t.Errorf("expected TLS 1.3, got %s", entry.TLSVersion)
	}
	if entry.Browser != "Edge" {
		t.Errorf("expected Edge, got %s", entry.Browser)
	}
	if entry.OS != "Windows" {
		t.Errorf("expected Windows, got %s", entry.OS)
	}
	if entry.RefererDomain != "lusvecciatore.duckdns.org" {
		t.Errorf("expected referer domain, got %s", entry.RefererDomain)
	}
}

func TestParseBotClassifier(t *testing.T) {
	line := `{"level":"info","ts":1785148431.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"74.125.208.73","proto":"HTTP/1.1","method":"GET","uri":"/","headers":{"User-Agent":["Mozilla/5.0 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)"]}},"status":200}`

	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !entry.IsBot {
		t.Errorf("expected bot classification")
	}
	if entry.BotName != "Google-Read-Aloud" {
		t.Errorf("expected BotName Google-Read-Aloud, got %s", entry.BotName)
	}
}

func TestParseMalformedJSON(t *testing.T) {
	line := `D"],"Sec-Fetch-Mode":["no-cors"]}`
	entry, err := Parse(line)
	if err == nil {
		t.Error("expected error on malformed JSON, got nil")
	}
	if entry != nil {
		t.Errorf("expected nil entry on error, got %v", entry)
	}
}

func TestParseNonHandledMsg(t *testing.T) {
	line := `{"level":"info","ts":1785148418,"msg":"started server"}`
	entry, err := Parse(line)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if entry != nil {
		t.Errorf("expected nil entry for non-handled request message")
	}
}

func TestParseRemoteAddrBracketedIPv6(t *testing.T) {
	line := `{"level":"info","ts":1785148418.5,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/","remote_addr":"[::1]:50432","proto":"HTTP/2.0"},"status":200}`
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.RemoteIP != "::1" {
		t.Errorf("expected RemoteIP ::1, got %q", entry.RemoteIP)
	}
}

func TestParseRemoteAddrIPv6NoPort(t *testing.T) {
	line := `{"level":"info","ts":1785148418.5,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/","remote_addr":"2001:db8::1","proto":"HTTP/1.1"},"status":200}`
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.RemoteIP != "2001:db8::1" {
		t.Errorf("expected RemoteIP 2001:db8::1, got %q", entry.RemoteIP)
	}
}

func TestParseRemoteAddrHostPort(t *testing.T) {
	line := `{"level":"info","ts":1785148418.5,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/","remote_addr":"192.168.1.5:54321","proto":"HTTP/1.1"},"status":200}`
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.RemoteIP != "192.168.1.5" {
		t.Errorf("expected RemoteIP 192.168.1.5, got %q", entry.RemoteIP)
	}
}

func TestParseNumericStringFields(t *testing.T) {
	line := `{"level":"info","ts":"1785148418.5","logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/","remote_ip":"1.2.3.4","proto":"HTTP/1.1"},"status":"200","size":"140","duration":"0.001"}`
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.Status != 200 {
		t.Errorf("expected status 200, got %d", entry.Status)
	}
	if entry.Size != 140 {
		t.Errorf("expected size 140, got %d", entry.Size)
	}
	if entry.Duration != 0.001 {
		t.Errorf("expected duration 0.001, got %f", entry.Duration)
	}
}

func TestParseLatencySecondsPreferredOverNanoseconds(t *testing.T) {
	line := `{"level":"info","ts":1785148418.5,"msg":"handled request","request":{"method":"GET","uri":"/","remote_ip":"1.2.3.4","proto":"HTTP/1.1"},"latency":12345678,"latency_seconds":0.012345678,"status":200}`
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.Duration != 0.012345678 {
		t.Errorf("expected duration from latency_seconds 0.012345678, got %f", entry.Duration)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1:80", "192.168.1.1"},
		{"[::1]:50432", "::1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"fe80::1%eth0", "fe80::1%eth0"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := extractIP(tt.addr); got != tt.want {
			t.Errorf("extractIP(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestParseForwardedHeaders(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"10.0.0.1","method":"GET","uri":"/","headers":{"X-Forwarded-For":["203.0.113.5, 70.0.0.1"],"X-Real-Ip":["203.0.113.5"]}},"status":200}`

	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if len(entry.ForwardedFor) != 2 || entry.ForwardedFor[0] != "203.0.113.5" {
		t.Errorf("unexpected XFF: %v", entry.ForwardedFor)
	}
	if entry.RealIP != "203.0.113.5" {
		t.Errorf("unexpected X-Real-IP: %s", entry.RealIP)
	}
	if got := entry.EffectiveClientIP(false); got != "10.0.0.1" {
		t.Errorf("EffectiveClientIP(false) should be RemoteIP, got %s", got)
	}
	if got := entry.EffectiveClientIP(true); got != "70.0.0.1" {
		t.Errorf("EffectiveClientIP(true) should pick last public XFF hop (trusted proxy), got %s", got)
	}
}

func TestEffectiveClientIPSkipsPrivateXFF(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"10.0.0.1","method":"GET","uri":"/","headers":{"X-Forwarded-For":["192.168.1.1, 10.0.0.99"]}},"status":200}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	// All XFF hops are private → fall back to RemoteIP.
	if got := entry.EffectiveClientIP(true); got != "10.0.0.1" {
		t.Errorf("expected fallback to RemoteIP, got %s", got)
	}
}

func TestParseEmptyLine(t *testing.T) {
	entry, err := Parse("")
	if err != nil {
		t.Fatalf("unexpected error on empty line: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected nil entry on empty line, got %v", entry)
	}
}

func TestParseNonJSON(t *testing.T) {
	entry, err := Parse("this is not json")
	if err == nil {
		t.Fatal("expected error on non-JSON input")
	}
	if entry != nil {
		t.Fatalf("expected nil entry on non-JSON, got %v", entry)
	}
}

func TestParseNonCaddyJSON(t *testing.T) {
	entry, err := Parse(`{"level":"info","msg":"some other message"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected nil for non-handled-request msg, got %v", entry)
	}
}

func TestParseMissingFields(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"method":"GET","uri":"/"},"status":200}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if entry.RemoteIP != "" {
		t.Errorf("expected empty RemoteIP, got %s", entry.RemoteIP)
	}
	if entry.Method != "GET" {
		t.Errorf("expected GET, got %s", entry.Method)
	}
}

func TestParseAuthorizationHeader(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"1.2.3.4","method":"GET","uri":"/","headers":{"Authorization":["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"]}},"status":200}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if entry.Authorization == "" {
		t.Fatal("expected non-empty Authorization")
	}
	if len(entry.Authorization) > 500 {
		t.Fatalf("Authorization not truncated: %d chars", len(entry.Authorization))
	}
}

func TestParseAuthorizationTruncation(t *testing.T) {
	longAuth := "Bearer " + strings.Repeat("A", 600)
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"1.2.3.4","method":"GET","uri":"/","headers":{"Authorization":["` + longAuth + `"]}},"status":200}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if len(entry.Authorization) != 500 {
		t.Fatalf("expected 500 chars, got %d", len(entry.Authorization))
	}
}

func TestParseSizeAsString(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"1.2.3.4","method":"GET","uri":"/"},"status":200,"size":"1024"}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if entry.Size != 1024 {
		t.Errorf("expected size 1024, got %d", entry.Size)
	}
}

func TestParseDurationAsString(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"1.2.3.4","method":"GET","uri":"/"},"status":200,"duration":"0.123"}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if entry.Duration != 0.123 {
		t.Errorf("expected duration 0.123, got %f", entry.Duration)
	}
}

func TestParseStatusAsString(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"1.2.3.4","method":"GET","uri":"/"},"status":"404"}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if entry.Status != 404 {
		t.Errorf("expected status 404, got %d", entry.Status)
	}
}

func TestParseRemoteAddrFallback(t *testing.T) {
	line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_addr":"5.6.7.8:12345","method":"GET","uri":"/"},"status":200}`
	entry, err := Parse(line)
	if err != nil || entry == nil {
		t.Fatalf("parse error: %v entry=%v", err, entry)
	}
	if entry.RemoteIP != "5.6.7.8" {
		t.Errorf("expected RemoteIP 5.6.7.8 from RemoteAddr, got %s", entry.RemoteIP)
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"/api/users/123", "/api/users/123"},
		{"/api/users/123?foo=bar", "/api/users/123"},
		{"", ""},
		{"/", "/"},
	}
	for _, tt := range tests {
		line := `{"level":"info","ts":1785148418.35,"msg":"handled request","request":{"remote_ip":"1.2.3.4","method":"GET","uri":"` + tt.uri + `"},"status":200}`
		entry, err := Parse(line)
		if err != nil || entry == nil {
			t.Fatalf("parse error for uri=%q: %v entry=%v", tt.uri, err, entry)
		}
		if got := entry.Path(); got != tt.want {
			t.Errorf("Path() for uri=%q = %q, want %q", tt.uri, got, tt.want)
		}
	}
}
