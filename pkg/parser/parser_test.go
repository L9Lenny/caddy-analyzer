package parser

import (
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
