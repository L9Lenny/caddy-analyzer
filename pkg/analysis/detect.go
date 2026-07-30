package analysis

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

type DetectionType string

const (
	DetSQLInjection  DetectionType = "sql_injection"
	DetPathTraversal DetectionType = "path_traversal"
	DetScanner       DetectionType = "scanner"
	DetXSS           DetectionType = "xss"
	DetBruteForce    DetectionType = "brute_force"
	DetCredScan      DetectionType = "credential_scanning"
	DetRCE           DetectionType = "rce"
	DetSensitiveFile DetectionType = "sensitive_file_probe"
	DetLog4j         DetectionType = "log4j_jndi"
	DetAdminProbe    DetectionType = "admin_probe"
	DetWPProbe       DetectionType = "wordpress_probe"
	DetCGIProbe      DetectionType = "cgi_probe"
	DetSSRF          DetectionType = "ssrf"
	DetSSTI          DetectionType = "ssti"
	DetNoSQLi        DetectionType = "nosql_injection"
	DetGraphQL       DetectionType = "graphql_introspection"
	DetLFIWrapper    DetectionType = "lfi_wrapper_abuse"
)

type Detection struct {
	Type   DetectionType `json:"type"`
	IP     string        `json:"ip"`
	URI    string        `json:"uri"`
	Status int           `json:"status"`
	Desc   string        `json:"description"`
}

type IPDetStats struct {
	AuthFailures int
	NotFound     int
	Total        int
}

type Detector struct {
	patterns []struct {
		re    *regexp.Regexp
		dtype DetectionType
		desc  string
	}
	ipStats map[string]*IPDetStats
}

func NewDetector() *Detector {
	return &Detector{
		patterns: compilePatterns(),
		ipStats:  make(map[string]*IPDetStats),
	}
}

func compilePatterns() []struct {
	re    *regexp.Regexp
	dtype DetectionType
	desc  string
} {
	var p []struct {
		re    *regexp.Regexp
		dtype DetectionType
		desc  string
	}

	add := func(pattern string, dtype DetectionType, desc string) {
		p = append(p, struct {
			re    *regexp.Regexp
			dtype DetectionType
			desc  string
		}{regexp.MustCompile(pattern), dtype, desc})
	}

	add(`(?i)(\${jndi:|class\.module\.classLoader|\$\{lower:jndi|\$\${::-j})`, DetLog4j, "Log4j / JNDI injection attempt")
	add(`(?i)(/bin/sh|/bin/bash|powershell|cmd\.exe|whoami|cat\s+/etc|nslookup\s|sleep\s+\d|ping\s+-n\s+\d|/tmp/|/dev/tcp/|/dev/udp/)`, DetRCE, "Remote Code Execution (RCE) attempt")
	add(`(?i)(\$ne|\$gt|\$gte|\$lt|\$regex|\$where|\$exists|\$nin|%24ne|%24gt|%24regex|%24where)`, DetNoSQLi, "NoSQL injection attempt")
	add(`(?i)(__schema|__type|__typename|IntrospectionQuery)`, DetGraphQL, "GraphQL introspection probe")
	add(`(?i)(\{\{.*\}\}|\$\{.*\}.*|<%.*%>|#\{.*\}|__class__|__mro__|__subclasses__|__globals__|freemarker|nunjucks|range\.constructor)`, DetSSTI, "Server-side template injection (SSTI) attempt")
	add(`(?i)(phar://|zip://|data://text/plain|expect://|php://input|compress\.zlib|compress\.bzip2)`, DetLFIWrapper, "LFI wrapper / PHP stream abuse")
	add(`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|0x7f000001|2130706433|gopher://|dict://)`, DetSSRF, "SSRF attempt (cloud metadata / protocol smuggling)")
	add(`(?i)(\bUNION\b.*\bSELECT\b|SELECT\b.*\bFROM\b|OR\s+1\s*=\s*1|'.*--|\bDROP\b.*\bTABLE|information_schema|pg_sleep|exec\s*\(.*xp_)`, DetSQLInjection, "SQL injection attempt")
	add(`(?i)(\.\./|\.\.%00|%00\.\.|/etc/passwd|/etc/shadow|/proc/self|/proc/self/environ|/windows/win\.ini|php://filter|file:///|expect://)`, DetPathTraversal, "Path traversal / LFI attempt")
	add(`(?i)(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|alert\s*\(|%3Cscript|%3Csvg|prompt\s*\()`, DetXSS, "XSS attempt")
	add(`(?i)(\.env|\.git/config|wp-config\.php|id_rsa|\.aws/credentials|\.htaccess|docker-compose\.yml|\.gitignore|composer\.json|package\.json)`, DetSensitiveFile, "Sensitive file discovery probe")
	add(`(?i)(/phpmyadmin|/wp-login\.php|/actuator/|/console/|/admin/config|/solr/|/api/v1/debug|/h2-console|/heapdump|/jolokia)`, DetAdminProbe, "Admin interface probe")
	add(`(?i)(/wp-content/plugins/|/wp-content/themes/|/wp-json/wp/v2/|/wp-includes/|/xmlrpc\.php)`, DetWPProbe, "WordPress vulnerability scanner probe")
	add(`(?i)(/cgi-bin/)`, DetCGIProbe, "CGI-bin probe / exploitation attempt")

	scannerUAs := []string{
		"sqlmap", "nikto", "dirbuster", "gobuster", "wfuzz", "nmap",
		"zap", "burp suite", "acunetix", "netsparker", "arachni",
		"masscan", "hydra", "medusa", "openvas", "nessus",
		"python-requests", "python-urllib", "go-http-client",
		"curl", "wget", "libwww-perl", "scrapy",
		"httpx", "nuclei", "ffuf", "katana", "jaeles", "arjun",
		"dalfox", "xsstrike", "commix", "tplmap", "nosqlmap",
	}
	scannerPat := "(?i)(" + strings.Join(scannerUAs, "|") + ")"
	add(scannerPat, DetScanner, "Scanner / automated tool detected")

	return p
}

var rawPatterns []struct {
	re    *regexp.Regexp
	dtype DetectionType
	desc  string
}

func init() {
	addRaw := func(pattern string, dtype DetectionType, desc string) {
		rawPatterns = append(rawPatterns, struct {
			re    *regexp.Regexp
			dtype DetectionType
			desc  string
		}{regexp.MustCompile(pattern), dtype, desc})
	}
	addRaw(`(?i)(%2e%2e%2f|%2e%2e/|\.%2e/|%2e\.%2f|%252e%252e%252f|\.\.%252f|%c0%ae%c0%ae%c0%af|%c0%ae%c0%ae/)`, DetPathTraversal, "Path traversal / LFI attempt (encoded)")
	addRaw(`(?i)(wp_filemanager\.php)`, DetSensitiveFile, "Sensitive file discovery probe (WordPress plugin)")
	addRaw(`(?i)(127\.0\.0\.1|localhost)(:|\b)`, DetSSRF, "SSRF attempt (internal host probe)")
}

func (d *Detector) Detect(entry *types.LogEntry) *Detection {
	rawURI := entry.URI
	uri := rawURI
	if unescaped, err := url.QueryUnescape(uri); err == nil {
		uri = unescaped
	}
	ua := entry.UserAgent

	stats := d.ipStats[entry.RemoteIP]
	if stats == nil {
		stats = &IPDetStats{}
		d.ipStats[entry.RemoteIP] = stats
	}
	stats.Total++

	if entry.Status == 401 || entry.Status == 403 {
		stats.AuthFailures++
	}
	if entry.Status == 404 {
		stats.NotFound++
	}

	for _, p := range d.patterns {
		if p.re.MatchString(uri) || p.re.MatchString(ua) {
			return &Detection{
				Type:   p.dtype,
				IP:     entry.RemoteIP,
				URI:    entry.URI,
				Status: entry.Status,
				Desc:   p.desc,
			}
		}
	}

	for _, p := range rawPatterns {
		if p.re.MatchString(rawURI) || p.re.MatchString(ua) {
			return &Detection{
				Type:   p.dtype,
				IP:     entry.RemoteIP,
				URI:    entry.URI,
				Status: entry.Status,
				Desc:   p.desc,
			}
		}
	}

	return nil
}

func (d *Detector) IPStats() map[string]*IPDetStats {
	return d.ipStats
}

func (d *Detector) IsSuspicious(ip string, authThreshold, notFoundThreshold, totalThreshold int) bool {
	stats := d.ipStats[ip]
	if stats == nil {
		return false
	}
	if stats.AuthFailures >= authThreshold {
		return true
	}
	if stats.NotFound >= notFoundThreshold {
		return true
	}
	if stats.Total >= totalThreshold {
		return true
	}
	return false
}
