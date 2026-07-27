package analysis

import (
	"regexp"
	"strings"

	"github.com/lenny/caddy-analyzer/pkg/types"
)

type DetectionType string

const (
	DetSQLInjection  DetectionType = "sql_injection"
	DetPathTraversal DetectionType = "path_traversal"
	DetScanner       DetectionType = "scanner"
	DetXSS           DetectionType = "xss"
	DetBruteForce    DetectionType = "brute_force"
	DetCredScan      DetectionType = "credential_scanning"
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

	add(`(?i)(\bUNION\b.*\bSELECT\b|SELECT\b.*\bFROM\b|OR\s+1\s*=\s*1|'.*--|\bDROP\b.*\bTABLE|information_schema|pg_sleep|exec\s*\(.*xp_)`, DetSQLInjection, "SQL injection attempt")
	add(`(?i)(%00|\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd|/proc/self|/windows/win\.ini|php://filter|file:///|expect://)`, DetPathTraversal, "Path traversal / LFI attempt")
	add(`(?i)(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=|alert\s*\(|%3Cscript|%3Csvg|prompt\s*\()`, DetXSS, "XSS attempt")

	scannerUAs := []string{
		"sqlmap", "nikto", "dirbuster", "gobuster", "wfuzz", "nmap",
		"zap", "burp suite", "acunetix", "netsparker", "arachni",
		"masscan", "hydra", "medusa", "openvas", "nessus",
		"python-requests", "python-urllib", "go-http-client",
		"curl", "wget", "libwww-perl", "scrapy",
	}
	scannerPat := "(?i)(" + strings.Join(scannerUAs, "|") + ")"
	add(scannerPat, DetScanner, "Scanner / automated tool detected")

	return p
}

func (d *Detector) Detect(entry *types.LogEntry) *Detection {
	uri := entry.URI
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
				URI:    uri,
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
