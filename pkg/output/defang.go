package output

import "strings"

// Defang replaces dots with [.] and URL schemes with hxxp[s]:// in a string
// to prevent accidental clicks in shared reports.
// Example: http://185.220.101.42 → hxxp://185[.]220[.]101[.]42
func Defang(s string) string {
	s = strings.ReplaceAll(s, "https://", "hxxps://")
	s = strings.ReplaceAll(s, "http://", "hxxp://")
	return strings.ReplaceAll(s, ".", "[.]")
}

// DefangIP is a convenience wrapper for defanging a bare IP address.
func DefangIP(ip string) string {
	return Defang(ip)
}
