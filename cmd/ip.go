package cmd

import (
	"fmt"
	"net"
	"strings"
)

func validateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty IP")
	}
	if strings.HasPrefix(ip, "-") {
		return fmt.Errorf("invalid IP %q: looks like a flag", ip)
	}
	if net.ParseIP(ip) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(ip); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP %q", ip)
}
