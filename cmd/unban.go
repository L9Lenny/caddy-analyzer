package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var unbanCmd = &cobra.Command{
	Use:   "unban <ip> [ip...]",
	Short: "Remove IP from firewall",
	Long: `Remove one or more IPs from the firewall (iptables).

Examples:
  caddy-analyze unban 192.168.1.1
  caddy-analyze unban 10.0.0.1 10.0.0.2
  caddy-analyze unban --all
  caddy-analyze unban --list
`,
	RunE: runUnban,
}

var unbanAll bool
var unbanList bool

func init() {
	unbanCmd.Flags().BoolVarP(&unbanAll, "all", "A", false, "Unblock all currently blocked IPs")
	unbanCmd.Flags().BoolVarP(&unbanList, "list", "l", false, "Show currently blocked IPs")
	rootCmd.AddCommand(unbanCmd)
}

func runUnban(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("requires root: run with sudo")
	}
	if unbanList {
		return listBlocked()
	}
	if unbanAll {
		return unblockAll()
	}
	if len(args) == 0 {
		return fmt.Errorf("specify at least one IP to unblock, or use --all")
	}
	return unblockIPs(args)
}

func unblockIPs(ips []string) error {
	for _, ip := range ips {
		if err := validateIP(ip); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
			continue
		}
		cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
		} else {
			fmt.Printf("  ✓ %s unblocked\n", ip)
		}
	}
	return nil
}

func unblockAll() error {
	ips, err := listBlockedIPs()
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		fmt.Println("No blocked IPs.")
		return nil
	}
	return unblockIPs(ips)
}

func listBlocked() error {
	ips, err := listBlockedIPs()
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		fmt.Println("No blocked IPs.")
		return nil
	}
	fmt.Println("Blocked IPs:")
	for _, ip := range ips {
		fmt.Printf("  %s\n", ip)
	}
	return nil
}

func listBlockedIPs() ([]string, error) {
	out, err := exec.Command("iptables", "-S", "INPUT").Output()
	if err != nil {
		return nil, fmt.Errorf("iptables: %w", err)
	}
	return parseBlockedIPs(string(out)), nil
}

func parseBlockedIPs(output string) []string {
	var ips []string
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "-j DROP") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "-s" && i+1 < len(fields) {
				ip := strings.Split(fields[i+1], "/")[0]
				if ip == "0.0.0.0" || ip == "::" {
					continue
				}
				ips = append(ips, ip)
				break
			}
		}
	}
	return ips
}
