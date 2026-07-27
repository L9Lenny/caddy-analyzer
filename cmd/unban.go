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
	out, err := exec.Command("iptables", "-L", "INPUT", "-n", "--line-numbers").Output()
	if err != nil {
		return nil, fmt.Errorf("iptables: %w", err)
	}

	var ips []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "DROP") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		source := fields[3]
		if source == "0.0.0.0/0" || source == "::/0" {
			continue
		}
		ip := source
		if idx := strings.Index(ip, "/"); idx > 0 {
			ip = ip[:idx]
		}
		ips = append(ips, ip)
	}
	return ips, nil
}
