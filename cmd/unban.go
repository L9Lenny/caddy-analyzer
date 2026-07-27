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
	Short: "Rimuove IP dal firewall",
	Long: `Rimuove uno o più IP dal firewall (iptables).

Esempi:
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
	unbanCmd.Flags().BoolVarP(&unbanAll, "all", "A", false, "Sblocca tutti gli IP bloccati")
	unbanCmd.Flags().BoolVarP(&unbanList, "list", "l", false, "Mostra IP attualmente bloccati")
	rootCmd.AddCommand(unbanCmd)
}

func runUnban(cmd *cobra.Command, args []string) error {
	if unbanList {
		return listBlocked()
	}
	if unbanAll {
		return unblockAll()
	}
	if len(args) == 0 {
		return fmt.Errorf("specifica almeno un IP da sbloccare, oppure --all")
	}
	return unblockIPs(args)
}

func unblockIPs(ips []string) error {
	for _, ip := range ips {
		cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
		} else {
			fmt.Printf("  ✓ %s sbloccato\n", ip)
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
		fmt.Println("Nessun IP bloccato.")
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
		fmt.Println("Nessun IP bloccato.")
		return nil
	}
	fmt.Println("IP bloccati:")
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
		if strings.Contains(line, "DROP") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "-s" && i+1 < len(fields) {
					ip := fields[i+1]
					if idx := strings.Index(ip, "/"); idx > 0 {
						ip = ip[:idx]
					}
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, nil
}
