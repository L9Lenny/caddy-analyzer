package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/L9Lenny/caddy-analyzer/pkg/audit"
)

var blockAuditLog string

var blockCmd = &cobra.Command{
	Use:   "block <ip> [ip...]",
	Short: "Block IP via iptables",
	Long: `Block one or more IPs via iptables.

Examples:
  caddy-analyze block 10.0.0.1
  caddy-analyze block 192.168.1.1 10.0.0.2
`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("requires root: run with sudo")
		}
		var al *audit.Logger
		if blockAuditLog != "" {
			var err error
			al, err = audit.New(blockAuditLog)
			if err != nil {
				return fmt.Errorf("audit log: %w", err)
			}
			defer al.Close()
		}
		for _, ip := range args {
			if err := validateIP(ip); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
				continue
			}
			c := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", ip, err)
			} else {
				fmt.Printf("  ✓ %s blocked\n", ip)
				if al != nil {
					al.Log("block", ip, "manual block", "permanent")
				}
			}
		}
		return nil
	},
}

func init() {
	blockCmd.Flags().StringVarP(&blockAuditLog, "audit-log", "", "/var/log/caddy-analyzer-audit.jsonl", "Audit log path (empty to disable)")
	rootCmd.AddCommand(blockCmd)
}
