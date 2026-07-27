package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/lenny/caddy-analyzer/pkg/config"
)

var flagConfigGlobal bool

var configCmd = &cobra.Command{
	Use:   "config [source]",
	Short: "Set the default log source in the config file",
	Long: `Set the default log source in the config file.

The source is written to the config file so that future runs of
caddy-analyze will use it automatically (unless overridden by
positional args or --file).

Examples:
  caddy-analyze config /var/log/caddy/access.log
  caddy-analyze config docker://my-caddy
  caddy-analyze config k8s://my-pod -n production
  caddy-analyze config --global /var/log/caddy/access.log
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]

		var path string
		if flagConfigGlobal {
			defPath, err := config.DefaultConfigPath()
			if err != nil {
				return fmt.Errorf("config path: %w", err)
			}
			path = defPath
		} else {
			path = config.LocalConfigPath()
		}

		cfg := config.Config{Source: source}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}

		dir := filepath.Dir(path)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}
		}

		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("write config: %w", err)
		}

		fmt.Fprintf(os.Stderr, "config written: %s\n", path)
		fmt.Fprintf(os.Stderr, "  source: %s\n", source)
		return nil
	},
}

func init() {
	configCmd.Flags().BoolVarP(&flagConfigGlobal, "global", "g", false,
		"Write to global config (~/.config/caddy-analyzer/config.json) instead of local")
	rootCmd.AddCommand(configCmd)
}
