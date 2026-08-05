package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Source    string `json:"source,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

func DefaultConfigPath() (string, error) {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		xdg = filepath.Join(home, ".config")
	}
	dir := filepath.Join(xdg, "caddy-analyzer")
	return filepath.Join(dir, "config.json"), nil
}

func LocalConfigPath() string {
	return "caddy-analyzer.json"
}

func Load() (*Config, string, error) {
	paths := []string{LocalConfigPath()}

	defPath, err := DefaultConfigPath()
	if err == nil {
		paths = append(paths, defPath)
	}

	for _, p := range paths {
		cfg, err := loadFile(p)
		if err == nil {
			return cfg, p, nil
		}
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: config %s: %v\n", p, err)
		}
	}

	return nil, "", nil
}

func CreateDefault(path string) error {
	cfg := Config{Source: "/var/log/caddy/access.log"}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func loadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	return &cfg, nil
}
