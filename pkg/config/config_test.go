package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions not supported on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "config.json")

	if err := CreateDefault(path); err != nil {
		t.Fatalf("CreateDefault failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected perm 0600, got %v", info.Mode().Perm())
	}

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Source != "/var/log/caddy/access.log" {
		t.Errorf("expected source /var/log/caddy/access.log, got %q", cfg.Source)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := loadFile("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestLoadFileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := loadFile(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestLoadReturnsNilWhenNoConfig(t *testing.T) {
	dir := t.TempDir()
	localPath := filepath.Join(dir, "caddy-analyzer.json")
	defPath := filepath.Join(dir, "config", "config.json")

	origLocal := LocalConfigPath()
	defer func() { _ = os.Symlink(origLocal, origLocal) }()
	_ = localPath
	_ = defPath

	cfg, p, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when no files exist, got %+v", cfg)
	}
	if p != "" {
		t.Errorf("expected empty path, got %q", p)
	}
}

func TestLoadLocalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-analyzer.json")
	data := `{"source": "/custom/path.log"}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Source != "/custom/path.log" {
		t.Errorf("expected /custom/path.log, got %q", cfg.Source)
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path, err := DefaultConfigPath()
	if err != nil {
		t.Fatalf("DefaultConfigPath failed: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
}

func TestLocalConfigPath(t *testing.T) {
	if LocalConfigPath() != "caddy-analyzer.json" {
		t.Error("expected caddy-analyzer.json")
	}
}
