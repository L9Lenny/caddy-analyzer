package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerWritesEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	al.Log("block", "1.2.3.4", "3 auth failures", "10m")
	al.Log("unblock", "1.2.3.4", "expired", "10m")
	al.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var entries []Entry
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for dec.More() {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Action != "block" || entries[0].IP != "1.2.3.4" {
		t.Errorf("entry 0: action=%s ip=%s", entries[0].Action, entries[0].IP)
	}
	if entries[1].Action != "unblock" || entries[1].IP != "1.2.3.4" {
		t.Errorf("entry 1: action=%s ip=%s", entries[1].Action, entries[1].IP)
	}
	if entries[0].Reason != "3 auth failures" {
		t.Errorf("entry 0 reason: %s", entries[0].Reason)
	}
	if entries[0].Duration != "10m" {
		t.Errorf("entry 0 duration: %s", entries[0].Duration)
	}
	if entries[0].Timestamp.IsZero() {
		t.Error("entry 0 timestamp is zero")
	}
}

func TestLoggerNilSafe(t *testing.T) {
	var l *Logger
	l.Log("block", "1.2.3.4", "test", "1m")
	l.Close()
}

func TestLoggerFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	al, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	al.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %v", info.Mode().Perm())
	}
}
