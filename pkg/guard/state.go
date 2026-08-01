package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type stateEntry struct {
	IP   string    `json:"ip"`
	When time.Time `json:"when"`
}

type stateFile struct {
	mu   sync.Mutex
	path string
}

func newStateFile(path string) *stateFile {
	return &stateFile{path: path}
}

func (s *stateFile) load() []stateEntry {
	if s == nil || s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var entries []stateEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	return entries
}

func (s *stateFile) saveEntries(entries []stateEntry) error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return os.WriteFile(s.path, data, 0600)
}
