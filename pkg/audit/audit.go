package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"sync"
	"time"
)

type Entry struct {
	Timestamp time.Time `json:"ts"`
	Action    string    `json:"action"`
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Duration  string    `json:"duration"`
	User      string    `json:"user"`
}

type Logger struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	user string
}

func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	u := ""
	if curr, err := user.Current(); err == nil {
		u = curr.Username
	}
	return &Logger{f: f, enc: json.NewEncoder(f), user: u}, nil
}

func (l *Logger) Log(action, ip, reason, duration string) {
	if l == nil {
		return
	}
	entry := Entry{
		Timestamp: time.Now().UTC(),
		Action:    action,
		IP:        ip,
		Reason:    reason,
		Duration:  duration,
		User:      l.user,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(entry)
}

func (l *Logger) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}
