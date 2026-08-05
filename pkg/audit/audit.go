package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"sync"
	"time"
)

// maxAuditSize is the size in bytes at which the audit log is rotated.
// One block/unblock entry is ~200 bytes, so 10 MiB holds ~50k entries —
// enough for post-incident forensics without unbounded growth.
const maxAuditSize = 10 << 20

// flushInterval bounds how long an audit entry can sit in the OS buffer
// before being flushed to disk. A periodic flusher trades a little throughput
// for durability so a crash does not lose recent security-relevant entries.
const flushInterval = 1 * time.Second

type Entry struct {
	Timestamp time.Time `json:"ts"`
	Action    string    `json:"action"`
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Duration  string    `json:"duration"`
	User      string    `json:"user"`
}

type Logger struct {
	mu     sync.Mutex
	f      *os.File
	enc    *json.Encoder
	path   string
	user   string
	onErr  func(error)
	stopCh chan struct{}
	once   sync.Once
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
	l := &Logger{
		f:      f,
		enc:    json.NewEncoder(f),
		path:   path,
		user:   u,
		stopCh: make(chan struct{}),
	}
	go l.flushLoop()
	return l, nil
}

// SetErrorHandler registers a callback invoked when writing an audit entry
// fails (e.g. disk full), so failures are no longer silently dropped.
func (l *Logger) SetErrorHandler(fn func(error)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onErr = fn
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
	if l.f == nil {
		l.reopenLocked()
	}
	if l.enc == nil {
		return
	}
	if err := l.enc.Encode(entry); err != nil {
		if l.onErr != nil {
			l.onErr(fmt.Errorf("audit log write: %w", err))
		}
		l.f = nil
		l.enc = nil
		return
	}
	l.maybeRotateLocked()
}

// reopenLocked attempts to reopen the audit log file after a rotation
// failure or other error left l.f nil. Caller must hold l.mu.
func (l *Logger) reopenLocked() {
	nf, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		if l.onErr != nil {
			l.onErr(fmt.Errorf("reopen audit log: %w", err))
		}
		return
	}
	l.f = nf
	l.enc = json.NewEncoder(nf)
}

// maxRotatedFiles is the number of rotated copies to keep (.1, .2, …).
const maxRotatedFiles = 5

// maybeRotateLocked rotates the audit log if it exceeds maxAuditSize.
// Caller must hold l.mu.
func (l *Logger) maybeRotateLocked() {
	if l.path == "" {
		return
	}
	fi, err := l.f.Stat()
	if err != nil {
		return
	}
	if fi.Size() < maxAuditSize {
		return
	}
	// Rotate: close current, shift .N-1 -> .N, … , .1 -> .2, rename
	// current to .1, open fresh. This preserves history instead of
	// overwriting .1 on every rotation.
	_ = l.f.Close()
	for i := maxRotatedFiles; i > 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i-1), fmt.Sprintf("%s.%d", l.path, i))
	}
	_ = os.Rename(l.path, l.path+".1")
	nf, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		l.f = nil
		l.enc = nil
		if l.onErr != nil {
			l.onErr(fmt.Errorf("reopen audit log after rotate: %w", err))
		}
		return
	}
	l.f = nf
	l.enc = json.NewEncoder(nf)
}

// flushLoop periodically fsyncs the audit file so a crash does not lose the
// most recent security-relevant entries.
func (l *Logger) flushLoop() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.mu.Lock()
			if l.f != nil {
				_ = l.f.Sync()
			}
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		close(l.stopCh)
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Sync()
		_ = l.f.Close()
		l.f = nil
		l.enc = nil
	}
	return nil
}
