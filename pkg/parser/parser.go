package parser

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lenny/caddy-analyzer/pkg/types"
)

type rawLog struct {
	Level   string          `json:"level"`
	TS      json.Number     `json:"ts"`
	Logger  string          `json:"logger"`
	Msg     string          `json:"msg"`
	Request *rawRequest     `json:"request"`
	Status  json.Number     `json:"status"`
	Size    json.Number     `json:"size"`
	Duration json.Number    `json:"duration"`
	Latency  json.Number    `json:"latency"`
	LatencyS json.Number    `json:"latency_seconds"`
}

type rawRequest struct {
	Method     string              `json:"method"`
	URI        string              `json:"uri"`
	Host       string              `json:"host"`
	RemoteAddr string              `json:"remote_addr"`
	RemoteIP   string              `json:"remote_ip"`
	Proto      string              `json:"proto"`
	Headers    map[string][]string `json:"headers"`
}

func Parse(line string) (*types.LogEntry, error) {
	var raw rawLog
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("json parse: %w", err)
	}

	if raw.Msg != "handled request" {
		return nil, nil
	}

	entry := &types.LogEntry{
		Level:  raw.Level,
		Logger: raw.Logger,
		Raw:    line,
	}

	if raw.TS.String() != "" {
		ts, err := raw.TS.Float64()
		if err == nil {
			sec := int64(ts)
			nsec := int64((ts - float64(sec)) * 1e9)
			entry.Timestamp = time.Unix(sec, nsec)
		}
	}

	if raw.Request != nil {
		entry.Method = raw.Request.Method
		entry.URI = raw.Request.URI
		entry.Host = raw.Request.Host
		entry.RemoteAddr = raw.Request.RemoteAddr
		entry.RemoteIP = raw.Request.RemoteIP
		entry.Proto = raw.Request.Proto

		if ua, ok := raw.Request.Headers["User-Agent"]; ok && len(ua) > 0 {
			entry.UserAgent = ua[0]
		}
		if ref, ok := raw.Request.Headers["Referer"]; ok && len(ref) > 0 {
			entry.Referer = ref[0]
		}

		if entry.RemoteIP == "" && entry.RemoteAddr != "" {
			if idx := strings.LastIndex(entry.RemoteAddr, ":"); idx > 0 {
				entry.RemoteIP = entry.RemoteAddr[:idx]
			} else {
				entry.RemoteIP = entry.RemoteAddr
			}
		}
	}

	if raw.Status.String() != "" {
		s, _ := raw.Status.Int64()
		entry.Status = int(s)
	}

	if raw.Size.String() != "" {
		s, _ := raw.Size.Int64()
		entry.Size = s
	}

	entry.Duration = parseDuration(raw.Duration, raw.Latency, raw.LatencyS)

	return entry, nil
}

func parseDuration(values ...json.Number) float64 {
	for _, v := range values {
		if v.String() != "" {
			d, err := v.Float64()
			if err == nil {
				return d
			}
		}
	}
	return 0
}


