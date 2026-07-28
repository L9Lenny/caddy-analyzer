package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/L9Lenny/caddy-analyzer/pkg/analysis"
	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

func TestReportOutputs(t *testing.T) {
	engine := analysis.New(types.Filters{})
	engine.Process(&types.LogEntry{
		Method:     "GET",
		URI:        "/test",
		Host:       "localhost",
		RemoteIP:   "127.0.0.1",
		Status:     200,
		Size:       500,
		Duration:   0.002,
		Proto:      "HTTP/2.0",
		TLSVersion: "TLS 1.3",
	})
	engine.Finalize()

	tests := []struct {
		format   Format
		contains string
	}{
		{FormatTable, "CADDY LOG ANALYSIS REPORT"},
		{FormatJSON, `"total_requests": 1`},
		{FormatCSV, "total_requests,1"},
		{FormatHTML, "<!DOCTYPE html>"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			var buf bytes.Buffer
			report := NewReport(engine, tt.format, 5)
			report.SetWriter(&buf)
			report.Print()

			out := buf.String()
			if !strings.Contains(out, tt.contains) {
				t.Errorf("expected output to contain %q, got:\n%s", tt.contains, out)
			}
		})
	}
}
