package cmd

import (
	"testing"
)

func TestParseBlockedIPs(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []string
	}{
		{
			name: "single IPv4 block",
			output: `-P INPUT ACCEPT
-A INPUT -s 192.168.1.100/32 -j DROP`,
			want: []string{"192.168.1.100"},
		},
		{
			name: "multiple blocks with CIDR",
			output: `-A INPUT -s 10.0.0.1/32 -j DROP
-A INPUT -s 172.16.0.0/12 -j DROP
-A INPUT -s 8.8.8.8/32 -j DROP`,
			want: []string{"10.0.0.1", "172.16.0.0", "8.8.8.8"},
		},
		{
			name: "skip 0.0.0.0 source",
			output: `-A INPUT -s 0.0.0.0/0 -j DROP
-A INPUT -s 1.2.3.4/32 -j DROP`,
			want: []string{"1.2.3.4"},
		},
		{
			name: "skip :: source",
			output: `-A INPUT -s ::/0 -j DROP
-A INPUT -s fe80::1/128 -j DROP`,
			want: []string{"fe80::1"},
		},
		{
			name: "skip non-DROP rules",
			output: `-A INPUT -s 0.0.0.0/0 -j ACCEPT
-A INPUT -s 10.0.0.5/32 -j DROP`,
			want: []string{"10.0.0.5"},
		},
		{
			name:   "empty output",
			output: `-P INPUT ACCEPT`,
			want:   nil,
		},
		{
			name:   "truly empty output",
			output: "",
			want:   nil,
		},
		{
			name: "rule without -s skipped",
			output: `-A INPUT -j DROP
-A INPUT -s 10.0.0.2/32 -j DROP`,
			want: []string{"10.0.0.2"},
		},
		{
			name: "IPv6 block",
			output: `-A INPUT -s 2001:db8::1/128 -j DROP`,
			want: []string{"2001:db8::1"},
		},
		{
			name: "DROP in comment not matched",
			output: `-A INPUT -s 10.0.0.1/32 -j ACCEPT -m comment --comment "DROP test"
-A INPUT -s 10.0.0.2/32 -j DROP`,
			want: []string{"10.0.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBlockedIPs(tt.output)
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d IPs, got %d (%+v)", len(tt.want), len(got), got)
			}
			for i, ip := range got {
				if ip != tt.want[i] {
					t.Errorf("index %d: expected %q, got %q", i, tt.want[i], ip)
				}
			}
		})
	}
}
