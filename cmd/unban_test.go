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
			output: `Chain INPUT (policy ACCEPT 10 packets, 660 bytes)
num   target  prot  opt  source  destination
1   DROP  all  --  192.168.1.100  0.0.0.0/0`,
			want: []string{"192.168.1.100"},
		},
		{
			name: "multiple blocks with CIDR",
			output: `1   DROP  all  --  10.0.0.1  0.0.0.0/0
2   DROP  all  --  172.16.0.0/12  0.0.0.0/0
3   DROP  all  --  8.8.8.8  0.0.0.0/0`,
			want: []string{"10.0.0.1", "172.16.0.0", "8.8.8.8"},
		},
		{
			name: "skip 0.0.0.0/0 source",
			output: `1   DROP  all  --  0.0.0.0/0  0.0.0.0/0
2   DROP  all  --  1.2.3.4  0.0.0.0/0`,
			want: []string{"1.2.3.4"},
		},
		{
			name: "skip ::/0 source",
			output: `1   DROP  all  --  ::/0  ::/0
2   DROP  all  --  fe80::1  ::/0`,
			want: []string{"fe80::1"},
		},
		{
			name: "skip non-DROP rules",
			output: `1   ACCEPT  all  --  0.0.0.0/0  0.0.0.0/0
2   DROP  all  --  10.0.0.5  0.0.0.0/0`,
			want: []string{"10.0.0.5"},
		},
		{
			name: "empty output",
			output: `Chain INPUT (policy ACCEPT)`,
			want:  nil,
		},
		{
			name:   "truly empty output",
			output: "",
			want:   nil,
		},
		{
			name: "malformed lines skipped",
			output: `1   DROP  --  10.0.0.1
2   DROP  all  --  10.0.0.2  0.0.0.0/0`,
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
