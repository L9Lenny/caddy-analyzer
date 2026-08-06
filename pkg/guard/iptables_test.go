package guard

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
-A CADDY_ANALYZER -s 192.168.1.100/32 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"192.168.1.100"},
		},
		{
			name: "multiple blocks with CIDR",
			output: `-A CADDY_ANALYZER -s 10.0.0.1/32 -m comment --comment "caddy-analyzer" -j DROP
-A CADDY_ANALYZER -s 172.16.0.0/12 -m comment --comment "caddy-analyzer" -j DROP
-A CADDY_ANALYZER -s 8.8.8.8/32 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"10.0.0.1", "172.16.0.0", "8.8.8.8"},
		},
		{
			name: "skip 0.0.0.0 source",
			output: `-A CADDY_ANALYZER -s 0.0.0.0/0 -m comment --comment "caddy-analyzer" -j DROP
-A CADDY_ANALYZER -s 1.2.3.4/32 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"1.2.3.4"},
		},
		{
			name: "skip :: source",
			output: `-A CADDY_ANALYZER -s ::/0 -m comment --comment "caddy-analyzer" -j DROP
-A CADDY_ANALYZER -s fe80::1/128 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"fe80::1"},
		},
		{
			name: "skip non-DROP rules",
			output: `-A CADDY_ANALYZER -s 0.0.0.0/0 -j ACCEPT
-A CADDY_ANALYZER -s 10.0.0.5/32 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"10.0.0.5"},
		},
		{
			name: "skip rules without ownership comment",
			output: `-A INPUT -s 1.1.1.1/32 -j DROP
-A CADDY_ANALYZER -s 10.0.0.2/32 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"10.0.0.2"},
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
			output: `-A CADDY_ANALYZER -m comment --comment "caddy-analyzer" -j DROP
-A CADDY_ANALYZER -s 10.0.0.2/32 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"10.0.0.2"},
		},
		{
			name: "IPv6 block strips brackets",
			output: `-A CADDY_ANALYZER -s 2001:db8::1/128 -m comment --comment "caddy-analyzer" -j DROP
-A CADDY_ANALYZER -s [::1]/128 -m comment --comment "caddy-analyzer" -j DROP`,
			want: []string{"2001:db8::1", "::1"},
		},
		{
			name: "DROP in unrelated comment not matched",
			output: `-A INPUT -s 10.0.0.1/32 -j ACCEPT -m comment --comment "DROP test"
-A CADDY_ANALYZER -s 10.0.0.2/32 -m comment --comment "caddy-analyzer" -j DROP`,
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

func TestBinForIP(t *testing.T) {
	if got := BinForIP("1.2.3.4"); got != "iptables" {
		t.Errorf("IPv4: got %s, want iptables", got)
	}
	if got := BinForIP("2001:db8::1"); got != "ip6tables" {
		t.Errorf("IPv6: got %s, want ip6tables", got)
	}
	if got := BinForIP("not-an-ip"); got != "iptables" {
		t.Errorf("invalid IP: got %s, want iptables", got)
	}
}
