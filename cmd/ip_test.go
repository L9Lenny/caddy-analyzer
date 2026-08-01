package cmd

import "testing"

func TestValidateIP(t *testing.T) {
	tests := []struct {
		ip      string
		wantErr bool
	}{
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"::1", false},
		{"2001:db8::1", false},
		{"fe80::1", false},
		{"10.0.0.0/8", false},
		{"192.168.1.0/24", false},
		{"172.16.0.0/12", false},
		{"::1/128", false},
		{"2001:db8::/32", false},
		{"", true},
		{"localhost", true},
		{"not an ip", true},
		{"--wait", true},
		{"-j", true},
		{"-j DROP", true},
		{"-s 0.0.0.0/0", true},
		{"--list", true},
		{"-A INPUT", true},
		{"192.168.1.1; rm -rf /", true},
		{"192.168.1.1 -j ACCEPT", true},
		{"999.999.999.999", true},
		{"192.168.1", true},
		{"192.168.1.1.1", true},
		{"::g", true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			err := validateIP(tt.ip)
			if tt.wantErr && err == nil {
				t.Errorf("validateIP(%q) expected error, got nil", tt.ip)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateIP(%q) expected no error, got %v", tt.ip, err)
			}
		})
	}
}
