package output

import "testing"

func TestDefang(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"185.220.101.42", "185[.]220[.]101[.]42"},
		{"https://evil.com", "hxxps://evil[.]com"},
		{"http://169.254.169.254/", "hxxp://169[.]254[.]169[.]254/"},
		{"192.168.1.1:8080", "192[.]168[.]1[.]1:8080"},
		{"", ""},
		{"no-dots-here", "no-dots-here"},
	}
	for _, tt := range tests {
		if got := Defang(tt.in); got != tt.want {
			t.Errorf("Defang(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDefangIP(t *testing.T) {
	got := DefangIP("10.0.0.1")
	want := "10[.]0[.]0[.]1"
	if got != want {
		t.Errorf("DefangIP = %q, want %q", got, want)
	}
}
