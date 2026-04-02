package netutil

import "testing"

func TestNormalizeTransportBypassList(t *testing.T) {
	rules, err := NormalizeTransportBypassList([]string{" localhost ", "127.*", "LOCALHOST", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NormalizeTransportBypassList() error = %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("len(rules) = %d, want 3", len(rules))
	}
	if rules[0] != "localhost" {
		t.Fatalf("rules[0] = %q, want localhost", rules[0])
	}
}

func TestNormalizeTransportBypassList_InvalidRule(t *testing.T) {
	_, err := NormalizeTransportBypassList([]string{"localhost:8080"})
	if err == nil {
		t.Fatal("expected error for host:port rule")
	}
}

func TestParseTransportBypassEnv(t *testing.T) {
	rules := ParseTransportBypassEnv("localhost; 127.*\n192.168.*\r\n;10.*")
	if len(rules) != 4 {
		t.Fatalf("len(rules) = %d, want 4", len(rules))
	}
}

func TestTransportBypassMatcher_MatchHost(t *testing.T) {
	matcher, err := CompileTransportBypassMatcher([]string{"localhost", ".example.com", "127.*", "10.0.0.0/8", "::1"})
	if err != nil {
		t.Fatalf("CompileTransportBypassMatcher() error = %v", err)
	}
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "exact host", host: "LOCALHOST", want: true},
		{name: "domain suffix exact root", host: "example.com", want: true},
		{name: "domain suffix subdomain", host: "api.example.com", want: true},
		{name: "ipv4 wildcard", host: "127.0.0.1", want: true},
		{name: "cidr", host: "10.2.3.4", want: true},
		{name: "ipv6 exact", host: "::1", want: true},
		{name: "host with brackets", host: "[::1]", want: true},
		{name: "miss", host: "8.8.8.8", want: false},
	}
	for _, tt := range tests {
		if got := matcher.MatchHost(tt.host); got != tt.want {
			t.Fatalf("%s: MatchHost(%q) = %v, want %v", tt.name, tt.host, got, tt.want)
		}
	}
}
