package authkeys

import (
	"strings"
	"testing"
)

func TestAuthkeysMatchers(t *testing.T) {
	t.Run("match_permit_connect", func(t *testing.T) {
		pattern := PermitConnect{User: "*", Host: "*.example.com", Port: "22-23"}

		t.Run("match", func(t *testing.T) {
			if !MatchPermitConnect(pattern, PermitConnect{User: "alice", Host: "api.example.com", Port: "22"}) {
				t.Error("expected permitconnect pattern to match")
			}
		})

		t.Run("no_match", func(t *testing.T) {
			if MatchPermitConnect(pattern, PermitConnect{User: "alice", Host: "api.example.net", Port: "22"}) {
				t.Error("expected permitconnect pattern not to match")
			}
		})
	})

	t.Run("match_user_pattern", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
			user    string
			want    bool
		}{
			{name: "exact", pattern: "root", user: "root", want: true},
			{name: "wildcard", pattern: "*", user: "root", want: true},
			{name: "empty", pattern: "*", user: "", want: false},
			{name: "too_long", pattern: "*", user: strings.Repeat("a", 256), want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := MatchUserPattern(tt.pattern, tt.user); got != tt.want {
					t.Errorf("MatchUserPattern(%q, %q) = %v, want %v", tt.pattern, tt.user, got, tt.want)
				}
			})
		}
	})

	t.Run("match_host_pattern", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
			host    string
			want    bool
		}{
			{name: "glob_case_insensitive", pattern: "*.Example.com", host: "api.example.com", want: true},
			{name: "cidr", pattern: "10.0.0.0/8", host: "10.1.2.3", want: true},
			{name: "cidr_non_ip", pattern: "10.0.0.0/8", host: "api.example.com", want: false},
			{name: "too_long", pattern: "*", host: strings.Repeat("a", 256), want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := MatchHostPattern(tt.pattern, tt.host); got != tt.want {
					t.Errorf("MatchHostPattern(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
				}
			})
		}
	})

	t.Run("match_port_pattern", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
			port    any
			want    bool
		}{
			{name: "exact", pattern: "22", port: "22", want: true},
			{name: "wildcard", pattern: "*", port: "22", want: true},
			{name: "range", pattern: "1024-2048", port: "2048", want: true},
			{name: "invalid_target", pattern: "*", port: "abc", want: false},
			{name: "out_of_range", pattern: "*", port: "65536", want: false},
			{name: "invalid_range", pattern: "2000-1000", port: "1500", want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := MatchPortPattern(tt.pattern, tt.port); got != tt.want {
					t.Errorf("MatchPortPattern(%q, %v) = %v, want %v", tt.pattern, tt.port, got, tt.want)
				}
			})
		}
	})

	t.Run("match_name_pattern", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
			value   string
			want    bool
		}{
			{name: "exact", pattern: "alice", value: "alice", want: true},
			{name: "glob", pattern: "al*", value: "alice", want: true},
			{name: "slash_rejected", pattern: "*", value: "alice/root", want: false},
			{name: "dot_rejected", pattern: "*", value: ".", want: false},
			{name: "invalid_pattern", pattern: "[", value: "alice", want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := MatchNamePattern(tt.pattern, tt.value); got != tt.want {
					t.Errorf("MatchNamePattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
				}
			})
		}
	})

	t.Run("match_path_pattern", func(t *testing.T) {
		tests := []struct {
			name    string
			pattern string
			value   string
			want    bool
		}{
			{name: "wildcard", pattern: "*", value: "/tmp/agent.sock", want: true},
			{name: "cleaned_match", pattern: "/tmp/*.sock", value: "/tmp/../tmp/agent.sock", want: true},
			{name: "relative_match", pattern: "run/*.sock", value: "run/agent.sock", want: true},
			{name: "abs_rel_mismatch", pattern: "/tmp/*.sock", value: "tmp/agent.sock", want: false},
			{name: "empty_value", pattern: "*", value: "", want: false},
			{name: "invalid_pattern", pattern: "[", value: "/tmp/agent.sock", want: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := MatchPathPattern(tt.pattern, tt.value); got != tt.want {
					t.Errorf("MatchPathPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
				}
			})
		}
	})
}
