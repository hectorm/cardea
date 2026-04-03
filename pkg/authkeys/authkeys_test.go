package authkeys

import (
	"strings"
	"testing"
	"time"
)

func TestAuthkeys(t *testing.T) {
	// See internal/server/server_test.go for full integration tests.
	t.Run("parse_file", func(t *testing.T) {
		aliceKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice"
		bobKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB bob"

		t.Run("simple", func(t *testing.T) {
			content := []byte("permitconnect=\"*@example.com:22\" " + aliceKey + "\n")
			db, warnings, err := ParseFile(content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) != 0 {
				t.Errorf("expected no warnings, got %d", len(warnings))
			}
			if len(db) != 1 {
				t.Errorf("expected 1 key, got %d", len(db))
			}
		})

		t.Run("macros", func(t *testing.T) {
			content := []byte("#define OPTS permitconnect=\"*@example.com:22\"\nOPTS " + aliceKey + "\n")
			db, warnings, err := ParseFile(content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) != 0 {
				t.Errorf("expected no warnings, got %d", len(warnings))
			}
			if len(db) != 1 {
				t.Errorf("expected 1 key, got %d", len(db))
			}
		})

		t.Run("pipe", func(t *testing.T) {
			content := []byte("permitconnect=\"*@example.com:22\" " + aliceKey + " | " + bobKey + "\n")
			db, warnings, err := ParseFile(content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) != 0 {
				t.Errorf("expected no warnings, got %d", len(warnings))
			}
			if len(db) != 2 {
				t.Errorf("expected 2 keys, got %d", len(db))
			}
		})

		t.Run("line_continuation", func(t *testing.T) {
			content := []byte("permitconnect=\"*@example.com:22\" \\\n" + aliceKey + "\n")
			db, warnings, err := ParseFile(content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) != 0 {
				t.Errorf("expected no warnings, got %d", len(warnings))
			}
			if len(db) != 1 {
				t.Errorf("expected 1 key, got %d", len(db))
			}
		})

		t.Run("warnings", func(t *testing.T) {
			content := []byte("permitconnect=\"invalid\" " + aliceKey + "\n")
			db, warnings, err := ParseFile(content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) == 0 {
				t.Error("expected warnings, got none")
			}
			if len(db) != 0 {
				t.Errorf("expected 0 keys, got %d", len(db))
			}
		})

		t.Run("empty", func(t *testing.T) {
			db, warnings, err := ParseFile([]byte{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) != 0 {
				t.Errorf("expected no warnings, got %d", len(warnings))
			}
			if len(db) != 0 {
				t.Errorf("expected 0 keys, got %d", len(db))
			}
		})
	})

	t.Run("parse_line", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			line := []byte(`permitconnect="*@example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			opts, pubKey, err := ParseLine(line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pubKey == nil {
				t.Fatal("expected public key, got nil")
			}
			if len(opts.PermitConnects) != 1 {
				t.Errorf("expected 1 PermitConnect, got %d", len(opts.PermitConnects))
			}
			if opts.Comment != "alice" {
				t.Errorf("Comment = %q, want %q", opts.Comment, "alice")
			}
		})

		t.Run("missing_options", func(t *testing.T) {
			line := []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			_, _, err := ParseLine(line)
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), "missing options") {
				t.Errorf("expected error containing %q, got %q", "missing options", err.Error())
			}
		})
	})

	t.Run("parse_key", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			line := []byte(`permitconnect="*@example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			pubKey, comment, opts, err := ParseKey(line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pubKey == nil {
				t.Fatal("expected public key, got nil")
			}
			if comment != "alice" {
				t.Errorf("comment = %q, want %q", comment, "alice")
			}
			if len(opts) == 0 {
				t.Error("expected options, got none")
			}
		})

		t.Run("bare_key", func(t *testing.T) {
			line := []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			pubKey, _, opts, err := ParseKey(line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pubKey == nil {
				t.Fatal("expected public key, got nil")
			}
			if len(opts) != 0 {
				t.Errorf("expected no options, got %d", len(opts))
			}
		})

		t.Run("invalid", func(t *testing.T) {
			_, _, _, err := ParseKey([]byte("not-a-valid-key"))
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	})

	t.Run("parse_options", func(t *testing.T) {
		t.Run("missing_permitconnect", func(t *testing.T) {
			_, err := ParseOptions([]string{`command="ls"`})
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), "permitconnect") {
				t.Errorf("expected error about permitconnect, got %q", err.Error())
			}
		})

		t.Run("default_permit_opens", func(t *testing.T) {
			opts, err := ParseOptions([]string{`permitconnect="*@example.com:22"`})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(opts.PermitOpens) != 3 {
				t.Errorf("expected 3 default PermitOpens, got %d", len(opts.PermitOpens))
			}
		})

		t.Run("malformed_option", func(t *testing.T) {
			_, err := ParseOptions([]string{`command=unquoted`})
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), "malformed") {
				t.Errorf("expected error containing %q, got %q", "malformed", err.Error())
			}
		})
	})

	t.Run("split_option", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name      string
				input     string
				wantName  string
				wantValue string
			}{
				{name: "no_value", input: "restrict", wantName: "restrict"},
				{name: "empty_value", input: `command=""`, wantName: "command", wantValue: ""},
				{name: "simple_value", input: `command="ls"`, wantName: "command", wantValue: "ls"},
				{name: "escaped_quote", input: `command="echo \"hello\""`, wantName: "command", wantValue: `echo "hello"`},
				{name: "backslash_no_quote", input: `command="C:\\path"`, wantName: "command", wantValue: `C:\\path`},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					name, value, ok := SplitOption(tt.input)
					if !ok {
						t.Fatal("expected ok, got false")
					}
					if name != tt.wantName {
						t.Errorf("name = %q, want %q", name, tt.wantName)
					}
					if value != tt.wantValue {
						t.Errorf("value = %q, want %q", value, tt.wantValue)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
			}{
				{name: "unquoted_value", input: "command=ls"},
				{name: "missing_close_quote", input: `command="ls`},
				{name: "garbage_after_quote", input: `command="ls"extra`},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, _, ok := SplitOption(tt.input)
					if ok {
						t.Error("expected ok = false")
					}
				})
			}
		})
	})

	t.Run("quote_option_value", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
			want  string
		}{
			{name: "simple", input: "hello", want: `"hello"`},
			{name: "empty", input: "", want: `""`},
			{name: "with_quote", input: `say "hi"`, want: `"say \"hi\""`},
			{name: "with_backslash", input: `C:\path`, want: `"C:\path"`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := QuoteOptionValue(tt.input)
				if got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			})
		}
	})

	t.Run("parse_permit_connect", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name     string
				input    string
				wantUser string
				wantHost string
				wantPort string
			}{
				{name: "at_with_port", input: "*@example.com:22", wantUser: "*", wantHost: "example.com", wantPort: "22"},
				{name: "at_without_port", input: "root@example.com", wantUser: "root", wantHost: "example.com", wantPort: "22"},
				{name: "at_ipv6_with_port", input: "root@[2001:db8::1]:22", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "at_ipv6_without_port", input: "root@[2001:db8::1]", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "at_ipv4", input: "root@192.168.1.1", wantUser: "root", wantHost: "192.168.1.1", wantPort: "22"},
				{name: "plus_with_port", input: "root+example.com+2222", wantUser: "root", wantHost: "example.com", wantPort: "2222"},
				{name: "plus_without_port", input: "root+example.com", wantUser: "root", wantHost: "example.com", wantPort: "22"},
				{name: "plus_ipv4", input: "root+192.168.1.1", wantUser: "root", wantHost: "192.168.1.1", wantPort: "22"},
				{name: "plus_ipv6", input: "root+[2001:db8::1]+22", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "cidr", input: "*@192.168.0.0/16:22", wantUser: "*", wantHost: "192.168.0.0/16", wantPort: "22"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					pc, err := ParsePermitConnect(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if pc.User != tt.wantUser {
						t.Errorf("User = %q, want %q", pc.User, tt.wantUser)
					}
					if pc.Host != tt.wantHost {
						t.Errorf("Host = %q, want %q", pc.Host, tt.wantHost)
					}
					if pc.Port != tt.wantPort {
						t.Errorf("Port = %q, want %q", pc.Port, tt.wantPort)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
			}{
				{name: "empty", input: ""},
				{name: "no_user", input: "example.com:22"},
				{name: "too_long", input: "*@" + strings.Repeat("a", MaxPermitConnectLength) + ":22"},
				{name: "at_empty_user", input: "@example.com:22"},
				{name: "at_empty_host", input: "root@:22"},
				{name: "plus_empty_user", input: "+example.com"},
				{name: "plus_empty_host", input: "root+"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParsePermitConnect(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
					}
				})
			}
		})
	})

	t.Run("parse_permit_tcp", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name     string
				input    string
				wantHost string
				wantPort string
			}{
				{name: "host_port", input: "localhost:8080", wantHost: "localhost", wantPort: "8080"},
				{name: "wildcard", input: "*:443", wantHost: "*", wantPort: "443"},
				{name: "ipv6", input: "[::1]:22", wantHost: "::1", wantPort: "22"},
				{name: "port_range", input: "*:1-65535", wantHost: "*", wantPort: "1-65535"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					pt, err := ParsePermitTCP(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if pt.Host != tt.wantHost {
						t.Errorf("Host = %q, want %q", pt.Host, tt.wantHost)
					}
					if pt.Port != tt.wantPort {
						t.Errorf("Port = %q, want %q", pt.Port, tt.wantPort)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "empty", input: "", errSS: "empty"},
				{name: "no_port", input: "localhost", errSS: "expected"},
				{name: "too_long", input: strings.Repeat("a", MaxPermitTCPLength+1) + ":22", errSS: "maximum length"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParsePermitTCP(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})

	t.Run("parse_permit_socket", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name     string
				input    string
				wantPath string
			}{
				{name: "wildcard", input: "*", wantPath: "*"},
				{name: "absolute_path", input: "/tmp/test.sock", wantPath: "/tmp/test.sock"},
				{name: "path_cleaned", input: "/tmp/../tmp/test.sock", wantPath: "/tmp/test.sock"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					ps, err := ParsePermitSocket(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if ps.Path != tt.wantPath {
						t.Errorf("Path = %q, want %q", ps.Path, tt.wantPath)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "empty", input: "", errSS: "empty"},
				{name: "too_long", input: "/" + strings.Repeat("a", MaxPermitSocketLength), errSS: "maximum length"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParsePermitSocket(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})

	t.Run("parse_environment", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name      string
				input     string
				wantSign  string
				wantName  string
				wantValue string
			}{
				{name: "key_value", input: "FOO=bar", wantName: "FOO", wantValue: "bar"},
				{name: "empty_value", input: "FOO=", wantName: "FOO", wantValue: ""},
				{name: "underscore_name", input: "MY_VAR=1", wantName: "MY_VAR", wantValue: "1"},
				{name: "allow_pattern", input: "+TERM*", wantSign: "+", wantName: "TERM*"},
				{name: "deny_pattern", input: "-SECRET*", wantSign: "-", wantName: "SECRET*"},
				{name: "question_mark_pattern", input: "+VAR?", wantSign: "+", wantName: "VAR?"},
				{name: "bracket_pattern", input: "+VAR[AB]", wantSign: "+", wantName: "VAR[AB]"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					env, err := ParseEnvironment(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if env.Sign != tt.wantSign {
						t.Errorf("Sign = %q, want %q", env.Sign, tt.wantSign)
					}
					if env.Name != tt.wantName {
						t.Errorf("Name = %q, want %q", env.Name, tt.wantName)
					}
					if env.Value != tt.wantValue {
						t.Errorf("Value = %q, want %q", env.Value, tt.wantValue)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "no_equals", input: "FOO", errSS: "expected NAME=value"},
				{name: "empty_name", input: "=bar", errSS: "expected NAME=value"},
				{name: "disallowed_char_in_name", input: "FOO-BAR=baz", errSS: "disallowed"},
				{name: "empty_allow_pattern", input: "+", errSS: "empty pattern"},
				{name: "empty_deny_pattern", input: "-", errSS: "empty pattern"},
				{name: "disallowed_char_in_pattern", input: "+FOO/BAR", errSS: "disallowed"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParseEnvironment(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})

	t.Run("parse_from", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			from, err := ParseFrom("192.168.1.0/24")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if from != "192.168.1.0/24" {
				t.Errorf("got %q, want %q", from, "192.168.1.0/24")
			}
		})

		t.Run("empty", func(t *testing.T) {
			_, err := ParseFrom("")
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	})

	t.Run("parse_timespec", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				want  time.Time
			}{
				{name: "date_only", input: "20250101", want: time.Date(2025, 1, 1, 0, 0, 0, 0, time.Local)},
				{name: "date_time_min", input: "202501011430", want: time.Date(2025, 1, 1, 14, 30, 0, 0, time.Local)},
				{name: "date_time_sec", input: "20250101143045", want: time.Date(2025, 1, 1, 14, 30, 45, 0, time.Local)},
				{name: "utc_date", input: "20250101Z", want: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
				{name: "utc_datetime", input: "202501011430Z", want: time.Date(2025, 1, 1, 14, 30, 0, 0, time.UTC)},
				{name: "utc_datetime_sec", input: "20250101143045Z", want: time.Date(2025, 1, 1, 14, 30, 45, 0, time.UTC)},
				{name: "utc_lowercase_z", input: "20250101z", want: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					got, err := ParseTimespec(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if !got.Equal(tt.want) {
						t.Errorf("got %v, want %v", got, tt.want)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "empty", input: "", errSS: "empty"},
				{name: "wrong_length", input: "2025", errSS: "invalid timespec length"},
				{name: "invalid_month_0", input: "20250001", errSS: "invalid month"},
				{name: "invalid_month_13", input: "20251301", errSS: "invalid month"},
				{name: "invalid_day_0", input: "20250100", errSS: "invalid day"},
				{name: "invalid_day_32", input: "20250132", errSS: "invalid day"},
				{name: "invalid_hour", input: "202501012400", errSS: "invalid hour"},
				{name: "invalid_minute", input: "202501011260", errSS: "invalid minute"},
				{name: "invalid_second", input: "20250101120060", errSS: "invalid second"},
				{name: "nonexistent_date", input: "20250230", errSS: "does not exist"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParseTimespec(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})
}
