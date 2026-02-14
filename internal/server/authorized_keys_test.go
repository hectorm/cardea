package server

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func FuzzAuthorizedKeysParse(f *testing.F) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	// permitconnect formats
	f.Add(`permitconnect="user@127.0.0.1:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@[::1]:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="*@127.0.0.1/8:*" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user+host+22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	// Option combinations
	f.Add(`permitconnect="user@host:22",permitopen="localhost:8080",permitlisten="localhost:9090" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitsocketopen="/var/run/docker.sock",permitsocketlisten="/tmp/agent.sock" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",environment="FOO=bar" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",from="10.0.0.0/8" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",start-time="20060102150405Z",expiry-time="26660102150405Z" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",time-window="dow:mon-fri hour:8-17 tz:Europe/Madrid" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",time-window="dow:mon-thu hour:8-17 tz:Europe/Madrid",time-window="dow:fri hour:8-14 tz:Europe/Madrid" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",time-window="hour:8-13/15-17 tz:Europe/Madrid" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",command="nologin" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",no-pty,no-port-forwarding,no-socket-forwarding,no-recording ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`restrict,permitconnect="user@host:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	// Preprocessor features
	f.Add("#define HOST 127.0.0.1\npermitconnect=\"user@HOST:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("#define A A\nA")
	f.Add("#define A B\n#define B A\nA")
	f.Add("permitconnect=\"user@host:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("permitconnect=\"user@host:22\" \\\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("# This is a comment\npermitconnect=\"user@host:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("permitconnect=\"user@host:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # inline comment")
	f.Add("# only comments")

	// Empty and whitespace
	f.Add("")
	f.Add("\n\n\n")
	f.Add("\r\n\r\n")

	// Malformed permitconnect
	f.Add(`permitconnect=""`)
	f.Add(`permitconnect="@:22"`)
	f.Add(`permitconnect="user@:22"`)
	f.Add(`permitconnect="@host:22"`)
	f.Add(`permitconnect="user@host:"`)

	// Malformed permitopen and permitlisten
	f.Add(`permitconnect="user@host:22",permitopen="" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitopen="noport" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitopen=":80" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitopen="host:" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitlisten="" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitlisten="noport" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitlisten=":8080" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitlisten="host:" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	// Malformed permitsocketopen and permitsocketlisten
	f.Add(`permitconnect="user@host:22",permitsocketopen="" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",permitsocketlisten="" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	// Malformed environment
	f.Add(`permitconnect="user@host:22",environment="" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",environment="NOEQUALS" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",environment="=value" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",environment="BAD-NAME=value" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",environment="+" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",environment="-" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	// Malformed start-time and expiry-time
	f.Add(`start-time="invalid"`)
	f.Add(`start-time="99999999"`)
	f.Add(`expiry-time="invalid"`)
	f.Add(`expiry-time="99999999"`)

	// Malformed time-window
	f.Add(`time-window="",permitconnect="user@host:22"`)
	f.Add(`time-window="invalid",permitconnect="user@host:22"`)
	f.Add(`time-window="tz:Invalid/Zone",permitconnect="user@host:22"`)
	f.Add(`time-window="dow:fri-mon",permitconnect="user@host:22"`)
	f.Add(`time-window="hour:25",permitconnect="user@host:22"`)

	// Malformed command
	f.Add(`permitconnect="user@host:22",command="" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	// Malformed key
	f.Add("permitconnect=\"user@host:22\" not-a-valid-key")

	// Oversized and binary input
	f.Add(strings.Repeat("A", 128))
	f.Add(strings.Repeat("A", 1024))
	f.Add("\x00\x00\x00")
	f.Add("permitconnect=\"\x00user@host:22\"")
	f.Add("permitconnect=\"user\x00@host:22\"")

	f.Fuzz(func(t *testing.T, content string) {
		result, err := parseAuthorizedKeys([]byte(content))
		if err != nil {
			return
		}

		for key, optsList := range result {
			if key == "" {
				t.Error("empty map key")
			}

			for _, opts := range optsList {
				if len(opts.PermitConnects) == 0 {
					t.Error("PermitConnects is empty")
				}
				for _, pc := range opts.PermitConnects {
					if pc.User == "" || pc.Host == "" || pc.Port == "" {
						t.Errorf("PermitConnect has empty field: %+v", pc)
					}
				}

				for _, po := range opts.PermitOpens {
					if po.Host == "" || po.Port == "" {
						t.Errorf("PermitOpen has empty field: %+v", po)
					}
				}

				for _, pl := range opts.PermitListens {
					if pl.Host == "" || pl.Port == "" {
						t.Errorf("PermitListen has empty field: %+v", pl)
					}
				}

				for _, pso := range opts.PermitSocketOpens {
					if pso.Path == "" {
						t.Errorf("PermitSocketOpen has empty path: %+v", pso)
					}
				}

				for _, psl := range opts.PermitSocketListens {
					if psl.Path == "" {
						t.Errorf("PermitSocketListen has empty path: %+v", psl)
					}
				}

				for _, env := range opts.Environments {
					if env.Name == "" {
						t.Errorf("Environment has empty name: %+v", env)
					}
				}
			}
		}
	})
}
