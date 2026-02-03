package server

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func FuzzAuthorizedKeysParse(f *testing.F) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	f.Add(`permitconnect="user@127.0.0.1:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@[::1]:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="*@127.0.0.1/8:*" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user+host+22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	f.Add(`permitconnect="user@host:22",permitopen="localhost:8080",from="10.0.0.0/8" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",start-time="20060102150405Z",expiry-time="26660102150405Z" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`permitconnect="user@host:22",no-pty,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)
	f.Add(`restrict,permitconnect="user@host:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`)

	f.Add("#define HOST 127.0.0.1\npermitconnect=\"user@HOST:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("#define A A\nA")
	f.Add("#define A B\n#define B A\nA")

	f.Add("permitconnect=\"user@host:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	f.Add("permitconnect=\"user@host:22\" \\\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	f.Add("# This is a comment\npermitconnect=\"user@host:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("permitconnect=\"user@host:22\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # inline comment")
	f.Add("# only comments")

	f.Add("")
	f.Add("\n\n\n")
	f.Add("\r\n\r\n")

	f.Add(`permitconnect=""`)
	f.Add(`permitconnect="@:22"`)
	f.Add(`permitconnect="user@:22"`)
	f.Add(`permitconnect="@host:22"`)
	f.Add(`permitconnect="user@host:"`)

	f.Add(`start-time="invalid"`)
	f.Add(`start-time="99999999"`)
	f.Add(`expiry-time="invalid"`)
	f.Add(`expiry-time="99999999"`)
	f.Add(`from="*" permitconnect="user@host:22"`)

	f.Add("permitconnect=\"user@host:22\" not-a-valid-key")

	f.Add(strings.Repeat("A", 1024))
	f.Add(strings.Repeat("A", 128))

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
			}
		}
	})
}
