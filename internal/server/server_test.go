package server

import (
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/config"
	"github.com/hectorm/cardea/internal/health"
	"github.com/hectorm/cardea/internal/server/mock"
	"github.com/hectorm/cardea/internal/timewindow"
	"github.com/hectorm/cardea/internal/utils/disk"
)

func setupBastionServer(t testing.TB, authorizedKeysContent, knownHostsContent string, opts ...Option) (*Server, error) {
	t.Helper()

	authorizedKeysFile := filepath.Join(t.TempDir(), "authorized_keys")
	if len(authorizedKeysContent) > 0 {
		if err := os.WriteFile(authorizedKeysFile, []byte(authorizedKeysContent), 0600); err != nil {
			return nil, err
		}
	}

	knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
	if len(knownHostsContent) > 0 {
		if err := os.WriteFile(knownHostsFile, []byte(knownHostsContent), 0600); err != nil {
			return nil, err
		}
	}

	cfg := &config.Config{
		Listen:                   "127.0.0.1:0",
		KeyStrategy:              "file",
		PrivateKeyFile:           filepath.Join(t.TempDir(), "private_key"),
		PrivateKeyPassphrase:     "",
		PrivateKeyPassphraseFile: "",
		AuthorizedKeysFile:       authorizedKeysFile,
		KnownHostsFile:           knownHostsFile,
		UnknownHostsPolicy:       "strict",
		ConnectionsMax:           0,
		RateLimitMax:             0,
		RateLimitTime:            0,
		RecordingsDir:            "",
		RecordingsRetentionTime:  30 * 24 * time.Hour,
		RecordingsMaxDiskUsage:   "0",
	}

	srv, err := NewServer(cfg, opts...)
	if err != nil {
		return nil, err
	}

	if err := srv.Start(); err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Errorf("failed to stop bastion server: %v", err)
		}
	})

	return srv, nil
}

func setupHealthServer(t testing.TB, bastionSrv *Server) (*health.Server, error) {
	t.Helper()

	healthSrv := health.NewServer("127.0.0.1:0", func() bool {
		addr := bastionSrv.Address()
		return addr != nil && addr.Port > 0
	}, bastionSrv.Metrics())

	if err := healthSrv.Start(); err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		if err := healthSrv.Stop(); err != nil {
			t.Errorf("failed to stop health server: %v", err)
		}
	})

	return healthSrv, nil
}

func setupMockServer(t testing.TB, opts ...mock.Option) (*mock.Server, error) {
	t.Helper()

	srv, err := mock.NewServer(opts...)
	if err != nil {
		return nil, err
	}

	if err := srv.Start(); err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Errorf("failed to stop mock server: %v", err)
		}
	})

	return srv, nil
}

func setupClient(t testing.TB) (*ssh.ClientConfig, ssh.PublicKey, error) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	cli := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
		Timeout:         5 * time.Second,
	}

	return cli, signer.PublicKey(), nil
}

func marshalAuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func connectToServer(t testing.TB, cli *ssh.ClientConfig, srv *Server) (*ssh.Client, error) {
	t.Helper()

	conn, err := ssh.Dial("tcp", srv.Address().String(), cli)
	if err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		_ = conn.Close()
	})

	return conn, nil
}

func createShellSession(t testing.TB, conn *ssh.Client) (*ssh.Session, io.WriteCloser, io.Reader, error) {
	t.Helper()

	session, err := conn.NewSession()
	if err != nil {
		return nil, nil, nil, err
	}

	err = session.RequestPty("xterm", 80, 24, ssh.TerminalModes{})
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}

	err = session.Shell()
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}

	t.Cleanup(func() {
		_ = session.Close()
	})

	return session, stdin, stdout, nil
}

func waitFor(timeout time.Duration, check func() error) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	deadline := time.NewTimer(timeout)
	defer func() { ticker.Stop(); deadline.Stop() }()

	var err error
	for {
		select {
		case <-ticker.C:
			if err = check(); err == nil {
				return nil
			}
		case <-deadline.C:
			return err
		}
	}
}

func waitForInitialPrompt(timeout time.Duration, t testing.TB, stdout io.Reader) error {
	t.Helper()

	if prompt, err := readUntil(timeout, stdout, "mock$", 100); err != nil {
		return err
	} else if !strings.Contains(prompt, "mock$") {
		return fmt.Errorf("expected prompt to contain '%s', got: %q", "mock$", prompt)
	}

	return nil
}

func waitForSessionClose(timeout time.Duration, t testing.TB, session *ssh.Session) error {
	t.Helper()

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return err
		}
	case <-time.After(timeout):
		return fmt.Errorf("session did not close within timeout")
	}

	return nil
}

func executeShellCommand(t testing.TB, stdin io.WriteCloser, stdout io.Reader, command string) (string, error) {
	t.Helper()

	_, err := stdin.Write([]byte(command + "\r"))
	if err != nil {
		return "", err
	}

	response, err := readUntil(2*time.Second, stdout, "mock$", 200)
	if err != nil {
		return "", err
	}

	return response, nil
}

func readUntil(timeout time.Duration, r io.Reader, expected string, maxBytes int) (string, error) {
	result := make([]byte, 0, maxBytes)
	buf := make([]byte, 1)
	deadline := time.After(timeout)

	for len(result) < maxBytes {
		readChan := make(chan struct {
			data byte
			err  error
		}, 1)

		go func() {
			n, err := r.Read(buf)
			if n > 0 {
				readChan <- struct {
					data byte
					err  error
				}{buf[0], nil}
			} else {
				readChan <- struct {
					data byte
					err  error
				}{0, err}
			}
		}()

		select {
		case <-deadline:
			return string(result), fmt.Errorf("timeout waiting for %q, got: %q", expected, string(result))
		case readResult := <-readChan:
			if readResult.err != nil {
				return string(result), readResult.err
			}

			result = append(result, readResult.data)
			if strings.Contains(string(result), expected) {
				return string(result), nil
			}
		}
	}

	return string(result), fmt.Errorf("max bytes reached without finding %q", expected)
}

func readGzipFile(path string) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	reader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	return io.ReadAll(reader)
}

func TestBastionSSHServer(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockSrv, err := setupMockServer(t)
	if err != nil {
		t.Errorf("failed to setup mock server: %v", err)
		return
	}
	mockAddr := mockSrv.Address()
	mockAuthorizedKeyStr := marshalAuthorizedKey(mockSrv.Signer().PublicKey())

	t.Run("permitconnect", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			pattern string
			user    string
			ok      bool
		}{
			{pattern: fmt.Sprintf("alice@%s", mockAddr), user: fmt.Sprintf("alice@%s", mockAddr), ok: true},
			{pattern: "alice@127.0.0.1/8:1-65535,alice@[::1/128]:1-65535", user: fmt.Sprintf("alice@%s", mockAddr), ok: true},
			{pattern: "Alice@*:*", user: fmt.Sprintf("alice@%s", mockAddr), ok: false},
			{pattern: "*@LocalHost:*", user: "alice@localhost:22", ok: true},
			{pattern: "*@*:*", user: fmt.Sprintf("alice@%s", mockAddr), ok: true},
			{pattern: "*+*+*", user: fmt.Sprintf("alice@%s", mockAddr), ok: true},
			{pattern: "*-*-*", user: fmt.Sprintf("alice@%s", mockAddr), ok: false},
			{pattern: "al*@*:*", user: fmt.Sprintf("alice@%s", mockAddr), ok: true},
			{pattern: "ali@*:*", user: fmt.Sprintf("alice@%s", mockAddr), ok: false},
			{pattern: "*ce@*:*", user: fmt.Sprintf("alice@%s", mockAddr), ok: true},
			{pattern: "ice@*:*", user: fmt.Sprintf("alice@%s", mockAddr), ok: false},
			{pattern: "*@192.168.1.1:*", user: fmt.Sprintf("alice@%s", mockAddr), ok: false},
			{pattern: "*@*:123", user: fmt.Sprintf("alice@%s", mockAddr), ok: false},
			{pattern: "*@*:*", user: fmt.Sprintf("@%s", mockAddr), ok: false},
			{pattern: "*@*:*", user: "", ok: false},
			{pattern: "*@*:*", user: "@", ok: false},
			{pattern: "*@*:*", user: "@:", ok: false},
			{pattern: "*@*:*", user: "@:0", ok: false},
			{pattern: "*@*:*", user: "@:invalid", ok: false},
			{pattern: "*@*:*", user: "alice@", ok: false},
			{pattern: "*@*:*", user: "alice@:", ok: false},
			{pattern: "*@*:*", user: "alice@:0", ok: false},
			{pattern: "*@*:*", user: "alice@:invalid", ok: false},
			{pattern: "*@*:*", user: "alice@127.0.0.1:", ok: false},
			{pattern: "*@*:*", user: "alice@127.0.0.1:0", ok: true},
			{pattern: "*@*:*", user: "alice@127.0.0.1:invalid", ok: false},
			{pattern: "*@*", user: "alice@127.0.0.1:123", ok: false},
			{pattern: "*+*", user: "alice@127.0.0.1:123", ok: false},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s->%s", tt.user, tt.pattern), func(t *testing.T) {
				cli.User = tt.user

				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="%s" %s`, tt.pattern, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				if tt.ok {
					if _, err := connectToServer(t, cli, bastionSrv); err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}
				} else {
					if _, err := connectToServer(t, cli, bastionSrv); err == nil {
						t.Error("expected connection to fail, but it succeeded")
						return
					}
				}
			})
		}
	})

	t.Run("permitopen", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		targetSrv, err := setupMockServer(t)
		if err != nil {
			t.Errorf("failed to setup target server: %v", err)
			return
		}
		targetAddr := targetSrv.Address()

		tests := []struct {
			pattern string
			target  string
			ok      bool
		}{
			{pattern: targetAddr.String(), target: targetAddr.String(), ok: true},
			{pattern: "127.0.0.1/8:1-65535,[::1/128]:1-65535", target: targetAddr.String(), ok: true},
			{pattern: "*:*", target: targetAddr.String(), ok: true},
			{pattern: "192.168.1.1:*", target: targetAddr.String(), ok: false},
			{pattern: "*:123", target: targetAddr.String(), ok: false},
			{pattern: "*:*", target: "", ok: false},
			{pattern: "*:*", target: ":", ok: false},
			{pattern: "*:*", target: ":0", ok: true},
			{pattern: "*:*", target: ":invalid", ok: false},
			{pattern: "*:*", target: "127.0.0.1", ok: false},
			{pattern: "*:*", target: "127.0.0.1:", ok: false},
			{pattern: "*:*", target: "127.0.0.1:0", ok: true},
			{pattern: "*:*", target: "127.0.0.1:invalid", ok: false},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s->%s", tt.target, tt.pattern), func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@%s",permitopen="%s" %s`, mockAddr, tt.pattern, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				bastionConn, err := connectToServer(t, cli, bastionSrv)
				if err != nil {
					t.Errorf("failed to connect to server: %v", err)
					return
				}

				session, err := bastionConn.NewSession()
				if err != nil {
					t.Errorf("failed to create session: %v", err)
					return
				}
				defer func() { _ = session.Close() }()

				if tt.ok {
					targetConn, err := bastionConn.Dial("tcp", tt.target)
					if err != nil {
						t.Errorf("expected dial to succeed, but it failed: %v", err)
						return
					}
					defer func() { _ = targetConn.Close() }()

					testData := []byte("Hello, World!")
					if _, err := targetConn.Write(testData); err != nil {
						t.Errorf("failed to write data: %v", err)
						return
					}

					buf := make([]byte, len(testData))
					if _, err := io.ReadFull(targetConn, buf); err != nil {
						t.Errorf("failed to read data: %v", err)
						return
					}

					if string(buf) != string(testData) {
						t.Errorf("expected %q, got %q", testData, buf)
						return
					}
				} else {
					if _, err = bastionConn.Dial("tcp", tt.target); err == nil {
						t.Error("expected dial to fail, but it succeeded")
						return
					}
				}
			})
		}
	})

	t.Run("permitlisten", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			pattern string
			ok      bool
		}{
			{pattern: "*:*", ok: true},
			{pattern: "127.0.0.1/8:*", ok: true},
			{pattern: "192.168.1.1:*", ok: false},
			{pattern: "*:1", ok: false},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("pattern=%s,ok=%t", tt.pattern, tt.ok), func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@%s",permitlisten="%s" %s`, mockAddr, tt.pattern, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				bastionConn, err := connectToServer(t, cli, bastionSrv)
				if err != nil {
					t.Errorf("failed to connect to server: %v", err)
					return
				}

				session, err := bastionConn.NewSession()
				if err != nil {
					t.Errorf("failed to create session: %v", err)
					return
				}
				defer func() { _ = session.Close() }()

				if tt.ok {
					listener, err := bastionConn.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Errorf("expected listen to succeed, but it failed: %v", err)
						return
					}
					defer func() { _ = listener.Close() }()

					go func() {
						time.Sleep(50 * time.Millisecond)
						conn, err := net.Dial("tcp", listener.Addr().String())
						if err != nil {
							return
						}
						defer func() { _ = conn.Close() }()
						_, _ = io.Copy(conn, conn)
					}()

					acceptedConn, err := listener.Accept()
					if err != nil {
						t.Errorf("failed to accept connection: %v", err)
						return
					}
					defer func() { _ = acceptedConn.Close() }()

					testData := []byte("Hello, World!")
					if _, err := acceptedConn.Write(testData); err != nil {
						t.Errorf("failed to write data: %v", err)
						return
					}

					buf := make([]byte, len(testData))
					if _, err := io.ReadFull(acceptedConn, buf); err != nil {
						t.Errorf("failed to read data: %v", err)
						return
					}

					if string(buf) != string(testData) {
						t.Errorf("expected %q, got %q", testData, buf)
						return
					}
				} else {
					if listener, err := bastionConn.Listen("tcp", "127.0.0.1:0"); err == nil {
						_ = listener.Close()
						t.Error("expected listen to fail, but it succeeded")
						return
					}
				}
			})
		}
	})

	t.Run("environment", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			name     string
			envOpts  string
			varName  string
			cliValue string
			expected string
		}{
			{name: "single_variable", envOpts: `environment="FOO=bar"`, varName: "FOO", expected: "bar"},
			{name: "multiple_variables", envOpts: `environment="AAA=111",environment="BBB=222"`, varName: "AAA", expected: "111"},
			{name: "value_with_equals", envOpts: `environment="KEY=val=ue"`, varName: "KEY", expected: "val=ue"},
			{name: "duplicate_last_wins", envOpts: `environment="FOO=first",environment="FOO=last"`, varName: "FOO", expected: "last"},
			{name: "deny_client_by_default", envOpts: ``, varName: "FOO", cliValue: "client", expected: ""},
			{name: "accept_client_variable", envOpts: `environment="+FOO"`, varName: "FOO", cliValue: "client", expected: "client"},
			{name: "client_cannot_override", envOpts: `environment="FOO=server",environment="+FOO"`, varName: "FOO", cliValue: "client", expected: "server"},
			{name: "accept_wildcard", envOpts: `environment="+LC_*"`, varName: "LC_ALL", cliValue: "C", expected: "C"},
			{name: "deny_overrides_accept", envOpts: `environment="+LC_*",environment="-LC_MESSAGES"`, varName: "LC_MESSAGES", cliValue: "C", expected: ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var authKeysContent string
				if tt.envOpts != "" {
					authKeysContent = fmt.Sprintf(`permitconnect="alice@%s",%s %s`, mockAddr, tt.envOpts, cliAuthorizedKeyStr)
				} else {
					authKeysContent = fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr)
				}
				bastionSrv, err := setupBastionServer(t,
					authKeysContent,
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				bastionConn, err := connectToServer(t, cli, bastionSrv)
				if err != nil {
					t.Errorf("failed to connect to server: %v", err)
					return
				}

				session, err := bastionConn.NewSession()
				if err != nil {
					t.Errorf("failed to create session: %v", err)
					return
				}
				defer func() { _ = session.Close() }()

				if tt.cliValue != "" {
					if err := session.Setenv(tt.varName, tt.cliValue); err != nil {
						t.Errorf("failed to set env: %v", err)
						return
					}
				}

				output, err := session.Output("printenv " + tt.varName)
				if err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				}
				if got := strings.TrimRight(string(output), "\r\n"); got != tt.expected {
					t.Errorf("unexpected output: got %q, want %q", got, tt.expected)
					return
				}
			})
		}
	})

	t.Run("from", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			name    string
			pattern string
			ok      bool
		}{
			{name: "exact_ipv4", pattern: "127.0.0.1", ok: true},
			{name: "cidr_ipv4", pattern: "127.0.0.0/8", ok: true},
			{name: "cidr_ipv4_nomatch", pattern: "192.168.0.0/16", ok: false},
			{name: "wildcard_ipv4", pattern: "127.0.0.*", ok: true},
			{name: "wildcard_ipv4_nomatch", pattern: "192.168.0.*", ok: false},
			{name: "wildcard_any", pattern: "*", ok: true},
			{name: "multiple_patterns", pattern: "192.168.0.0/16,127.0.0.0/8", ok: true},
			{name: "negation", pattern: "!127.0.0.1", ok: false},
			{name: "negation_cidr", pattern: "!127.0.0.0/8", ok: false},
			{name: "negation_with_allow", pattern: "!192.168.0.0/16,127.0.0.0/8", ok: true},
			{name: "negation_override", pattern: "127.0.0.0/8,!127.0.0.1", ok: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`from="%s",permitconnect="alice@*:*" %s`, tt.pattern, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				_, err = connectToServer(t, cli, bastionSrv)
				if tt.ok {
					if err != nil {
						t.Errorf("expected connection to succeed, but it failed: %v", err)
					}
				} else {
					if err == nil {
						t.Error("expected connection to fail, but it succeeded")
					}
				}
			})
		}
	})

	t.Run("start_time", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			name      string
			startTime string
			ok        bool
		}{
			{name: "past_YYYYMMDDHHMMSS_Z", startTime: time.Now().Add(-24*time.Hour).UTC().Format("20060102150405") + "Z", ok: true},
			{name: "past_YYYYMMDDHHMMSS_z", startTime: time.Now().Add(-24*time.Hour).UTC().Format("20060102150405") + "z", ok: true},
			{name: "past_YYYYMMDDHHMM_Z", startTime: time.Now().Add(-24*time.Hour).UTC().Format("200601021504") + "Z", ok: true},
			{name: "past_YYYYMMDD_Z", startTime: time.Now().Add(-48*time.Hour).UTC().Format("20060102") + "Z", ok: true},
			{name: "future_YYYYMMDDHHMMSS_Z", startTime: time.Now().Add(24*time.Hour).UTC().Format("20060102150405") + "Z", ok: false},
			{name: "future_YYYYMMDDHHMM_Z", startTime: time.Now().Add(24*time.Hour).UTC().Format("200601021504") + "Z", ok: false},
			{name: "future_YYYYMMDD_Z", startTime: time.Now().Add(48*time.Hour).UTC().Format("20060102") + "Z", ok: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`start-time="%s",permitconnect="alice@*:*" %s`, tt.startTime, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				_, err = connectToServer(t, cli, bastionSrv)
				if tt.ok {
					if err != nil {
						t.Errorf("expected connection to succeed, but it failed: %v", err)
					}
				} else {
					if err == nil {
						t.Error("expected connection to fail, but it succeeded")
					}
				}
			})
		}
	})

	t.Run("expiry_time", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			name       string
			expiryTime string
			ok         bool
		}{
			{name: "future_YYYYMMDDHHMMSS_Z", expiryTime: time.Now().Add(24*time.Hour).UTC().Format("20060102150405") + "Z", ok: true},
			{name: "future_YYYYMMDDHHMMSS_z", expiryTime: time.Now().Add(24*time.Hour).UTC().Format("20060102150405") + "z", ok: true},
			{name: "future_YYYYMMDDHHMM_Z", expiryTime: time.Now().Add(24*time.Hour).UTC().Format("200601021504") + "Z", ok: true},
			{name: "future_YYYYMMDD_Z", expiryTime: time.Now().Add(48*time.Hour).UTC().Format("20060102") + "Z", ok: true},
			{name: "past_YYYYMMDDHHMMSS_Z", expiryTime: time.Now().Add(-24*time.Hour).UTC().Format("20060102150405") + "Z", ok: false},
			{name: "past_YYYYMMDDHHMM_Z", expiryTime: time.Now().Add(-24*time.Hour).UTC().Format("200601021504") + "Z", ok: false},
			{name: "past_YYYYMMDD_Z", expiryTime: time.Now().Add(-48*time.Hour).UTC().Format("20060102") + "Z", ok: false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`expiry-time="%s",permitconnect="alice@*:*" %s`, tt.expiryTime, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				_, err = connectToServer(t, cli, bastionSrv)
				if tt.ok {
					if err != nil {
						t.Errorf("expected connection to succeed, but it failed: %v", err)
					}
				} else {
					if err == nil {
						t.Error("expected connection to fail, but it succeeded")
					}
				}
			})
		}
	})

	t.Run("time_window", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		now := time.Now()
		currentDOW := strings.ToLower(now.Weekday().String()[:3])
		currentHour := now.Hour()
		excludedHour := (currentHour + 12) % 24

		tests := []struct {
			name       string
			timeWindow string
			ok         bool
		}{
			{name: "current_time_matches", timeWindow: fmt.Sprintf("dow:%s hour:%d", currentDOW, currentHour), ok: true},
			{name: "current_time_no_match", timeWindow: fmt.Sprintf("hour:%d", excludedHour), ok: false},
			{name: "tz_only_matches_all", timeWindow: "tz:UTC", ok: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`time-window="%s",permitconnect="alice@*:*" %s`, tt.timeWindow, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				_, err = connectToServer(t, cli, bastionSrv)
				if tt.ok {
					if err != nil {
						t.Errorf("expected connection to succeed, but it failed: %v", err)
					}
				} else {
					if err == nil {
						t.Error("expected connection to fail, but it succeeded")
					}
				}
			})
		}
	})

	t.Run("command", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		if output, err := session.Output("echo Hello, World!"); err != nil {
			t.Errorf("failed to execute command: %v", err)
			return
		} else if expectedOutput := "This account is currently not available.\r\n"; string(output) != expectedOutput {
			t.Errorf("unexpected output: got %q, want %q", string(output), expectedOutput)
			return
		}
	})

	t.Run("no_port_forwarding", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr.String())
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",no-port-forwarding %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		// Verify local port forwarding is blocked
		if _, err := bastionConn.Dial("tcp", mockAddr.String()); err == nil {
			t.Error("expected dial to fail, but it succeeded")
			return
		}

		// Verify remote port forwarding is blocked
		if listener, err := bastionConn.Listen("tcp", "127.0.0.1:0"); err == nil {
			_ = listener.Close()
			t.Error("expected listen to fail, but it succeeded")
			return
		}
	})

	t.Run("no_pty", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",no-pty %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		if err = session.RequestPty("xterm", 80, 24, ssh.TerminalModes{}); err == nil {
			t.Error("expected pty request to fail, but it succeeded")
			return
		}
	})

	t.Run("restrict", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			name    string
			options string
			ptyOk   bool
		}{
			{name: "restrict", options: "restrict", ptyOk: false},
			{name: "restrict_pty", options: "restrict,pty", ptyOk: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`%s,permitconnect="alice@%s" %s`, tt.options, mockAddr, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				bastionConn, err := connectToServer(t, cli, bastionSrv)
				if err != nil {
					t.Errorf("failed to connect to server: %v", err)
					return
				}

				session, err := bastionConn.NewSession()
				if err != nil {
					t.Errorf("failed to create session: %v", err)
					return
				}
				defer func() { _ = session.Close() }()

				err = session.RequestPty("xterm", 80, 24, ssh.TerminalModes{})
				if tt.ptyOk && err != nil {
					t.Errorf("expected pty request to succeed, but it failed: %v", err)
				} else if !tt.ptyOk && err == nil {
					t.Error("expected pty request to fail, but it succeeded")
				}
			})
		}
	})

	t.Run("recordings", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		t.Run("exec_echo", func(t *testing.T) {
			recordingsDir := t.TempDir()
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
				fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				func(srv *Server) error {
					srv.config.RecordingsDir = recordingsDir
					return nil
				},
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}

			bastionConn, err := connectToServer(t, cli, bastionSrv)
			if err != nil {
				t.Errorf("failed to connect to server: %v", err)
				return
			}

			session, err := bastionConn.NewSession()
			if err != nil {
				t.Errorf("failed to create session: %v", err)
				return
			}
			defer func() { _ = session.Close() }()

			t.Run("echo", func(t *testing.T) {
				if output, err := session.Output("echo Hello, World!"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if expectedOutput := "Hello, World!\r\n"; string(output) != expectedOutput {
					t.Errorf("unexpected output: got %q, want %q", string(output), expectedOutput)
					return
				}
			})

			if err := waitFor(2*time.Second, func() error {
				files, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz"))
				if err != nil {
					return fmt.Errorf("failed to glob for recordings: %w", err)
				}
				if len(files) != 1 {
					return fmt.Errorf("expected 1 recording, got %d", len(files))
				}

				content, err := readGzipFile(files[0])
				if err != nil {
					return fmt.Errorf("failed to read recording: %w", err)
				}
				if !strings.Contains(string(content), "Hello, World!") {
					return fmt.Errorf("recording does not contain expected output: %q", string(content))
				}

				return nil
			}); err != nil {
				t.Error(err)
				return
			}
		})

		t.Run("exec_rsync", func(t *testing.T) {
			recordingsDir := t.TempDir()
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
				fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				func(srv *Server) error {
					srv.config.RecordingsDir = recordingsDir
					return nil
				},
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}

			bastionConn, err := connectToServer(t, cli, bastionSrv)
			if err != nil {
				t.Errorf("failed to connect to server: %v", err)
				return
			}

			session, err := bastionConn.NewSession()
			if err != nil {
				t.Errorf("failed to create session: %v", err)
				return
			}
			defer func() { _ = session.Close() }()

			t.Run("rsync", func(t *testing.T) {
				if output, err := session.Output("rsync --server"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if expectedOutput := "mock: rsync: NOOP\r\n"; string(output) != expectedOutput {
					t.Errorf("unexpected output: got %q, want %q", string(output), expectedOutput)
					return
				}
			})

			if err := waitFor(2*time.Second, func() error {
				files, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz"))
				if err != nil {
					return fmt.Errorf("failed to glob for recordings: %w", err)
				}
				if len(files) != 1 {
					return fmt.Errorf("expected 1 recording, got %d", len(files))
				}

				content, err := readGzipFile(files[0])
				if err != nil {
					return fmt.Errorf("failed to read recording: %w", err)
				}
				if strings.Contains(string(content), "mock: rsync: NOOP") {
					return fmt.Errorf("recording should not contain rsync output: %q", string(content))
				}

				return nil
			}); err != nil {
				t.Error(err)
				return
			}
		})

		t.Run("shell", func(t *testing.T) {
			recordingsDir := t.TempDir()
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@%s",environment="+FOO" %s`, mockAddr, cliAuthorizedKeyStr),
				fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				func(srv *Server) error {
					srv.config.RecordingsDir = recordingsDir
					return nil
				},
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}

			bastionConn, err := connectToServer(t, cli, bastionSrv)
			if err != nil {
				t.Errorf("failed to connect to server: %v", err)
				return
			}

			session, stdin, stdout, err := createShellSession(t, bastionConn)
			if err != nil {
				t.Errorf("failed to create shell session: %v", err)
				return
			}

			if err := waitForInitialPrompt(2*time.Second, t, stdout); err != nil {
				t.Errorf("failed to wait for initial prompt: %v", err)
				return
			}

			t.Run("echo", func(t *testing.T) {
				if response, err := executeShellCommand(t, stdin, stdout, "echo Hello, World!"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if !strings.Contains(response, "Hello, World!") {
					t.Errorf("expected response to contain echoed command, got: %q", response)
					return
				}
			})

			t.Run("cursor", func(t *testing.T) {
				if _, err := stdin.Write([]byte{
					'e', 'c', 'h', 'o', ' ', 'h', 'X', 'l', 'l', 'o',
					27, '[', 'D', 27, '[', 'C', 27, '[', 'D', 27, '[', 'D', 27, '[', 'D', 127,
					'e', '\r', '\n',
				}); err != nil {
					t.Errorf("failed to write cursor movement test sequence: %v", err)
					return
				}

				if response, err := readUntil(2*time.Second, stdout, "mock$", 300); err != nil {
					t.Errorf("failed to read cursor movement response: %v", err)
					return
				} else if !strings.Contains(response, "hello") {
					t.Errorf("expected response to contain edited command 'hello', got: %q", response)
					return
				}
			})

			t.Run("environment", func(t *testing.T) {
				if response, err := executeShellCommand(t, stdin, stdout, "printenv"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if !strings.Contains(response, "TERM=xterm") {
					t.Errorf("expected TERM to be xterm from initial pty-req, got response: %q", response)
					return
				}

				if response, err := executeShellCommand(t, stdin, stdout, "printenv LINES"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if !strings.Contains(response, "80") {
					t.Errorf("expected LINES to be 80 from initial pty-req, got response: %q", response)
					return
				}

				if response, err := executeShellCommand(t, stdin, stdout, "printenv COLUMNS"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if !strings.Contains(response, "24") {
					t.Errorf("expected COLUMNS to be 24 from initial pty-req, got response: %q", response)
					return
				}

				if err := session.Setenv("FOO", "BAR"); err != nil {
					t.Errorf("failed to set environment variable: %v", err)
					return
				}

				if response, err := executeShellCommand(t, stdin, stdout, "printenv FOO"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if !strings.Contains(response, "BAR") {
					t.Errorf("expected FOO to be BAR after Setenv, got response: %q", response)
					return
				}
			})

			t.Run("window", func(t *testing.T) {
				if err := session.WindowChange(30, 120); err != nil {
					t.Errorf("failed to send window change request: %v", err)
					return
				}

				if err := waitFor(2*time.Second, func() error {
					if response, err := executeShellCommand(t, stdin, stdout, "printenv LINES"); err != nil {
						return fmt.Errorf("failed to execute command: %w", err)
					} else if !strings.Contains(response, "30") {
						return fmt.Errorf("expected LINES to be 30 after window change, got response: %q", response)
					}

					if response, err := executeShellCommand(t, stdin, stdout, "printenv COLUMNS"); err != nil {
						return fmt.Errorf("failed to execute command: %w", err)
					} else if !strings.Contains(response, "120") {
						return fmt.Errorf("expected COLUMNS to be 120 after window change, got response: %q", response)
					}

					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("exit", func(t *testing.T) {
				if _, err := stdin.Write([]byte("exit 0\r")); err != nil {
					t.Errorf("failed to write exit command: %v", err)
					return
				}

				if err := waitForSessionClose(1*time.Second, t, session); err != nil {
					t.Errorf("session did not close as expected: %v", err)
					return
				}
			})

			if err := waitFor(2*time.Second, func() error {
				files, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz"))
				if err != nil {
					return fmt.Errorf("failed to glob for recordings: %w", err)
				}
				if len(files) != 1 {
					return fmt.Errorf("expected 1 recording, got %d", len(files))
				}

				content, err := readGzipFile(files[0])
				if err != nil {
					return fmt.Errorf("failed to read recording: %w", err)
				}
				if !strings.Contains(string(content), "Hello, World!") ||
					!strings.Contains(string(content), "hello") ||
					!strings.Contains(string(content), "logout") {
					return fmt.Errorf("recording does not contain expected output: %q", string(content))
				}

				return nil
			}); err != nil {
				t.Error(err)
				return
			}
		})

		t.Run("no_recording_option", func(t *testing.T) {
			tests := []struct {
				name          string
				options       string
				expectRecords int
			}{
				{name: "no_recording", options: "no-recording", expectRecords: 0},
				{name: "recording_overrides", options: "no-recording,recording", expectRecords: 1},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					recordingsDir := t.TempDir()
					bastionSrv, err := setupBastionServer(t,
						fmt.Sprintf(`permitconnect="alice@%s",%s %s`, mockAddr, tt.options, cliAuthorizedKeyStr),
						fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
						func(srv *Server) error {
							srv.config.RecordingsDir = recordingsDir
							return nil
						},
					)
					if err != nil {
						t.Errorf("failed to setup bastion server: %v", err)
						return
					}

					bastionConn, err := connectToServer(t, cli, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}

					session, err := bastionConn.NewSession()
					if err != nil {
						t.Errorf("failed to create session: %v", err)
						return
					}
					defer func() { _ = session.Close() }()

					if _, err := session.Output("echo Hello, World!"); err != nil {
						t.Errorf("failed to execute command: %v", err)
						return
					}

					if err := waitFor(2*time.Second, func() error {
						files, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz"))
						if err != nil {
							return fmt.Errorf("failed to glob for recordings: %w", err)
						}
						if len(files) != tt.expectRecords {
							return fmt.Errorf("expected %d recording(s), got %d", tt.expectRecords, len(files))
						}
						return nil
					}); err != nil {
						t.Error(err)
						return
					}
				})
			}
		})
	})

	t.Run("recordings_rotation_percentage", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		recordingsDir := t.TempDir()
		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			func(srv *Server) error {
				srv.config.RecordingsDir = recordingsDir
				// Set a low retention time to ensure files are considered old
				srv.config.RecordingsRetentionTime = 3 * time.Hour
				// Set a low disk space threshold to simulate no free space
				srv.config.RecordingsMaxDiskUsage = "0.0001%"
				return nil
			},
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		files := []struct {
			name string
			age  time.Duration
		}{
			{"file1.cast.gz", 1 * time.Hour},
			{"file2.cast.gz", 2 * time.Hour},
			{"file3.cast.gz", 3 * time.Hour},
			{"file4.cast.gz", 4 * time.Hour},
			{"file5.cast.gz", 5 * time.Hour},
		}

		for _, file := range files {
			path := filepath.Join(recordingsDir, file.name)
			if err := os.WriteFile(path, make([]byte, 1024), 0600); err != nil {
				t.Errorf("failed to create test file %s: %v", file.name, err)
				return
			}

			modTime := time.Now().Add(-file.age)
			if err := os.Chtimes(path, modTime, modTime); err != nil {
				t.Errorf("failed to set file time for %s: %v", file.name, err)
				return
			}
		}

		if currentFiles, err := disk.GetFilesBySuffix(recordingsDir, ".cast.gz"); err != nil {
			t.Errorf("failed to get current files: %v", err)
			return
		} else if len(currentFiles) != 5 {
			t.Errorf("expected 5 current files, got %d", len(currentFiles))
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		// Attempt to connect should trigger disk space check and cleanup operation
		_, _ = session.Output("exit 0")

		if remainingFiles, err := disk.GetFilesBySuffix(recordingsDir, ".cast.gz"); err != nil {
			t.Errorf("failed to get remaining files: %v", err)
			return
		} else if len(remainingFiles) > 0 {
			t.Errorf("expected 0 remaining files, got %d", len(remainingFiles))
			return
		}
	})

	t.Run("recordings_rotation_fixed_size", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		recordingsDir := t.TempDir()
		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			func(srv *Server) error {
				srv.config.RecordingsDir = recordingsDir
				// Set a low retention time to ensure files are considered old
				srv.config.RecordingsRetentionTime = 3 * time.Hour
				// Set a low disk space threshold to simulate no free space
				srv.config.RecordingsMaxDiskUsage = "4KB"
				return nil
			},
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		files := []struct {
			name string
			age  time.Duration
		}{
			{"file1.cast.gz", 1 * time.Hour},
			{"file2.cast.gz", 2 * time.Hour},
			{"file3.cast.gz", 3 * time.Hour},
			{"file4.cast.gz", 4 * time.Hour},
			{"file5.cast.gz", 5 * time.Hour},
		}

		for _, file := range files {
			path := filepath.Join(recordingsDir, file.name)
			if err := os.WriteFile(path, make([]byte, 1024), 0600); err != nil {
				t.Errorf("failed to create test file %s: %v", file.name, err)
				return
			}

			modTime := time.Now().Add(-file.age)
			if err := os.Chtimes(path, modTime, modTime); err != nil {
				t.Errorf("failed to set file time for %s: %v", file.name, err)
				return
			}
		}

		if currentFiles, err := disk.GetFilesBySuffix(recordingsDir, ".cast.gz"); err != nil {
			t.Errorf("failed to get current files: %v", err)
			return
		} else if len(currentFiles) != 5 {
			t.Errorf("expected 5 current files, got %d", len(currentFiles))
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		// Attempt to connect should trigger disk space check and cleanup operation
		_, _ = session.Output("exit 0")

		if remainingFiles, err := disk.GetFilesBySuffix(recordingsDir, ".cast.gz"); err != nil {
			t.Errorf("failed to get remaining files: %v", err)
			return
		} else if len(remainingFiles) != 3 {
			t.Errorf("expected 3 remaining files, got %d", len(remainingFiles))
			return
		}
	})

	t.Run("connections_max", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			func(srv *Server) error {
				srv.config.ConnectionsMax = 1
				return nil
			},
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("expected first connection to succeed, but got error: %v", err)
			return
		}

		_, err = connectToServer(t, cli, bastionSrv)
		if err == nil {
			t.Error("expected second connection to fail, but it succeeded")
			return
		}

		_ = bastionConn.Close()

		if err := waitFor(2*time.Second, func() error {
			if _, err := connectToServer(t, cli, bastionSrv); err != nil {
				return fmt.Errorf("expected third connection to succeed, but got error: %w", err)
			}
			return nil
		}); err != nil {
			t.Error(err)
			return
		}

	})

	t.Run("rate_limit", func(t *testing.T) {
		cliGood, cliGoodPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cliGood.User = fmt.Sprintf("alice@%s", mockAddr)
		cliGoodAuthorizedKeyStr := marshalAuthorizedKey(cliGoodPublicKey)

		cliBad, _, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cliBad.User = fmt.Sprintf("alice@%s", mockAddr)

		rateLimitMax := 3
		rateLimitTime := 1 * time.Hour
		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliGoodAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			func(srv *Server) error {
				srv.config.RateLimitMax = rateLimitMax
				srv.config.RateLimitTime = rateLimitTime
				return nil
			},
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		for range rateLimitMax {
			if _, err := connectToServer(t, cliBad, bastionSrv); err == nil {
				t.Error("expected authentication to fail, but it succeeded")
				return
			} else if !strings.Contains(err.Error(), "unable to authenticate") {
				t.Errorf("expected authentication error, got: %v", err)
				return
			}
		}

		if err := waitFor(2*time.Second, func() error {
			if bastionSrv.rateLimit.Allow("127.0.0.1") && bastionSrv.rateLimit.Allow("::1") {
				return fmt.Errorf("rate limiter should block localhost")
			}
			return nil
		}); err != nil {
			t.Error(err)
			return
		}

		if _, err := connectToServer(t, cliGood, bastionSrv); err == nil {
			t.Error("expected authentication to fail due to rate limit, but it succeeded")
			return
		}

		if bastionSrv.rateLimit.Allow("127.0.0.1") && bastionSrv.rateLimit.Allow("::1") {
			t.Error("rate limiter should still block localhost after rejected connection")
			return
		}

		bastionSrv.rateLimit.Reset("127.0.0.1")
		bastionSrv.rateLimit.Reset("::1")

		if _, err := connectToServer(t, cliGood, bastionSrv); err != nil {
			t.Errorf("expected authentication to succeed after rate limit reset, but got error: %v", err)
			return
		}
	})

	t.Run("deny_authentication", func(t *testing.T) {
		cli, _, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		if _, err := connectToServer(t, cli, bastionSrv); err == nil {
			t.Error("expected authentication to fail, but it succeeded")
			return
		} else if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Errorf("expected authentication error, got: %v", err)
			return
		}
	})

	t.Run("deny_invalid", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = "root"
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		if _, err := connectToServer(t, cli, bastionSrv); err == nil {
			t.Error("expected authentication to fail, but it succeeded")
			return
		} else if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Errorf("expected authentication error, got: %v", err)
			return
		}
	})

	t.Run("direct_tcpip_channel", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		payload := struct {
			HostToConnect  string
			PortToConnect  uint32
			OriginatorIP   string
			OriginatorPort uint32
		}{
			HostToConnect:  "127.0.0.1",
			PortToConnect:  7,
			OriginatorIP:   "127.0.0.1",
			OriginatorPort: 12345,
		}

		channel, requests, err := bastionConn.OpenChannel("direct-tcpip", ssh.Marshal(payload))
		if err != nil {
			t.Errorf("failed to open direct-tcpip channel: %v", err)
			return
		}
		defer func() { _ = channel.Close() }()

		go ssh.DiscardRequests(requests)

		data := "\x00\x01\x02\x03\xFF"

		if _, err = channel.Write([]byte(data)); err != nil {
			t.Errorf("failed to write data: %v", err)
			return
		}

		buffer := make([]byte, len(data))
		if _, err = io.ReadFull(channel, buffer); err != nil {
			t.Errorf("failed to read echoed data: %v", err)
			return
		} else if string(buffer) != data {
			t.Errorf("expected echoed data %q, got %q", data, string(buffer))
			return
		}
	})

	t.Run("unsupported_channel", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		if _, _, err := bastionConn.OpenChannel("unsupported", nil); err == nil {
			t.Error("expected unsupported channel to fail, but it succeeded")
			return
		}
	})

	t.Run("malformed_channel", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		tests := []struct {
			channel string
		}{
			{channel: "direct-tcpip"},
		}

		for _, tt := range tests {
			t.Run(tt.channel, func(t *testing.T) {
				if _, _, err := bastionConn.OpenChannel(tt.channel, []byte("invalid")); err == nil {
					t.Errorf("expected malformed %s channel to fail, but it succeeded", tt.channel)
					return
				}
			})
		}
	})

	t.Run("unsupported_request", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		if ok, _ := session.SendRequest("unsupported", true, nil); ok {
			t.Error("expected unsupported request to fail, but it succeeded")
			return
		}
	})

	t.Run("malformed_request", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		tests := []struct {
			req       string
			wantReply bool
		}{
			{req: "pty-req", wantReply: true},
			{req: "window-change", wantReply: false},
			{req: "env", wantReply: true},
			{req: "exec", wantReply: true},
			{req: "subsystem", wantReply: true},
		}

		for _, tt := range tests {
			t.Run(tt.req, func(t *testing.T) {
				if ok, _ := session.SendRequest(tt.req, tt.wantReply, []byte("invalid")); ok {
					t.Errorf("expected malformed %s request to fail, but it succeeded", tt.req)
					return
				}
			})
		}
	})

	t.Run("sftp_subsystem", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="internal-sftp" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		if err = session.RequestSubsystem("sftp"); err != nil {
			t.Errorf("expected sftp subsystem to be accepted, but got error: %v", err)
			return
		} else {
			// We expect the mock SFTP server to close the session immediately
			done := make(chan error, 1)
			go func() {
				done <- session.Wait()
			}()

			select {
			case <-done:
			case <-time.After(1 * time.Second):
				t.Error("SFTP session did not close within timeout")
				return
			}
		}
	})

	t.Run("sftp_subsystem_nologin", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		if err = session.RequestSubsystem("sftp"); err == nil {
			t.Error("expected sftp subsystem to fail with command 'nologin', but it succeeded")
			return
		}
	})

	t.Run("unsupported_subsystem", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("failed to create session: %v", err)
			return
		}
		defer func() { _ = session.Close() }()

		if err := session.RequestSubsystem("unsupported"); err == nil {
			t.Error("expected unsupported subsystem to fail, but it succeeded")
			return
		}
	})

	t.Run("host_connection_failure", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = "alice@127.0.0.1:9"
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@127.0.0.1:9" %s`, cliAuthorizedKeyStr),
			"",
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		if session, err := bastionConn.NewSession(); err == nil {
			_ = session.Close()
			t.Error("expected session creation to fail, but it succeeded")
			return
		}
	})

	t.Run("authorized_keys_db", func(t *testing.T) {
		aliceKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice"))
		aliceKeyStr := string(aliceKey.Marshal())
		aliceKeyAuth := marshalAuthorizedKey(aliceKey)

		bobKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA bob"))
		bobKeyStr := string(bobKey.Marshal())
		bobKeyAuth := marshalAuthorizedKey(bobKey)

		carolKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC carol"))
		carolKeyStr := string(carolKey.Marshal())
		carolKeyAuth := marshalAuthorizedKey(carolKey)

		defaultPermitOpens := []PermitOpen{
			{Host: "localhost", Port: "1-65535"},
			{Host: "127.0.0.1/8", Port: "1-65535"},
			{Host: "::1/128", Port: "1-65535"},
		}

		tests := []struct {
			content  string
			expected map[string][]*AuthorizedKeyOptions
		}{
			{
				content: fmt.Sprintf(`
				#define ALICE_KEY %s
				#define BOB_KEY %s
				#define CAROL_KEY %s

				# "#define" with no name is ignored
				#define

				# "#invalid" directive is ignored
				#invalid SOMETHING

				# Comment with pipe (|) in it

				# [T1] Single permitconnect entry
				permitconnect="*@basic.example.com:22" ALICE_KEY

				# [T2] Multiple permitconnect values
				permitconnect="*@192.168.0.0/16:22,*@172.16.0.0/12:22" BOB_KEY

				# [T3] Explicit permitopen option
				permitconnect="*@permitopen.example.com:22",permitopen="*:80,*:443" CAROL_KEY

				# [T4] Alternative user+host+port format
				permitconnect="*+altformat.example.com+2222" ALICE_KEY

				# [T5] IPv6 address in permitconnect value
				permitconnect="*@[2001:db8::1]:22" BOB_KEY

				# [T6] Option: no-pty
				permitconnect="*@no-pty.example.com:22",no-pty CAROL_KEY

				# [T7] Option: no-port-forwarding
				permitconnect="*@no-port-fwd.example.com:22",no-port-forwarding ALICE_KEY

				# [T8] Option: command
				permitconnect="*@command.example.com:22",command="internal-sftp" BOB_KEY

				# [T9] Option: permitlisten
				permitconnect="*@permitlisten.example.com:22",permitlisten="localhost:8080" CAROL_KEY

				# [T10] Macro expansion for key
				permitconnect="*@macro-key.example.com:22" ALICE_KEY

				# [T11] Macro expansion in permitconnect value
				#define T11_SERVERS *@10.0.1.0/24:22,*@macro-value.example.com:22
				permitconnect="T11_SERVERS" BOB_KEY

				# [T12] Multi-line macro expansion in permitconnect value
				#define T12_SERVERS \
					# dev network
					*@10.0.0.0/24:22, \
					# dev server
					*@multiline-macro.example.com:22
				permitconnect="T12_SERVERS" CAROL_KEY

				# [T13] Composed macro expansion in permitconnect value
				#define T13_SERVERS T12_SERVERS,T11_SERVERS
				permitconnect="T13_SERVERS" ALICE_KEY

				# [T14] Nested macro expansion within depth limit
				#define T14_L0 T14_L1
				#define T14_L1 T14_L2
				#define T14_L2 T14_L3
				#define T14_L3 T14_L4
				#define T14_L4 T14_L5
				#define T14_L5 T14_L6
				#define T14_L6 T14_L7
				#define T14_L7 T14_L8
				#define T14_L8 ALICE_KEY
				permitconnect="*@nested-macro.example.com:22" T14_L0

				# [T15] Line continuation with LF
				permitconnect="*@line-cont-lf.example.com:22",permitopen="*:80,*:443" \
					# comment
					BOB_KEY

				# [T16] Line continuation with CRLF
				permitconnect="*@line-cont-crlf.example.com:22",permitopen="*:80,*:443" `+"\\\r\n"+`CAROL_KEY

				# [T17] Comment with CRLF ending`+"\r\n"+`permitconnect="*@crlf-comment.example.com:22" ALICE_KEY

				# [T18] Inline comment on #define for a key
				#define T18_KEY ALICE_KEY # This is an inline comment
				permitconnect="*@inline-define-key.example.com:22" T18_KEY

				# [T19] Inline comment on #define for composed macro with pipe
				#define T19_TEAM ALICE_KEY | BOB_KEY # Team with inline comment
				permitconnect="*@inline-define-team.example.com:22" T19_TEAM

				# [T20] Inline comment at end of multi-line #define
				#define T20_SERVERS \
					*@inline-multiline-1.example.com:22, \
					*@inline-multiline-2.example.com:22 # Inline comment at end of multi-line
				permitconnect="T20_SERVERS" ALICE_KEY

				# [T21] Inline comment on access rule
				permitconnect="*@inline-rule.example.com:22" ALICE_KEY # Rule with inline comment

				# [T22] Inline comment on access rule with pipe expansion
				permitconnect="*@inline-rule-pipe.example.com:22" ALICE_KEY | BOB_KEY # Rule with pipe and inline comment

				# [T23] Pipe expansion with consecutive line continuations
				permitconnect="*@pipe-continuation.example.com:22" ALICE_KEY \
					\
					\
					| CAROL_KEY

				# [T24] Macro containing pipe operator
				#define T24_TEAM ALICE_KEY | T24_DEFERRED
				#define T24_DEFERRED BOB_KEY
				permitconnect="*@macro-pipe.example.com:22" T24_TEAM

				# [T25] Pipe character inside quoted command
				permitconnect="*@pipe-in-command.example.com:22",command="echo hello | grep h" BOB_KEY

				# [T26] Escaped quotes in command value
				permitconnect="*@escaped-quotes.example.com:22",command="echo \"hello\"" CAROL_KEY

				# [T27] Escaped backslash in command value
				permitconnect="*@escaped-backslash.example.com:22",command="echo C:\\path\\file" ALICE_KEY

				# [T28] Multiple entries for same key
				permitconnect="*@multi-entry-1.example.com:22" ALICE_KEY
				permitconnect="*@multi-entry-2.example.com:22" ALICE_KEY

				# [T29] Empty pipe segments
				|permitconnect="*@empty-pipes.example.com:22" ALICE_KEY||BOB_KEY|||CAROL_KEY|

				# [T30] Empty macro value
				#define T30_EMPTY
				permitconnect="*@empty-macro.example.com:22" T30_EMPTY ALICE_KEY

				# [T31] Whitespace-padded macro value
				#define T31_PADDED   *@padded-macro.example.com:22
				permitconnect="T31_PADDED" ALICE_KEY

				# [T32] Macro redefinition: last definition wins
				#define T32_REDEF *@redef-first.example.com:22
				#define T32_REDEF *@redef-last.example.com:22
				permitconnect="T32_REDEF" ALICE_KEY

				# [T33] Macro redefinition: sequential processing
				#define T33_SEQ *@seq-first.example.com:22
				permitconnect="T33_SEQ" ALICE_KEY
				#define T33_SEQ *@seq-second.example.com:22
				permitconnect="T33_SEQ" BOB_KEY

				# [T34] Macro token boundary matching
				#define T34_ALICE BOB_KEY
				#define T34_AAAAC should_not_match
				permitconnect="*@token-boundary.example.com:22" ALICE_KEY

				# [T35] Tab separator in #define
				#define	T35_TAB *@tab-define.example.com:22
				permitconnect="T35_TAB" ALICE_KEY

				# [T36] Underscore-prefixed macro
				#define _T36_UNDERSCORE *@underscore-prefix.example.com:22
				permitconnect="_T36_UNDERSCORE" ALICE_KEY

				# [T37] Alphanumeric macro name
				#define T37_SERVER_123 *@alphanumeric-name.example.com:22
				permitconnect="T37_SERVER_123" ALICE_KEY

				# [T38] Macro at EOF without trailing newline
				#define T38_EOF *@eof-no-newline.example.com:22
				permitconnect="T38_EOF" ALICE_KEY

				# [T39] Hash character in quoted value
				permitconnect="#user@hash#host.example.com:22",command="echo # not a comment" ALICE_KEY # a comment

				# [T40] Macro expansion with adjacent hash character
				#define T40_HOST hash-adjacent.example.com
				permitconnect="*@T40_HOST:22,*@other#host.example.com:22" ALICE_KEY

				# [T41] Unclosed quote line isolation
				permitconnect="*@unclosed-quote.example.com:22" BOB_KEY unclosed="value
				permitconnect="*@after-unclosed.example.com:22" ALICE_KEY

				# [T42] Option template macro
				#define T42_OPTS command="internal-sftp",no-pty
				permitconnect="*@opts-template.example.com:22",T42_OPTS ALICE_KEY

				# [T43] Parameterized hostname via nested expansion
				#define T43_ENV prod
				#define T43_REGION us
				#define T43_HOST app.T43_ENV.T43_REGION.example.com
				permitconnect="*@T43_HOST:22" BOB_KEY

				# [T44] Hierarchical server groups
				#define T44_TIER1 *@hierarchy-1.example.com:22
				#define T44_TIER2 T44_TIER1,*@hierarchy-2.example.com:22
				permitconnect="T44_TIER2" CAROL_KEY

				# [T45] Full-line template macro
				#define T45_LINE permitconnect="*@line-template.example.com:22"
				T45_LINE ALICE_KEY

				# [T46] Option composition macro
				#define T46_NO_PTY no-pty
				#define T46_NO_FWD no-port-forwarding
				#define T46_OPTS T46_NO_PTY,T46_NO_FWD
				permitconnect="*@opts-composed.example.com:22",T46_OPTS BOB_KEY

				# [T47] Port abstraction macro
				#define T47_PORT 22
				#define T47_HOST port-abstract.example.com
				permitconnect="*@T47_HOST:T47_PORT" CAROL_KEY

				# [T48] User pattern macro
				#define T48_USER admin
				permitconnect="T48_USER@user-pattern.example.com:22" ALICE_KEY

				# [T49] Macro in multiple option values
				#define T49_HOST multi-option.example.com
				permitconnect="*@T49_HOST:22",permitopen="T49_HOST:80" BOB_KEY

				# [T50] Nested team composition
				#define T50_SUBTEAM_A ALICE_KEY
				#define T50_SUBTEAM_B BOB_KEY | CAROL_KEY
				#define T50_TEAM T50_SUBTEAM_A | T50_SUBTEAM_B
				permitconnect="*@nested-team.example.com:22" T50_TEAM

				# [T51] Multiple declarations of same option type
				permitconnect="*@multi-decl-1.example.com:22",permitconnect="*@multi-decl-2.example.com:22",\
				permitopen="*:80",permitopen="*:443",\
				permitlisten="localhost:8080",permitlisten="localhost:9090",\
				environment="FOO=bar",environment="BAZ=quux",\
				from="10.0.0.0/8",from="172.16.0.0/12",\
				start-time="20060101Z",start-time="20060102Z",\
				expiry-time="20060101Z",expiry-time="20060102Z",\
				time-window="dow:mon-thu hour:8-17 tz:Europe/Madrid",time-window="dow:fri hour:8-14 tz:Europe/Madrid",\
				command="first",command="last",\
				no-port-forwarding,port-forwarding,\
				no-pty,pty,\
				no-recording,recording \
				ALICE_KEY

				# [T52] Restrict
				restrict,permitconnect="*@restrict.example.com:22" ALICE_KEY

				# [T53] Restrict with pty and port-forwarding overrides
				restrict,pty,port-forwarding,permitconnect="*@restrict-override.example.com:22" BOB_KEY
				`, aliceKeyAuth, bobKeyAuth, carolKeyAuth),
				expected: map[string][]*AuthorizedKeyOptions{
					aliceKeyStr: {
						// [T1]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "basic.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T4]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "altformat.example.com", Port: "2222"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T7]
						{
							PermitConnects:   []PermitConnect{{User: "*", Host: "no-port-fwd.example.com", Port: "22"}},
							PermitOpens:      defaultPermitOpens,
							NoPortForwarding: true,
						},
						// [T10]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "macro-key.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T13]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "10.0.0.0/24", Port: "22"},
								{User: "*", Host: "multiline-macro.example.com", Port: "22"},
								{User: "*", Host: "10.0.1.0/24", Port: "22"},
								{User: "*", Host: "macro-value.example.com", Port: "22"},
							},
							PermitOpens: defaultPermitOpens,
						},
						// [T14]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "nested-macro.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T17]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "crlf-comment.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T18]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "inline-define-key.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T19]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "inline-define-team.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T20]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "inline-multiline-1.example.com", Port: "22"},
								{User: "*", Host: "inline-multiline-2.example.com", Port: "22"},
							},
							PermitOpens: defaultPermitOpens,
						},
						// [T21]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "inline-rule.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T22]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "inline-rule-pipe.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T23]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "pipe-continuation.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T24]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "macro-pipe.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T27]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "escaped-backslash.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							Command:        `echo C:\\path\\file`,
						},
						// [T28]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "multi-entry-1.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T28]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "multi-entry-2.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T29]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "empty-pipes.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T30]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "empty-macro.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T31]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "padded-macro.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T32]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "redef-last.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T33]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "seq-first.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T34]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "token-boundary.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T35]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "tab-define.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T36]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "underscore-prefix.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T37]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "alphanumeric-name.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T38]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "eof-no-newline.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T39]
						{
							PermitConnects: []PermitConnect{{User: "#user", Host: "hash#host.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							Command:        "echo # not a comment",
						},
						// [T40]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "hash-adjacent.example.com", Port: "22"},
								{User: "*", Host: "other#host.example.com", Port: "22"},
							},
							PermitOpens: defaultPermitOpens,
						},
						// [T41]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "after-unclosed.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T42]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "opts-template.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							Command:        "internal-sftp",
							NoPty:          true,
						},
						// [T45]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "line-template.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T48]
						{
							PermitConnects: []PermitConnect{{User: "admin", Host: "user-pattern.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T50]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "nested-team.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T51]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "multi-decl-1.example.com", Port: "22"},
								{User: "*", Host: "multi-decl-2.example.com", Port: "22"},
							},
							PermitOpens: []PermitOpen{
								{Host: "*", Port: "80"},
								{Host: "*", Port: "443"},
							},
							PermitListens: []PermitListen{
								{Host: "localhost", Port: "8080"},
								{Host: "localhost", Port: "9090"},
							},
							Environments: []Environment{
								{Name: "FOO", Value: "bar"},
								{Name: "BAZ", Value: "quux"},
							},
							Froms:      []string{"10.0.0.0/8", "172.16.0.0/12"},
							StartTime:  func() *time.Time { t := time.Date(2006, 1, 2, 0, 0, 0, 0, time.UTC); return &t }(),
							ExpiryTime: func() *time.Time { t := time.Date(2006, 1, 1, 0, 0, 0, 0, time.UTC); return &t }(),
							TimeWindow: func() *timewindow.TimeWindow {
								tw, _ := timewindow.Parse("dow:mon-thu hour:8-17 tz:Europe/Madrid,dow:fri hour:8-14 tz:Europe/Madrid")
								return tw
							}(),
							Command:          "last",
							NoPortForwarding: false,
							NoPty:            false,
							NoRecording:      false,
						},
						// [T52]
						{
							PermitConnects:   []PermitConnect{{User: "*", Host: "restrict.example.com", Port: "22"}},
							PermitOpens:      defaultPermitOpens,
							NoPortForwarding: true,
							NoPty:            true,
						},
					},
					bobKeyStr: {
						// [T2]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "192.168.0.0/16", Port: "22"},
								{User: "*", Host: "172.16.0.0/12", Port: "22"},
							},
							PermitOpens: defaultPermitOpens,
						},
						// [T5]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "2001:db8::1", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T8]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "command.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							Command:        "internal-sftp",
						},
						// [T11]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "10.0.1.0/24", Port: "22"},
								{User: "*", Host: "macro-value.example.com", Port: "22"},
							},
							PermitOpens: defaultPermitOpens,
						},
						// [T15]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "line-cont-lf.example.com", Port: "22"}},
							PermitOpens: []PermitOpen{
								{Host: "*", Port: "80"},
								{Host: "*", Port: "443"},
							},
						},
						// [T19]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "inline-define-team.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T22]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "inline-rule-pipe.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T24]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "macro-pipe.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T25]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "pipe-in-command.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							Command:        "echo hello | grep h",
						},
						// [T29]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "empty-pipes.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T33]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "seq-second.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T41]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "unclosed-quote.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T43]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "app.prod.us.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T46]
						{
							PermitConnects:   []PermitConnect{{User: "*", Host: "opts-composed.example.com", Port: "22"}},
							PermitOpens:      defaultPermitOpens,
							NoPty:            true,
							NoPortForwarding: true,
						},
						// [T49]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "multi-option.example.com", Port: "22"}},
							PermitOpens:    []PermitOpen{{Host: "multi-option.example.com", Port: "80"}},
						},
						// [T50]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "nested-team.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T53]
						{
							PermitConnects:   []PermitConnect{{User: "*", Host: "restrict-override.example.com", Port: "22"}},
							PermitOpens:      defaultPermitOpens,
							NoPortForwarding: false,
							NoPty:            false,
						},
					},
					carolKeyStr: {
						// [T3]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "permitopen.example.com", Port: "22"}},
							PermitOpens: []PermitOpen{
								{Host: "*", Port: "80"},
								{Host: "*", Port: "443"},
							},
						},
						// [T6]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "no-pty.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							NoPty:          true,
						},
						// [T9]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "permitlisten.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							PermitListens:  []PermitListen{{Host: "localhost", Port: "8080"}},
						},
						// [T12]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "10.0.0.0/24", Port: "22"},
								{User: "*", Host: "multiline-macro.example.com", Port: "22"},
							},
							PermitOpens: defaultPermitOpens,
						},
						// [T16]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "line-cont-crlf.example.com", Port: "22"}},
							PermitOpens: []PermitOpen{
								{Host: "*", Port: "80"},
								{Host: "*", Port: "443"},
							},
						},
						// [T23]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "pipe-continuation.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T26]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "escaped-quotes.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
							Command:        `echo "hello"`,
						},
						// [T29]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "empty-pipes.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T44]
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "hierarchy-1.example.com", Port: "22"},
								{User: "*", Host: "hierarchy-2.example.com", Port: "22"},
							},
							PermitOpens: defaultPermitOpens,
						},
						// [T47]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "port-abstract.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
						// [T50]
						{
							PermitConnects: []PermitConnect{{User: "*", Host: "nested-team.example.com", Port: "22"}},
							PermitOpens:    defaultPermitOpens,
						},
					},
				},
			},
		}

		for _, tt := range tests {
			bastionSrv, err := setupBastionServer(t, tt.content, "")
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}

			if len(bastionSrv.authKeysDB) != len(tt.expected) {
				t.Errorf("expected %d keys in authorized_keys db, got %d", len(tt.expected), len(bastionSrv.authKeysDB))
				return
			}
			for key, optsList := range bastionSrv.authKeysDB {
				if expectedOptsList, ok := tt.expected[key]; !ok {
					t.Error("expected key to be in authorized_keys db, but it was not found")
					return
				} else if len(optsList) != len(expectedOptsList) {
					t.Errorf("expected %d options for key, got %d", len(expectedOptsList), len(optsList))
					return
				} else {
					for i, opts := range optsList {
						expectedOpts := expectedOptsList[i]
						if len(opts.PermitConnects) != len(expectedOpts.PermitConnects) {
							t.Errorf("expected %d permitconnects for key, got %d", len(expectedOpts.PermitConnects), len(opts.PermitConnects))
							return
						}
						for j, pc := range opts.PermitConnects {
							expectedPC := expectedOpts.PermitConnects[j]
							if pc.User != expectedPC.User || pc.Host != expectedPC.Host || pc.Port != expectedPC.Port {
								t.Errorf("expected permitconnect %v for key, got %v", expectedPC, pc)
								return
							}
						}
						if len(opts.PermitOpens) != len(expectedOpts.PermitOpens) {
							t.Errorf("expected %d permitopens for key, got %d", len(expectedOpts.PermitOpens), len(opts.PermitOpens))
							return
						}
						for j, po := range opts.PermitOpens {
							expectedPO := expectedOpts.PermitOpens[j]
							if po.Host != expectedPO.Host || po.Port != expectedPO.Port {
								t.Errorf("expected permitopen %v for key, got %v", expectedPO, po)
								return
							}
						}
						if len(opts.PermitListens) != len(expectedOpts.PermitListens) {
							t.Errorf("expected %d permitlistens for key, got %d", len(expectedOpts.PermitListens), len(opts.PermitListens))
							return
						}
						for j, pl := range opts.PermitListens {
							expectedPL := expectedOpts.PermitListens[j]
							if pl.Host != expectedPL.Host || pl.Port != expectedPL.Port {
								t.Errorf("expected permitlisten %v for key, got %v", expectedPL, pl)
								return
							}
						}
						if len(opts.Environments) != len(expectedOpts.Environments) {
							t.Errorf("expected %d environments for key, got %d", len(expectedOpts.Environments), len(opts.Environments))
							return
						}
						for j, env := range opts.Environments {
							if env != expectedOpts.Environments[j] {
								t.Errorf("expected environment %+v for key, got %+v", expectedOpts.Environments[j], env)
								return
							}
						}
						if len(opts.Froms) != len(expectedOpts.Froms) {
							t.Errorf("expected %d froms for key, got %d", len(expectedOpts.Froms), len(opts.Froms))
							return
						}
						for j, from := range opts.Froms {
							if from != expectedOpts.Froms[j] {
								t.Errorf("expected from %q for key, got %q", expectedOpts.Froms[j], from)
								return
							}
						}
						if (opts.StartTime == nil) != (expectedOpts.StartTime == nil) {
							t.Errorf("expected start-time %v for key, got %v", expectedOpts.StartTime, opts.StartTime)
							return
						}
						if opts.StartTime != nil && !opts.StartTime.Equal(*expectedOpts.StartTime) {
							t.Errorf("expected start-time %v for key, got %v", *expectedOpts.StartTime, *opts.StartTime)
							return
						}
						if (opts.ExpiryTime == nil) != (expectedOpts.ExpiryTime == nil) {
							t.Errorf("expected expiry-time %v for key, got %v", expectedOpts.ExpiryTime, opts.ExpiryTime)
							return
						}
						if opts.ExpiryTime != nil && !opts.ExpiryTime.Equal(*expectedOpts.ExpiryTime) {
							t.Errorf("expected expiry-time %v for key, got %v", *expectedOpts.ExpiryTime, *opts.ExpiryTime)
							return
						}
						if (opts.TimeWindow == nil) != (expectedOpts.TimeWindow == nil) {
							t.Errorf("expected time-window %v for key, got %v", expectedOpts.TimeWindow, opts.TimeWindow)
							return
						}
						if opts.TimeWindow != nil {
							got, err := json.Marshal(opts.TimeWindow)
							if err != nil {
								t.Errorf("failed to marshal time-window: %v", err)
								return
							}
							expected, err := json.Marshal(expectedOpts.TimeWindow)
							if err != nil {
								t.Errorf("failed to marshal expected time-window: %v", err)
								return
							}
							if string(got) != string(expected) {
								t.Errorf("expected time-window %s for key, got %s", expected, got)
								return
							}
						}
						if opts.Command != expectedOpts.Command {
							t.Errorf("expected command %q for key, got %q", expectedOpts.Command, opts.Command)
							return
						}
						if opts.NoPortForwarding != expectedOpts.NoPortForwarding {
							t.Errorf("expected no-port-forwarding %t for key, got %t", expectedOpts.NoPortForwarding, opts.NoPortForwarding)
							return
						}
						if opts.NoPty != expectedOpts.NoPty {
							t.Errorf("expected no-pty %t for key, got %t", expectedOpts.NoPty, opts.NoPty)
							return
						}
						if opts.NoRecording != expectedOpts.NoRecording {
							t.Errorf("expected no-recording %t for key, got %t", expectedOpts.NoRecording, opts.NoRecording)
							return
						}
					}
				}
			}
		}

		t.Run("reject", func(t *testing.T) {
			tests := []struct {
				name    string
				content string
			}{
				// Empty/whitespace/comment content
				{name: "empty_file", content: ``},
				{name: "whitespace_only", content: `   `},
				{name: "tabs_and_newlines", content: "\t\n\t\n"},
				{name: "comment_only", content: "# comment only\n# another comment"},
				// Invalid SSH key format
				{name: "invalid_ssh_key", content: `permitconnect="*@example.com:22" invalid`},
				// Key without options
				{name: "key_without_options", content: aliceKeyAuth},
				// Options without permitconnect
				{name: "options_without_permitconnect", content: fmt.Sprintf(`command="nologin" %s`, aliceKeyAuth)},
				// Invalid permitconnect
				{name: "permitconnect_empty", content: fmt.Sprintf(`permitconnect="" %s`, aliceKeyAuth)},
				{name: "permitconnect_invalid_format", content: fmt.Sprintf(`permitconnect="invalid" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_user_at", content: fmt.Sprintf(`permitconnect="@host:22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_host_at", content: fmt.Sprintf(`permitconnect="user@:22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_port_at", content: fmt.Sprintf(`permitconnect="user@host:" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_user_plus", content: fmt.Sprintf(`permitconnect="+host+22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_host_plus", content: fmt.Sprintf(`permitconnect="user++22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_port_plus", content: fmt.Sprintf(`permitconnect="user+host+" %s`, aliceKeyAuth)},
				{name: "permitconnect_empty_user_and_host_at", content: fmt.Sprintf(`permitconnect="@:22" %s`, aliceKeyAuth)},
				{name: "permitconnect_empty_user_and_host_plus", content: fmt.Sprintf(`permitconnect="++22" %s`, aliceKeyAuth)},
				{name: "permitconnect_exceeding_length_at", content: fmt.Sprintf(`permitconnect="*@%s:22" %s`, strings.Repeat("a", 1100), aliceKeyAuth)},
				{name: "permitconnect_exceeding_length_plus", content: fmt.Sprintf(`permitconnect="*+%s+22" %s`, strings.Repeat("a", 1100), aliceKeyAuth)},
				// Invalid permitopen
				{name: "permitopen_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="" %s`, aliceKeyAuth)},
				{name: "permitopen_invalid_format", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="invalid" %s`, aliceKeyAuth)},
				{name: "permitopen_missing_host", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen=":22" %s`, aliceKeyAuth)},
				{name: "permitopen_missing_port", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="host:" %s`, aliceKeyAuth)},
				{name: "permitopen_exceeding_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="%s:22" %s`, strings.Repeat("a", 550), aliceKeyAuth)},
				// Invalid permitlisten
				{name: "permitlisten_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="" %s`, aliceKeyAuth)},
				{name: "permitlisten_invalid_format", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="invalid" %s`, aliceKeyAuth)},
				{name: "permitlisten_missing_host", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten=":22" %s`, aliceKeyAuth)},
				{name: "permitlisten_missing_port", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="host:" %s`, aliceKeyAuth)},
				{name: "permitlisten_exceeding_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="%s:22" %s`, strings.Repeat("a", 550), aliceKeyAuth)},
				// Invalid environment
				{name: "environment_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="" %s`, aliceKeyAuth)},
				{name: "environment_missing_equals", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="NOEQUALS" %s`, aliceKeyAuth)},
				{name: "environment_empty_name", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="=value" %s`, aliceKeyAuth)},
				{name: "environment_invalid_name_hyphen", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="BAD-NAME=value" %s`, aliceKeyAuth)},
				{name: "environment_invalid_name_dot", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="BAD.NAME=value" %s`, aliceKeyAuth)},
				{name: "environment_empty_accept_pattern", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="+" %s`, aliceKeyAuth)},
				{name: "environment_empty_deny_pattern", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="-" %s`, aliceKeyAuth)},
				{name: "environment_invalid_accept_glob", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="+VAR[" %s`, aliceKeyAuth)},
				{name: "environment_invalid_deny_glob", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="-VAR[" %s`, aliceKeyAuth)},
				// Invalid start-time
				{name: "start_time_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="2020Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_month", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20201301Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_day", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20200132Z" %s`, aliceKeyAuth)},
				{name: "start_time_nonexistent_date", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20200230Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_hour", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="202001012500Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_minute", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="202001010060Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_second", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20200101000060Z" %s`, aliceKeyAuth)},
				{name: "start_time_non_numeric_ymd", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="ABCD0101Z" %s`, aliceKeyAuth)},
				{name: "start_time_non_numeric_ymdhm", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="ABCD01010000Z" %s`, aliceKeyAuth)},
				{name: "start_time_non_numeric_ymdhms", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="ABCD0101000000Z" %s`, aliceKeyAuth)},
				// Invalid expiry-time
				{name: "expiry_time_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="2099Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_month", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20991301Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_day", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20990132Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_nonexistent_date", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20990230Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_hour", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="209901012500Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_minute", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="209901010060Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_second", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20990101000060Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_non_numeric_ymd", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="ABCD0101Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_non_numeric_ymdhm", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="ABCD01010000Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_non_numeric_ymdhms", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="ABCD0101000000Z" %s`, aliceKeyAuth)},
				// Invalid time-window
				{name: "time_window_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="" %s`, aliceKeyAuth)},
				{name: "time_window_whitespace_only", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="   " %s`, aliceKeyAuth)},
				{name: "time_window_unknown_constraint", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="foo:bar" %s`, aliceKeyAuth)},
				{name: "time_window_missing_value", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:" %s`, aliceKeyAuth)},
				{name: "time_window_missing_colon", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow" %s`, aliceKeyAuth)},
				{name: "time_window_hour_out_of_range", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:25" %s`, aliceKeyAuth)},
				{name: "time_window_dow_out_of_range", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:7" %s`, aliceKeyAuth)},
				{name: "time_window_month_out_of_range", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="month:0" %s`, aliceKeyAuth)},
				{name: "time_window_dow_wrap_around", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:fri-mon" %s`, aliceKeyAuth)},
				{name: "time_window_hour_wrap_around", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:22-6" %s`, aliceKeyAuth)},
				{name: "time_window_invalid_timezone", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="tz:Invalid/Zone" %s`, aliceKeyAuth)},
				{name: "time_window_duplicate_constraint", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:9 hour:10" %s`, aliceKeyAuth)},
				{name: "time_window_leading_comma", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window=",dow:mon" %s`, aliceKeyAuth)},
				{name: "time_window_trailing_comma", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:mon," %s`, aliceKeyAuth)},
				{name: "time_window_double_comma", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:mon,,dow:tue" %s`, aliceKeyAuth)},
				{name: "time_window_negative_number", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:-1" %s`, aliceKeyAuth)},
				{name: "time_window_non_integer", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:9.5" %s`, aliceKeyAuth)},
				{name: "time_window_overflow", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:999999999999" %s`, aliceKeyAuth)},
				{name: "time_window_empty_range_component", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:1//5" %s`, aliceKeyAuth)},
				// Quote/line continuation edge cases
				{name: "unterminated_quoted_string", content: fmt.Sprintf(`permitconnect="*@example.com:22 %s`, aliceKeyAuth)},
				{name: "crlf_inside_quoted_string", content: fmt.Sprintf("permitconnect=\"*@example.com:22\",command=\"echo \r\ntest\" %s", aliceKeyAuth)},
				{name: "trailing_backslash_at_eof", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s\`, aliceKeyAuth)},
				{name: "backslash_space_before_newline", content: fmt.Sprintf("permitconnect=\"*@example.com:22\" \\ \n%s", aliceKeyAuth)},
				{name: "line_continuation_at_eof_without_key", content: `permitconnect="*@example.com:22" \`},
				// Pipe edge cases
				{name: "pipe_only", content: "|"},
				{name: "pipe_whitespace_segments", content: `   |   |   `},
				{name: "pipe_without_options", content: fmt.Sprintf(`%s | %s`, aliceKeyAuth, bobKeyAuth)},
				{name: "options_on_non_first_pipe_segment", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s | permitconnect="*@other.com:22" %s`, aliceKeyAuth, bobKeyAuth)},
				{name: "invalid_key_in_pipe_segment", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s | invalid`, aliceKeyAuth)},
				{name: "invalid_key_in_middle_pipe_segment", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s | invalid | %s`, aliceKeyAuth, bobKeyAuth)},
				// Macro edge cases
				{
					name: "define_without_whitespace_separator",
					content: `
					#defineX MACRO value
					permitconnect="*@example.com:22" MACRO
					`,
				},
				{
					name: "macro_name_leading_digit",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define 1BAD_KEY %s
					permitconnect="*@example.com:22" 1BAD_KEY
					`, aliceKeyAuth, bobKeyAuth),
				},
				{
					name: "macro_name_non_ascii",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define BÄD_KEY %s
					permitconnect="*@example.com:22" BÄD_KEY
					`, aliceKeyAuth, bobKeyAuth),
				},
				{
					name: "self_referential_macro",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define INFINITE INFINITE
					permitconnect="*@example.com:22" INFINITE
					`, aliceKeyAuth),
				},
				{
					name: "self_referential_macro_in_quoted_value",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define INFINITE INFINITE
					permitconnect="INFINITE" ALICE_KEY
					`, aliceKeyAuth),
				},
				{
					name: "mutually_recursive_macros",
					content: `
					#define A B
					#define B A
					permitconnect="*@example.com:22" A
					`,
				},
				{
					name: "macro_recursion_exceeding_depth",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define L0 L1
					#define L1 L2
					#define L2 L3
					#define L3 L4
					#define L4 L5
					#define L5 L6
					#define L6 L7
					#define L7 L8
					#define L8 L9
					#define L9 ALICE_KEY
					permitconnect="*@example.com:22" L0
					`, aliceKeyAuth),
				},
				// Null byte cases
				{name: "null_byte_only", content: "\x00"},
				{name: "null_byte_in_key_data", content: "permitconnect=\"*@example.com:22\" ssh-ed25519 AAAA\x00AAAA comment"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					db, err := parseAuthorizedKeys([]byte(tt.content))
					if err != nil {
						t.Fatalf("parseAuthorizedKeys returned error: %v", err)
					}
					if len(db) != 0 {
						t.Errorf("expected empty db, got %d keys", len(db))
					}
				})
			}
		})
	})

	t.Run("authorized_keys_watcher", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t, "", fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr))
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}
		bastionCfg := bastionSrv.Config()

		if _, err := connectToServer(t, cli, bastionSrv); err == nil {
			t.Error("expected connection to fail initially, but it succeeded")
			return
		}

		authorizedKeysFile := bastionCfg.AuthorizedKeysFile
		authorizedKeysContent := fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr)
		if err := os.WriteFile(authorizedKeysFile, []byte(authorizedKeysContent), 0600); err != nil {
			t.Error(err)
			return
		}

		if err := waitFor(30*time.Second, func() error {
			if _, err := connectToServer(t, cli, bastionSrv); err != nil {
				return fmt.Errorf("expected connection to succeed after updating authorized_keys: %v", err)
			}
			return nil
		}); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("known_hosts_db", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		t.Run("unknown_policy_strict", func(t *testing.T) {
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
				"",
				func(srv *Server) error {
					srv.config.UnknownHostsPolicy = "strict"
					return nil
				},
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}

			bastionConn, err := connectToServer(t, cli, bastionSrv)
			if err != nil {
				t.Errorf("failed to connect to server: %v", err)
				return
			}

			if session, err := bastionConn.NewSession(); err == nil {
				_ = session.Close()
				t.Error("expected session creation to fail, but it succeeded")
				return
			}
		})

		t.Run("unknown_policy_tofu", func(t *testing.T) {
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@%s",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
				"",
				func(srv *Server) error {
					srv.config.UnknownHostsPolicy = "tofu"
					return nil
				},
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}
			bastionCfg := bastionSrv.Config()

			bastionConn, err := connectToServer(t, cli, bastionSrv)
			if err != nil {
				t.Errorf("failed to connect to server: %v", err)
				return
			}

			session, err := bastionConn.NewSession()
			if err != nil {
				t.Errorf("failed to create session: %v", err)
				return
			}
			defer func() { _ = session.Close() }()

			knownHostsFile := filepath.Clean(bastionCfg.KnownHostsFile)
			knownHostsContent, err := os.ReadFile(knownHostsFile)
			if err != nil {
				t.Errorf("failed to read known_hosts file: %v", err)
				return
			}

			expectedContent := fmt.Sprintf("[%s]:%d %s", mockAddr.IP, mockAddr.Port, mockAuthorizedKeyStr)
			if !strings.Contains(string(knownHostsContent), expectedContent) {
				t.Errorf("expected known_hosts to contain entry %q, got: %q", expectedContent, string(knownHostsContent))
				return
			}
		})

		t.Run("ca", func(t *testing.T) {
			gen := func(kind string) (caPrivateKey, srvPrivateKey crypto.PrivateKey, err error) {
				switch kind {
				case ssh.KeyAlgoED25519:
					_, ca, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					_, srv, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					return ca, srv, nil
				case ssh.KeyAlgoECDSA256:
					ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					srv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					return ca, srv, nil
				case ssh.KeyAlgoECDSA384:
					ca, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					srv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					return ca, srv, nil
				case ssh.KeyAlgoECDSA521:
					ca, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					srv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					if err != nil {
						return nil, nil, err
					}
					return ca, srv, nil
				case ssh.KeyAlgoRSA:
					ca, err := rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						return nil, nil, err
					}
					srv, err := rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						return nil, nil, err
					}
					return ca, srv, nil
				default:
					return nil, nil, fmt.Errorf("unsupported key type %q", kind)
				}
			}

			keys := []string{
				ssh.KeyAlgoED25519,
				ssh.KeyAlgoECDSA256,
				ssh.KeyAlgoECDSA384,
				ssh.KeyAlgoECDSA521,
				ssh.KeyAlgoRSA,
			}

			for _, k := range keys {
				t.Run(k, func(t *testing.T) {
					caPrivateKey, srvPrivateKey, err := gen(k)
					if err != nil {
						t.Errorf("failed to generate %s keys: %v", k, err)
						return
					}

					caSigner, err := ssh.NewSignerFromKey(caPrivateKey)
					if err != nil {
						t.Errorf("failed to create CA signer: %v", err)
						return
					}
					caAuthorizedKeyStr := marshalAuthorizedKey(caSigner.PublicKey())

					srvSigner, err := ssh.NewSignerFromKey(srvPrivateKey)
					if err != nil {
						t.Errorf("failed to create host signer: %v", err)
						return
					}

					srvCert := &ssh.Certificate{
						Key:             srvSigner.PublicKey(),
						Serial:          1,
						CertType:        ssh.HostCert,
						ValidPrincipals: []string{"localhost", "127.0.0.1", "::1"},
						ValidAfter:      0,
						ValidBefore:     math.MaxUint64,
						Permissions:     ssh.Permissions{},
					}
					if err := srvCert.SignCert(rand.Reader, caSigner); err != nil {
						t.Errorf("failed to sign certificate: %v", err)
						return
					}

					srvCertSigner, err := ssh.NewCertSigner(srvCert, srvSigner)
					if err != nil {
						t.Errorf("failed to create cert signer: %v", err)
						return
					}

					mockWithCertSrv, err := setupMockServer(t, mock.WithSigner(srvCertSigner))
					if err != nil {
						t.Errorf("failed to setup mock server: %v", err)
						return
					}
					mockWithCertAddr := mockWithCertSrv.Address()

					cli, cliPublicKey, err := setupClient(t)
					if err != nil {
						t.Errorf("failed to setup client: %v", err)
						return
					}
					cli.User = fmt.Sprintf("alice@%s", mockWithCertAddr)
					cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

					bastionSrv, err := setupBastionServer(t,
						fmt.Sprintf(`permitconnect="alice@%s" %s`, mockWithCertAddr, cliAuthorizedKeyStr),
						fmt.Sprintf("@cert-authority *:%d %s", mockWithCertAddr.Port, caAuthorizedKeyStr),
					)
					if err != nil {
						t.Errorf("failed to setup bastion server: %v", err)
						return
					}

					bastionConn, err := connectToServer(t, cli, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}

					session, err := bastionConn.NewSession()
					if err != nil {
						t.Errorf("failed to create session: %v", err)
						return
					}
					defer func() { _ = session.Close() }()

					if output, err := session.Output("echo Hello, World!"); err != nil {
						t.Errorf("failed to execute command: %v", err)
						return
					} else if expectedOutput := "Hello, World!\r\n"; string(output) != expectedOutput {
						t.Errorf("unexpected output: got %q, want %q", string(output), expectedOutput)
						return
					}
				})
			}
		})
	})

	t.Run("credential_providers", func(t *testing.T) {
		t.Run("file", func(t *testing.T) {
			t.Run("existing_with_passphrase", func(t *testing.T) {
				_, privateKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Errorf("failed to generate private key: %v", err)
					return
				}

				pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte("hunter2"))
				if err != nil {
					t.Errorf("failed to marshal private key: %v", err)
					return
				}

				privateKeyPath := filepath.Join(t.TempDir(), "private_key")
				if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
					t.Errorf("failed to write private key to file: %v", err)
					return
				}

				t.Run("correct_passphrase", func(t *testing.T) {
					_, err = setupBastionServer(t, "", "", func(srv *Server) error {
						srv.config.PrivateKeyFile = privateKeyPath
						srv.config.PrivateKeyPassphrase = "hunter2"
						srv.config.PrivateKeyPassphraseFile = ""
						return nil
					})
					if err != nil {
						t.Errorf("failed to setup bastion server with existing private key: %v", err)
						return
					}
				})

				t.Run("wrong_passphrase", func(t *testing.T) {
					_, err = setupBastionServer(t, "", "", func(srv *Server) error {
						srv.config.PrivateKeyFile = privateKeyPath
						srv.config.PrivateKeyPassphrase = "wrongpass"
						srv.config.PrivateKeyPassphraseFile = ""
						return nil
					})
					if err == nil {
						t.Error("expected setup with wrong passphrase to fail, but it succeeded")
						return
					}
				})

				t.Run("missing_passphrase", func(t *testing.T) {
					_, err = setupBastionServer(t, "", "", func(srv *Server) error {
						srv.config.PrivateKeyFile = privateKeyPath
						srv.config.PrivateKeyPassphrase = ""
						srv.config.PrivateKeyPassphraseFile = ""
						return nil
					})
					if err == nil {
						t.Error("expected setup with missing passphrase to fail, but it succeeded")
						return
					}
				})
			})

			t.Run("existing_without_passphrase", func(t *testing.T) {
				_, privateKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Errorf("failed to generate private key: %v", err)
					return
				}

				pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
				if err != nil {
					t.Errorf("failed to marshal private key: %v", err)
					return
				}

				privateKeyPath := filepath.Join(t.TempDir(), "private_key")
				if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
					t.Errorf("failed to write private key to file: %v", err)
					return
				}

				t.Run("passphrase", func(t *testing.T) {
					_, err = setupBastionServer(t, "", "", func(srv *Server) error {
						srv.config.PrivateKeyFile = privateKeyPath
						srv.config.PrivateKeyPassphrase = "hunter2"
						srv.config.PrivateKeyPassphraseFile = ""
						return nil
					})
					if err == nil {
						t.Error("expected setup with passphrase to fail, but it succeeded")
						return
					}
				})

				t.Run("no_passphrase", func(t *testing.T) {
					_, err = setupBastionServer(t, "", "", func(srv *Server) error {
						srv.config.PrivateKeyFile = privateKeyPath
						srv.config.PrivateKeyPassphrase = ""
						srv.config.PrivateKeyPassphraseFile = ""
						return nil
					})
					if err != nil {
						t.Errorf("failed to setup bastion server with existing private key: %v", err)
						return
					}
				})
			})

			t.Run("missing_with_passphrase", func(t *testing.T) {
				privateKeyPath := filepath.Join(t.TempDir(), "private_key")

				_, err = setupBastionServer(t, "", "", func(srv *Server) error {
					srv.config.PrivateKeyFile = privateKeyPath
					srv.config.PrivateKeyPassphrase = "hunter2"
					srv.config.PrivateKeyPassphraseFile = ""
					return nil
				})
				if err != nil {
					t.Errorf("failed to setup bastion server with missing private key: %v", err)
					return
				}
			})

			t.Run("missing_without_passphrase", func(t *testing.T) {
				privateKeyPath := filepath.Join(t.TempDir(), "private_key")

				_, err = setupBastionServer(t, "", "", func(srv *Server) error {
					srv.config.PrivateKeyFile = privateKeyPath
					srv.config.PrivateKeyPassphrase = ""
					srv.config.PrivateKeyPassphraseFile = ""
					return nil
				})
				if err != nil {
					t.Errorf("failed to setup bastion server with missing private key: %v", err)
					return
				}
			})

			t.Run("existing_with_passphrase_file", func(t *testing.T) {
				_, privateKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Errorf("failed to generate private key: %v", err)
					return
				}

				pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte("hunter2"))
				if err != nil {
					t.Errorf("failed to marshal private key: %v", err)
					return
				}

				privateKeyPath := filepath.Join(t.TempDir(), "private_key")
				if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
					t.Errorf("failed to write private key to file: %v", err)
					return
				}

				t.Run("correct_passphrase_file", func(t *testing.T) {
					passphraseFilePath := filepath.Join(t.TempDir(), "passphrase")
					if err := os.WriteFile(passphraseFilePath, []byte("hunter2"), 0600); err != nil {
						t.Errorf("failed to write passphrase to file: %v", err)
						return
					}

					t.Run("without_passphrase_flag", func(t *testing.T) {
						_, err = setupBastionServer(t, "", "", func(srv *Server) error {
							srv.config.PrivateKeyFile = privateKeyPath
							srv.config.PrivateKeyPassphrase = ""
							srv.config.PrivateKeyPassphraseFile = passphraseFilePath
							return nil
						})
						if err != nil {
							t.Errorf("failed to setup bastion server with existing private key: %v", err)
							return
						}
					})

					t.Run("with_passphrase_flag", func(t *testing.T) {
						_, err = setupBastionServer(t, "", "", func(srv *Server) error {
							srv.config.PrivateKeyFile = privateKeyPath
							srv.config.PrivateKeyPassphrase = "hunter2"
							srv.config.PrivateKeyPassphraseFile = passphraseFilePath
							return nil
						})
						if err == nil {
							t.Error("expected setup with correct passphrase file and passphrase flag to fail, but it succeeded")
							return
						}
					})
				})

				t.Run("wrong_passphrase_file", func(t *testing.T) {
					wrongPassphraseFilePath := filepath.Join(t.TempDir(), "passphrase")
					if err := os.WriteFile(wrongPassphraseFilePath, []byte("wrongpass"), 0600); err != nil {
						t.Errorf("failed to write passphrase to file: %v", err)
						return
					}

					_, err = setupBastionServer(t, "", "", func(srv *Server) error {
						srv.config.PrivateKeyFile = privateKeyPath
						srv.config.PrivateKeyPassphrase = ""
						srv.config.PrivateKeyPassphraseFile = wrongPassphraseFilePath
						return nil
					})
					if err == nil {
						t.Error("expected setup with wrong passphrase file to fail, but it succeeded")
						return
					}
				})

				t.Run("missing_passphrase_file", func(t *testing.T) {
					missingPassphraseFilePath := filepath.Join(t.TempDir(), "passphrase")

					_, err = setupBastionServer(t, "", "", func(srv *Server) error {
						srv.config.PrivateKeyFile = privateKeyPath
						srv.config.PrivateKeyPassphrase = ""
						srv.config.PrivateKeyPassphraseFile = missingPassphraseFilePath
						return nil
					})
					if err == nil {
						t.Error("expected setup with missing passphrase file to fail, but it succeeded")
						return
					}
				})
			})
		})
	})

	t.Run("banner", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bannerFile := filepath.Join(t.TempDir(), "banner.txt")
		initialBanner := "\x1b[1;32mWelcome\x1b[0m to Cardea\n"
		if err := os.WriteFile(bannerFile, []byte(initialBanner), 0600); err != nil {
			t.Errorf("failed to write banner file: %v", err)
			return
		}

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			func(srv *Server) error {
				srv.config.BannerFile = bannerFile
				return nil
			},
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		var receivedBanner string
		cli.BannerCallback = func(message string) error {
			receivedBanner = message
			return nil
		}

		if _, err := connectToServer(t, cli, bastionSrv); err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		expectedBanner := "Welcome to Cardea\n"
		if receivedBanner != expectedBanner {
			t.Errorf("expected banner %q, got %q", expectedBanner, receivedBanner)
			return
		}

		updatedBanner := "Updated banner\n"
		if err := os.WriteFile(bannerFile, []byte(updatedBanner), 0600); err != nil {
			t.Errorf("failed to update banner file: %v", err)
			return
		}

		if err := waitFor(30*time.Second, func() error {
			receivedBanner = ""
			if _, err := connectToServer(t, cli, bastionSrv); err != nil {
				return err
			}
			if receivedBanner != updatedBanner {
				return fmt.Errorf("expected banner %q, got %q", updatedBanner, receivedBanner)
			}
			return nil
		}); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("health_server", func(t *testing.T) {
		cliAuthorized, cliAuthorizedPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cliAuthorized.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedAuthorizedKeyStr := marshalAuthorizedKey(cliAuthorizedPublicKey)

		cliUnauthorized, _, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cliUnauthorized.User = fmt.Sprintf("alice@%s", mockAddr)

		unknownHostMockSrv, err := setupMockServer(t)
		if err != nil {
			t.Errorf("failed to setup unknown host mock server: %v", err)
			return
		}
		unknownHostMockAddr := unknownHostMockSrv.Address()

		mismatchMockSrv, err := setupMockServer(t)
		if err != nil {
			t.Errorf("failed to setup mismatch mock server: %v", err)
			return
		}
		mismatchMockAddr := mismatchMockSrv.Address()

		denyMockSrv, err := setupMockServer(t, mock.WithPublicKeyCallback(mock.AlwaysDenyPublicKey))
		if err != nil {
			t.Errorf("failed to setup deny mock server: %v", err)
			return
		}
		denyMockAddr := denyMockSrv.Address()
		denyMockAuthorizedKeyStr := marshalAuthorizedKey(denyMockSrv.Signer().PublicKey())

		t.Run("healthz", func(t *testing.T) {
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
				fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}

			healthSrv, err := setupHealthServer(t, bastionSrv)
			if err != nil {
				t.Errorf("failed to setup health server: %v", err)
				return
			}
			healthURL := fmt.Sprintf("http://%s", healthSrv.Address())

			resp, err := http.Get(healthURL + "/healthz")
			if err != nil {
				t.Errorf("failed to request /healthz: %v", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.StatusCode)
				return
			}

			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "ok") {
				t.Errorf("expected body to contain 'ok', got %q", body)
				return
			}
		})

		t.Run("readyz", func(t *testing.T) {
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
				fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}

			healthSrv, err := setupHealthServer(t, bastionSrv)
			if err != nil {
				t.Errorf("failed to setup health server: %v", err)
				return
			}
			healthURL := fmt.Sprintf("http://%s", healthSrv.Address())

			resp, err := http.Get(healthURL + "/readyz")
			if err != nil {
				t.Errorf("failed to request /readyz: %v", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.StatusCode)
				return
			}

			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "ok") {
				t.Errorf("expected body to contain 'ok', got %q", body)
				return
			}
		})

		t.Run("metrics", func(t *testing.T) {
			t.Run("connections", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				// Create 5 connections, then close
				for range 5 {
					bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}
					_ = bastionConn.Close()
				}

				// Create 3 connections, keep open
				for range 3 {
					_, err := connectToServer(t, cliAuthorized, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.ConnectionsActive.Load(); count != 3 {
						return fmt.Errorf("expected cardea_connections_active 3, got %d", count)
					}
					if count := metrics.ConnectionsTotal.Load(); count != 8 {
						return fmt.Errorf("expected cardea_connections_total 8, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("sessions", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				// Create 5 sessions, then close
				for range 5 {
					bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}

					session, err := bastionConn.NewSession()
					if err != nil {
						t.Errorf("failed to create session: %v", err)
						return
					}
					_ = session.Close()
					_ = bastionConn.Close()
				}

				// Create 3 sessions, keep open
				for range 3 {
					bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}

					session, err := bastionConn.NewSession()
					if err != nil {
						t.Errorf("failed to create session: %v", err)
						return
					}
					defer func() { _ = session.Close() }()
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.SessionsActive.Load(); count != 3 {
						return fmt.Errorf("expected cardea_sessions_active 3, got %d", count)
					}
					if count := metrics.SessionsTotal.Load(); count != 8 {
						return fmt.Errorf("expected cardea_sessions_total 8, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("port_forwards", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*",permitopen="*:*",permitlisten="*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				// Create 5 local port forwards: 3 closed, 2 kept open
				for i := range 5 {
					bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}

					dialConn, err := bastionConn.Dial("tcp", mockAddr.String())
					if err != nil {
						t.Errorf("failed to open local port forward: %v", err)
						return
					}

					if i < 3 {
						_ = dialConn.Close()
						_ = bastionConn.Close()
					} else {
						defer func() { _ = dialConn.Close() }()
					}
				}

				// Create 3 remote port forwards with sessions: 2 closed, 1 kept open
				for i := range 3 {
					bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}

					session, err := bastionConn.NewSession()
					if err != nil {
						t.Errorf("failed to create session: %v", err)
						return
					}

					listener, err := bastionConn.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						_ = session.Close()
						t.Errorf("failed to request remote port forward: %v", err)
						return
					}

					go func() {
						time.Sleep(50 * time.Millisecond)
						conn, err := net.Dial("tcp", listener.Addr().String())
						if err != nil {
							return
						}
						defer func() { _ = conn.Close() }()
						_, _ = io.Copy(conn, conn)
					}()

					acceptedConn, err := listener.Accept()
					if err != nil {
						_ = listener.Close()
						_ = session.Close()
						t.Errorf("failed to accept connection: %v", err)
						return
					}

					_, _ = acceptedConn.Write([]byte{0})
					_, _ = acceptedConn.Read(make([]byte, 1))

					if i < 2 {
						_ = acceptedConn.Close()
						_ = listener.Close()
						_ = session.Close()
						_ = bastionConn.Close()
					} else {
						defer func() {
							_ = acceptedConn.Close()
							_ = listener.Close()
							_ = session.Close()
						}()
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.PortForwardsLocalActive.Load(); count != 2 {
						return fmt.Errorf("expected cardea_port_forwards_local_active 2, got %d", count)
					}
					if count := metrics.PortForwardsLocalTotal.Load(); count != 5 {
						return fmt.Errorf("expected cardea_port_forwards_local_total 5, got %d", count)
					}
					if count := metrics.PortForwardsRemoteActive.Load(); count != 1 {
						return fmt.Errorf("expected cardea_port_forwards_remote_active 1, got %d", count)
					}
					if count := metrics.PortForwardsRemoteTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_port_forwards_remote_total 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("transferred_bytes", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv)
				if err != nil {
					t.Errorf("failed to connect to server: %v", err)
					return
				}

				session, err := bastionConn.NewSession()
				if err != nil {
					t.Errorf("failed to create session: %v", err)
					return
				}
				defer func() { _ = session.Close() }()

				if output, err := session.Output("echo Hello, World!"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if expectedOutput := "Hello, World!\r\n"; string(output) != expectedOutput {
					t.Errorf("unexpected output: got %q, want %q", string(output), expectedOutput)
					return
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.ReceivedBytesTotal.Load(); count == 0 {
						return fmt.Errorf("expected cardea_received_bytes_total > 0, got %d", count)
					}
					if count := metrics.SentBytesTotal.Load(); count == 0 {
						return fmt.Errorf("expected cardea_sent_bytes_total > 0, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_successes", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				for range 5 {
					bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv)
					if err != nil {
						t.Errorf("failed to connect to server: %v", err)
						return
					}
					_ = bastionConn.Close()
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.AuthSuccessesTotal.Load(); count != 5 {
						return fmt.Errorf("expected cardea_auth_successes_total 5, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_failures_unknown_key", func(t *testing.T) {
				rateLimitMax := 7
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
					func(srv *Server) error {
						srv.config.RateLimitMax = rateLimitMax
						srv.config.RateLimitTime = 1 * time.Hour
						return nil
					},
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				for range rateLimitMax {
					if _, err := connectToServer(t, cliUnauthorized, bastionSrv); err == nil {
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					// #nosec G115
					if count := metrics.AuthFailuresUnknownKeyTotal.Load(); int(count) != rateLimitMax {
						return fmt.Errorf("expected cardea_auth_failures_total{reason=\"unknown_key\"} %d, got %d", rateLimitMax, count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_failures_denied_start_time", func(t *testing.T) {
				futureTime := time.Now().Add(24*time.Hour).UTC().Format("20060102150405") + "Z"
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`start-time="%s",permitconnect="alice@*:*" %s`, futureTime, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				for range 3 {
					if bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv); err == nil {
						_ = bastionConn.Close()
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.AuthFailuresDeniedStartTimeTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_auth_failures_total{reason=\"denied_start_time\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_failures_denied_expiry_time", func(t *testing.T) {
				expiredTime := time.Now().Add(-24*time.Hour).UTC().Format("20060102150405") + "Z"
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`expiry-time="%s",permitconnect="alice@*:*" %s`, expiredTime, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				for range 3 {
					if bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv); err == nil {
						_ = bastionConn.Close()
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.AuthFailuresDeniedExpiryTimeTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_auth_failures_total{reason=\"denied_expiry_time\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_failures_denied_time_window", func(t *testing.T) {
				excludedHour := (time.Now().Hour() + 12) % 24
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`time-window="hour:%d",permitconnect="alice@*:*" %s`, excludedHour, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				for range 3 {
					if bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv); err == nil {
						_ = bastionConn.Close()
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.AuthFailuresDeniedTimeWindowTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_auth_failures_total{reason=\"denied_time_window\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_failures_denied_source", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`from="192.168.0.0/16",permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				for range 3 {
					if bastionConn, err := connectToServer(t, cliAuthorized, bastionSrv); err == nil {
						_ = bastionConn.Close()
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.AuthFailuresDeniedSourceTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_auth_failures_total{reason=\"denied_source\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_failures_denied_backend", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				cliUnauthorizedTarget := *cliAuthorized
				cliUnauthorizedTarget.User = fmt.Sprintf("bob@%s", mockAddr)
				for range 3 {
					if bastionConn, err := connectToServer(t, &cliUnauthorizedTarget, bastionSrv); err == nil {
						_ = bastionConn.Close()
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.AuthFailuresDeniedBackendTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_auth_failures_total{reason=\"denied_backend\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("auth_failures_invalid_backend", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				cliInvalidFormat := *cliAuthorized
				cliInvalidFormat.User = "invalidformat"
				for range 3 {
					if bastionConn, err := connectToServer(t, &cliInvalidFormat, bastionSrv); err == nil {
						_ = bastionConn.Close()
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.AuthFailuresInvalidBackendTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_auth_failures_total{reason=\"invalid_backend\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("rate_limit_rejections", func(t *testing.T) {
				rateLimitMax := 7
				rateLimitTime := 1 * time.Hour
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
					func(srv *Server) error {
						srv.config.RateLimitMax = rateLimitMax
						srv.config.RateLimitTime = rateLimitTime
						return nil
					},
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				for range rateLimitMax {
					if _, err := connectToServer(t, cliUnauthorized, bastionSrv); err == nil {
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if bastionSrv.rateLimit.Allow("127.0.0.1") && bastionSrv.rateLimit.Allow("::1") {
						return fmt.Errorf("rate limiter should block localhost")
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}

				for range 5 {
					if _, err := connectToServer(t, cliUnauthorized, bastionSrv); err == nil {
						t.Error("expected authentication to fail, but it succeeded")
						return
					}
				}

				if err := waitFor(2*time.Second, func() error {
					// #nosec G115
					if count := metrics.RateLimitRejectionsTotal.Load(); int(count) != 5 {
						return fmt.Errorf("expected cardea_rate_limit_rejections_total 5, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("backend_errors_refused", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				cliBadBackend := *cliAuthorized
				cliBadBackend.User = "alice@127.0.0.1:9"
				for range 5 {
					if bastionConn, err := connectToServer(t, &cliBadBackend, bastionSrv); err == nil {
						_ = bastionConn.Close()
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.BackendErrorsRefusedTotal.Load(); count != 5 {
						return fmt.Errorf("expected cardea_backend_errors_total{reason=\"refused\"} 5, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("backend_errors_failed_auth", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", denyMockAddr, denyMockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				cliDenyHost := *cliAuthorized
				cliDenyHost.User = fmt.Sprintf("alice@%s", denyMockAddr)
				for range 3 {
					if bastionConn, err := connectToServer(t, &cliDenyHost, bastionSrv); err == nil {
						_ = bastionConn.Close()
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.BackendErrorsFailedAuthTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_backend_errors_total{reason=\"failed_auth\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("backend_errors_unknown_host", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					"",
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				cliUnknownHost := *cliAuthorized
				cliUnknownHost.User = fmt.Sprintf("alice@%s", unknownHostMockAddr)
				for range 3 {
					if bastionConn, err := connectToServer(t, &cliUnknownHost, bastionSrv); err == nil {
						_ = bastionConn.Close()
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.BackendErrorsUnknownHostTotal.Load(); count != 3 {
						return fmt.Errorf("expected cardea_backend_errors_total{reason=\"unknown_host\"} 3, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("backend_errors_mismatched_hostkey", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mismatchMockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}
				metrics := bastionSrv.Metrics()

				cliMismatchHost := *cliAuthorized
				cliMismatchHost.User = fmt.Sprintf("alice@%s", mismatchMockAddr)
				for range 2 {
					if bastionConn, err := connectToServer(t, &cliMismatchHost, bastionSrv); err == nil {
						_ = bastionConn.Close()
					}
				}

				if err := waitFor(2*time.Second, func() error {
					if count := metrics.BackendErrorsMismatchedHostkeyTotal.Load(); count != 2 {
						return fmt.Errorf("expected cardea_backend_errors_total{reason=\"mismatched_hostkey\"} 2, got %d", count)
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			})

			t.Run("output_format", func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@*:*" %s`, cliAuthorizedAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				healthSrv, err := setupHealthServer(t, bastionSrv)
				if err != nil {
					t.Errorf("failed to setup health server: %v", err)
					return
				}
				healthURL := fmt.Sprintf("http://%s", healthSrv.Address())

				req, err := http.NewRequest("GET", healthURL+"/metrics", nil)
				if err != nil {
					t.Errorf("failed to create request: %v", err)
					return
				}
				req.Header.Set("Accept", "application/openmetrics-text; version=1.0.0")

				resp, err := http.DefaultClient.Do(req) // #nosec G704
				if err != nil {
					t.Errorf("failed to request /metrics: %v", err)
					return
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusOK {
					t.Errorf("expected status 200, got %d", resp.StatusCode)
					return
				}
				if val := resp.Header.Get("Content-Type"); !strings.Contains(val, "application/openmetrics-text") {
					t.Errorf("expected Content-Type application/openmetrics-text, got %q", val)
					return
				}

				body, _ := io.ReadAll(resp.Body)
				metrics := []string{
					"go_info",
					"go_goroutines",
					"go_threads",
					"go_sched_gomaxprocs_threads",
					"go_gc_cycles_automatic_gc_cycles_total",
					"go_gc_cycles_forced_gc_cycles_total",
					"go_gc_cycles_total_gc_cycles_total",
					"go_gc_gogc_percent",
					"go_gc_gomemlimit_bytes",
					"go_gc_heap_live_bytes",
					"go_gc_heap_tiny_allocs_objects_total",
					"go_gc_limiter_last_enabled_gc_cycle",
					"go_gc_scan_globals_bytes",
					"go_gc_scan_heap_bytes",
					"go_gc_scan_stack_bytes",
					"go_gc_scan_total_bytes",
					"go_gc_stack_starting_size_bytes",
					"go_sync_mutex_wait_total_seconds_total",
					"cardea_build_info",
					"cardea_start_time_seconds",
					"cardea_connections_active",
					"cardea_connections_total",
					"cardea_sessions_active",
					"cardea_sessions_total",
					"cardea_port_forwards_local_active",
					"cardea_port_forwards_local_total",
					"cardea_port_forwards_remote_active",
					"cardea_port_forwards_remote_total",
					"cardea_received_bytes_total",
					"cardea_sent_bytes_total",
					"cardea_auth_successes_total",
					"cardea_auth_failures_total{reason=\"unknown_key\"}",
					"cardea_auth_failures_total{reason=\"denied_start_time\"}",
					"cardea_auth_failures_total{reason=\"denied_expiry_time\"}",
					"cardea_auth_failures_total{reason=\"denied_source\"}",
					"cardea_auth_failures_total{reason=\"denied_backend\"}",
					"cardea_auth_failures_total{reason=\"invalid_backend\"}",
					"cardea_rate_limit_rejections_total",
					"cardea_backend_errors_total{reason=\"timeout\"}",
					"cardea_backend_errors_total{reason=\"refused\"}",
					"cardea_backend_errors_total{reason=\"failed_auth\"}",
					"cardea_backend_errors_total{reason=\"unknown_host\"}",
					"cardea_backend_errors_total{reason=\"mismatched_hostkey\"}",
					"cardea_backend_errors_total{reason=\"other\"}",
				}
				for _, metric := range metrics {
					if !strings.Contains(string(body), metric) {
						t.Errorf("expected metric %s to exist, got:\n%s", metric, body)
						return
					}
				}

				if !strings.Contains(string(body), "# EOF") {
					t.Errorf("expected # EOF marker, got:\n%s", body)
					return
				}
			})
		})
	})
}

func FuzzBastionSSHServerUser(f *testing.F) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	cli, cliPublicKey, err := setupClient(f)
	if err != nil {
		f.Errorf("failed to setup client: %v", err)
		return
	}
	cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

	bastionSrv, err := setupBastionServer(f,
		fmt.Sprintf(`permitconnect="*@127.0.0.1/8:0,*@[::1/128]:0" %s`, cliAuthorizedKeyStr),
		"",
	)
	if err != nil {
		f.Errorf("failed to setup bastion server: %v", err)
		return
	}
	bastionAddr := bastionSrv.Address()

	f.Add("user@127.0.0.1")
	f.Add("user@127.0.0.1:22")
	f.Add("user+127.0.0.1")
	f.Add("user+127.0.0.1+22")
	f.Add("user@[::1]")
	f.Add("user@[::1]:22")
	f.Add("user+[::1]")
	f.Add("user+[::1]+22")
	f.Add("user@example.com")
	f.Add("user with spaces@127.0.0.1")
	f.Add("user\x00@\x00127.0.0.1")
	f.Add("user\n@\n127.0.0.1")
	f.Add(".")
	f.Add("..")
	f.Add("/")
	f.Add("\x00")
	f.Add("\r\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, user string) {
		cli := *cli
		cli.User = user

		bastionConn, err := ssh.Dial("tcp", bastionAddr.String(), &cli)
		if err != nil {
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			_ = bastionConn.Close()
			return
		}

		_ = session.Close()
		_ = bastionConn.Close()
	})
}

func FuzzBastionSSHServerRequest(f *testing.F) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockSrv, err := setupMockServer(f)
	if err != nil {
		f.Errorf("failed to setup mock server: %v", err)
		return
	}
	mockAddr := mockSrv.Address()
	mockAuthorizedKeyStr := marshalAuthorizedKey(mockSrv.Signer().PublicKey())

	cli, cliPublicKey, err := setupClient(f)
	if err != nil {
		f.Errorf("failed to setup client: %v", err)
		return
	}
	cli.User = fmt.Sprintf("alice@%s", mockAddr)
	cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

	bastionSrv, err := setupBastionServer(f,
		fmt.Sprintf(`permitconnect="*@127.0.0.1/8:*,*@[::1/128]:*" %s`, cliAuthorizedKeyStr),
		fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
	)
	if err != nil {
		f.Errorf("failed to setup bastion server: %v", err)
		return
	}

	bastionConn, err := connectToServer(f, cli, bastionSrv)
	if err != nil {
		f.Errorf("failed to connect to server: %v", err)
		return
	}

	f.Add("pty-req", []byte("\x00\x00\x00\x05xterm\x00\x00\x00P\x00\x00\x00\x18\x00\x00\x02\x80\x00\x00\x01\xe0\x00\x00\x00\x105\x00\x00\x00\x01\x80\x00\x008@\x81\x00\x008@\x00"))
	f.Add("window-change", []byte("\x00\x00\x00x\x00\x00\x00\x1e\x00\x00\x03\xc0\x00\x00\x01\xe0"))
	f.Add("env", []byte("\x00\x00\x00\x03FOO\x00\x00\x00\x03BAR"))
	f.Add("exec", []byte("\x00\x00\x00\x06exit 0"))
	f.Add("shell", []byte{})
	f.Add("subsystem", []byte("\x00\x00\x00\x04sftp"))
	f.Add("unsupported", []byte("\x00"))
	f.Add("", []byte{})

	f.Fuzz(func(t *testing.T, reqType string, payload []byte) {
		session, err := bastionConn.NewSession()
		if err != nil {
			return
		}

		if ok, _ := session.SendRequest(reqType, true, payload); ok {
			_ = session.Setenv("FOO", "BAR")
		}

		_ = session.Close()
	})
}

func BenchmarkBastionSSHServerConnection(b *testing.B) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockSrv, err := setupMockServer(b)
	if err != nil {
		b.Errorf("failed to setup mock server: %v", err)
		return
	}
	mockAddr := mockSrv.Address()
	mockAuthorizedKeyStr := marshalAuthorizedKey(mockSrv.Signer().PublicKey())

	cli, cliPublicKey, err := setupClient(b)
	if err != nil {
		b.Errorf("failed to setup client: %v", err)
		return
	}
	cli.User = fmt.Sprintf("alice@%s", mockAddr)
	cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

	bastionSrv, err := setupBastionServer(b,
		fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
		fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
	)
	if err != nil {
		b.Errorf("failed to setup bastion server: %v", err)
		return
	}
	bastionAddr := bastionSrv.Address()

	b.ResetTimer()

	for b.Loop() {
		bastionConn, err := ssh.Dial("tcp", bastionAddr.String(), cli)
		if err != nil {
			b.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			b.Errorf("failed to create session: %v", err)
			_ = bastionConn.Close()
			return
		}

		if _, err = session.Output("echo Hello, World!"); err != nil {
			_ = session.Close()
			_ = bastionConn.Close()
			b.Errorf("failed to execute command: %v", err)
			return
		}

		_ = session.Close()
		_ = bastionConn.Close()
	}
}

func BenchmarkBastionSSHServerConnectionParallel(b *testing.B) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockSrv, err := setupMockServer(b)
	if err != nil {
		b.Errorf("failed to setup mock server: %v", err)
		return
	}
	mockAddr := mockSrv.Address()
	mockAuthorizedKeyStr := marshalAuthorizedKey(mockSrv.Signer().PublicKey())

	cli, cliPublicKey, err := setupClient(b)
	if err != nil {
		b.Errorf("failed to setup client: %v", err)
		return
	}
	cli.User = fmt.Sprintf("alice@%s", mockAddr)
	cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

	bastionSrv, err := setupBastionServer(b,
		fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
		fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
	)
	if err != nil {
		b.Errorf("failed to setup bastion server: %v", err)
		return
	}
	bastionAddr := bastionSrv.Address()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bastionConn, err := ssh.Dial("tcp", bastionAddr.String(), cli)
			if err != nil {
				b.Errorf("failed to connect to server: %v", err)
				return
			}

			session, err := bastionConn.NewSession()
			if err != nil {
				b.Errorf("failed to create session: %v", err)
				_ = bastionConn.Close()
				return
			}

			if _, err = session.Output("echo Hello, World!"); err != nil {
				_ = session.Close()
				_ = bastionConn.Close()
				b.Errorf("failed to execute command: %v", err)
				return
			}

			_ = session.Close()
			_ = bastionConn.Close()
		}
	})
}
