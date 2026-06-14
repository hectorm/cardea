package server

import (
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

func waitForCleanExit(timeout time.Duration, t testing.TB, session *ssh.Session) error {
	t.Helper()

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("session did not close within timeout")
	}
}

func waitForSessionEnd(timeout time.Duration, t testing.TB, session *ssh.Session) error {
	t.Helper()

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("session did not end within timeout")
	}
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

	t.Run("invalid_node_id", func(t *testing.T) {
		for _, nodeID := range []string{".", "..", ".hidden", "../parent", "-flag", "_underscore", strings.Repeat("a", 254)} {
			t.Run(nodeID, func(t *testing.T) {
				if _, err := setupBastionServer(t, "", "", func(srv *Server) error {
					srv.config.NodeID = nodeID
					return nil
				}); err == nil {
					t.Error("expected invalid node id to fail")
				}
			})
		}
	})

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

		t.Run("exec_no_pty", func(t *testing.T) {
			recordingsDir := t.TempDir()
			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
				fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				func(srv *Server) error {
					srv.config.RecordingsDir = recordingsDir
					srv.config.NodeID = "node-a_1.2"
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

			if err := session.Run("exit 42"); err == nil {
				t.Errorf("expected non-zero exit status")
				return
			} else if exitErr, ok := err.(*ssh.ExitError); !ok {
				t.Errorf("expected ExitError, got %T: %v", err, err)
				return
			} else if exitErr.ExitStatus() != 42 {
				t.Errorf("unexpected exit status: got %d, want 42", exitErr.ExitStatus())
				return
			}

			if err := waitFor(2*time.Second, func() error {
				files, err := filepath.Glob(filepath.Join(recordingsDir, "[0-9][0-9][0-9][0-9]", "[0-9][0-9]", "[0-9][0-9]", "*-node-a_1.2.cast.gz"))
				if err != nil {
					return fmt.Errorf("failed to glob for recordings: %w", err)
				}
				if len(files) != 1 {
					return fmt.Errorf("expected 1 recording, got %d", len(files))
				}
				tmpFiles, err := filepath.Glob(filepath.Join(recordingsDir, "[0-9][0-9][0-9][0-9]", "[0-9][0-9]", "[0-9][0-9]", "*.cast.gz.tmp"))
				if err != nil {
					return fmt.Errorf("failed to glob for temporary recordings: %w", err)
				}
				if len(tmpFiles) != 0 {
					return fmt.Errorf("expected no temporary recordings, got %d", len(tmpFiles))
				}

				content, err := readGzipFile(files[0])
				if err != nil {
					return fmt.Errorf("failed to read recording: %w", err)
				}
				if !strings.Contains(string(content), `"node_id":"node-a_1.2"`) {
					return fmt.Errorf("recording should contain node id in metadata: %q", string(content))
				}
				if !strings.Contains(string(content), fmt.Sprintf(`"backend_target":"alice@%s"`, mockAddr)) {
					return fmt.Errorf("recording should contain requested backend in metadata: %q", string(content))
				}
				if !strings.Contains(string(content), `"command":"exit 42"`) {
					return fmt.Errorf("recording should contain command in header: %q", string(content))
				}
				if !strings.Contains(string(content), "$ exit 42") {
					return fmt.Errorf("recording should contain command in output: %q", string(content))
				}
				if !strings.Contains(string(content), "[recording paused]") {
					return fmt.Errorf("recording should contain pause message: %q", string(content))
				}
				if !strings.Contains(string(content), `,"x","42"]`) {
					return fmt.Errorf("recording should contain exit event with status 42: %q", string(content))
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

				if err := waitForCleanExit(1*time.Second, t, session); err != nil {
					t.Errorf("session did not close as expected: %v", err)
					return
				}
			})

			if err := waitFor(2*time.Second, func() error {
				files, err := filepath.Glob(filepath.Join(recordingsDir, "[0-9][0-9][0-9][0-9]", "[0-9][0-9]", "[0-9][0-9]", "*.cast.gz"))
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
						files, err := filepath.Glob(filepath.Join(recordingsDir, "[0-9][0-9][0-9][0-9]", "[0-9][0-9]", "[0-9][0-9]", "*.cast.gz"))
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

		t.Run("sequence", func(t *testing.T) {
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

			for range 3 {
				session, err := bastionConn.NewSession()
				if err != nil {
					t.Errorf("failed to create session: %v", err)
					return
				}
				if _, err := session.Output("echo Hello, World!"); err != nil {
					_ = session.Close()
					t.Errorf("failed to execute command: %v", err)
					return
				}
				_ = session.Close()
			}

			if err := waitFor(2*time.Second, func() error {
				files, err := filepath.Glob(filepath.Join(recordingsDir, "[0-9][0-9][0-9][0-9]", "[0-9][0-9]", "[0-9][0-9]", "*.cast.gz"))
				if err != nil {
					return fmt.Errorf("failed to glob for recordings: %w", err)
				}
				if len(files) != 3 {
					return fmt.Errorf("expected 3 recordings, got %d", len(files))
				}

				for i := range 3 {
					seq := i + 1
					matches, err := filepath.Glob(filepath.Join(recordingsDir, "[0-9][0-9][0-9][0-9]", "[0-9][0-9]", "[0-9][0-9]", fmt.Sprintf("*_%d.cast.gz", seq)))
					if err != nil {
						return fmt.Errorf("failed to glob for recording with sequence %d: %w", seq, err)
					}
					if len(matches) != 1 {
						return fmt.Errorf("expected 1 recording with sequence %d, got %d", seq, len(matches))
					}
				}

				return nil
			}); err != nil {
				t.Error(err)
				return
			}
		})

		t.Run("rotation", func(t *testing.T) {
			t.Run("node_id", func(t *testing.T) {
				recordingsDir := t.TempDir()
				bastionSrv, err := setupBastionServer(t, "", "", func(srv *Server) error {
					srv.config.RecordingsDir = recordingsDir
					srv.config.NodeID = "node-a"
					srv.config.RecordingsRetentionTime = time.Hour
					srv.config.RecordingsMaxDiskUsage = "0"
					return nil
				})
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				retainedDay := time.Now()
				retainedDayPath := filepath.Join(retainedDay.Format("2006"), retainedDay.Format("01"), retainedDay.Format("02"))
				expiredDay := retainedDay.AddDate(0, 0, -3)
				expiredDayPath := filepath.Join(expiredDay.Format("2006"), expiredDay.Format("01"), expiredDay.Format("02"))
				files := []struct {
					name       string
					modTime    time.Time
					shouldStay bool
				}{
					{filepath.Join(expiredDayPath, "000000-aaaaaaaaaaaaaaaaaaaa-node-a.cast.gz"), expiredDay, false},
					{filepath.Join(expiredDayPath, "000001-bbbbbbbbbbbbbbbbbbbb-node-a.cast.gz.tmp"), expiredDay, false},
					{filepath.Join(expiredDayPath, "000002-cccccccccccccccccccc-node-b.cast.gz"), expiredDay, true},
					{filepath.Join(expiredDayPath, "000003-dddddddddddddddddddd-node-b.cast.gz.tmp"), expiredDay, true},
					{filepath.Join(expiredDayPath, "000006-gggggggggggggggggggg-b-node-a.cast.gz"), expiredDay, true},
					{filepath.Join(expiredDayPath, "000007-hhhhhhhhhhhhhhhhhhhh-b-node-a.cast.gz.tmp"), expiredDay, true},
					{filepath.Join(retainedDayPath, "000004-eeeeeeeeeeeeeeeeeeee-node-a.cast.gz"), retainedDay, true},
					{filepath.Join(retainedDayPath, "000005-ffffffffffffffffffff-node-a.cast.gz.tmp"), retainedDay, true},
				}
				for _, file := range files {
					path := filepath.Join(recordingsDir, file.name)
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Errorf("failed to create recording dir: %v", err)
						return
					}
					if err := os.WriteFile(path, []byte("recording"), 0600); err != nil {
						t.Errorf("failed to create test file %s: %v", file.name, err)
						return
					}
					if err := os.Chtimes(path, file.modTime, file.modTime); err != nil {
						t.Errorf("failed to set file time for %s: %v", file.name, err)
						return
					}
				}

				if ok, _, err := bastionSrv.diskCleanup(); err != nil {
					t.Errorf("failed to clean recordings: %v", err)
					return
				} else if !ok {
					t.Error("expected cleanup to succeed")
					return
				}

				for _, file := range files {
					path := filepath.Join(recordingsDir, file.name)
					if _, err := os.Stat(path); file.shouldStay && err != nil {
						t.Errorf("expected %s to remain: %v", file.name, err)
					} else if !file.shouldStay && !os.IsNotExist(err) {
						t.Errorf("expected %s to be removed", file.name)
					}
				}
			})

			t.Run("percentage", func(t *testing.T) {
				recordingsDir := t.TempDir()
				bastionSrv, err := setupBastionServer(t, "", "", func(srv *Server) error {
					srv.config.RecordingsDir = recordingsDir
					srv.config.RecordingsRetentionTime = 0
					srv.config.RecordingsMaxDiskUsage = "0.0001%"
					return nil
				})
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
					{"file3.cast.gz", 4 * time.Hour},
					{"file4.cast.gz", 5 * time.Hour},
					{"file5.cast.gz", 6 * time.Hour},
					{"file6.cast.gz.tmp", 7 * time.Hour},
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

				if currentFiles, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz")); err != nil {
					t.Errorf("failed to get current files: %v", err)
					return
				} else if len(currentFiles) != 5 {
					t.Errorf("expected 5 current files, got %d", len(currentFiles))
					return
				}

				if ok, deleted, err := bastionSrv.diskCleanup(); err != nil {
					t.Errorf("failed to clean recordings: %v", err)
					return
				} else if ok {
					t.Error("expected cleanup to report insufficient space")
					return
				} else if !deleted {
					t.Error("expected cleanup to delete recordings")
					return
				}

				if remainingFiles, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz")); err != nil {
					t.Errorf("failed to get remaining files: %v", err)
					return
				} else if len(remainingFiles) > 0 {
					t.Errorf("expected 0 remaining files, got %d", len(remainingFiles))
					return
				}
				if _, err := os.Stat(filepath.Join(recordingsDir, "file1.cast.gz")); !os.IsNotExist(err) {
					t.Error("expected recent recording to be removed")
					return
				}
				if _, err := os.Stat(filepath.Join(recordingsDir, "file5.cast.gz")); !os.IsNotExist(err) {
					t.Error("expected old recording to be removed")
					return
				}
				if remainingFiles, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz.tmp")); err != nil {
					t.Errorf("failed to get remaining temporary files: %v", err)
					return
				} else if len(remainingFiles) != 0 {
					t.Errorf("expected 0 remaining temporary files, got %d", len(remainingFiles))
					return
				}
			})

			t.Run("fixed_size", func(t *testing.T) {
				recordingsDir := t.TempDir()
				bastionSrv, err := setupBastionServer(t, "", "", func(srv *Server) error {
					srv.config.RecordingsDir = recordingsDir
					srv.config.RecordingsRetentionTime = 0
					srv.config.RecordingsMaxDiskUsage = "4KB"
					return nil
				})
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
					{"file3.cast.gz", 4 * time.Hour},
					{"file4.cast.gz", 5 * time.Hour},
					{"file5.cast.gz", 6 * time.Hour},
					{"file6.cast.gz.tmp", 7 * time.Hour},
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

				if currentFiles, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz")); err != nil {
					t.Errorf("failed to get current files: %v", err)
					return
				} else if len(currentFiles) != 5 {
					t.Errorf("expected 5 current files, got %d", len(currentFiles))
					return
				}

				if ok, deleted, err := bastionSrv.diskCleanup(); err != nil {
					t.Errorf("failed to clean recordings: %v", err)
					return
				} else if !ok {
					t.Error("expected cleanup to succeed")
					return
				} else if !deleted {
					t.Error("expected cleanup to delete recordings")
					return
				}

				if remainingFiles, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz")); err != nil {
					t.Errorf("failed to get remaining files: %v", err)
					return
				} else if len(remainingFiles) != 4 {
					t.Errorf("expected 4 remaining files, got %d", len(remainingFiles))
					return
				}
				if _, err := os.Stat(filepath.Join(recordingsDir, "file1.cast.gz")); err != nil {
					t.Errorf("expected recent recording to remain: %v", err)
					return
				}
				if _, err := os.Stat(filepath.Join(recordingsDir, "file5.cast.gz")); !os.IsNotExist(err) {
					t.Error("expected old recording to be removed")
					return
				}
				if remainingFiles, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz.tmp")); err != nil {
					t.Errorf("failed to get remaining temporary files: %v", err)
					return
				} else if len(remainingFiles) != 0 {
					t.Errorf("expected 0 remaining temporary files, got %d", len(remainingFiles))
					return
				}
			})
		})
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

		if count := bastionSrv.Metrics().ConnectionRejectionsTotal.Load(); count != 1 {
			t.Errorf("expected cardea_connection_rejections_total 1, got %d", count)
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

	t.Run("sessions_max", func(t *testing.T) {
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
				srv.config.SessionsMax = 1
				return nil
			},
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("expected connection to succeed, but got error: %v", err)
			return
		}

		session, err := bastionConn.NewSession()
		if err != nil {
			t.Errorf("expected first session to succeed, but got error: %v", err)
			return
		}

		_, err = bastionConn.NewSession()
		if err == nil {
			t.Error("expected second session to fail, but it succeeded")
			return
		}

		if count := bastionSrv.Metrics().SessionRejectionsTotal.Load(); count != 1 {
			t.Errorf("expected cardea_session_rejections_total 1, got %d", count)
			return
		}

		_ = session.Close()

		if err := waitFor(2*time.Second, func() error {
			session, err := bastionConn.NewSession()
			if err != nil {
				return fmt.Errorf("expected third session to succeed, but got error: %w", err)
			}
			_ = session.Close()
			return nil
		}); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("forwards_max", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",permitopen="*:*" %s`, mockAddr, cliAuthorizedKeyStr),
			fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			func(srv *Server) error {
				srv.config.ForwardsMax = 1
				return nil
			},
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		bastionConn, err := connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("expected connection to succeed, but got error: %v", err)
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
			t.Errorf("expected first forward to succeed, but got error: %v", err)
			return
		}
		go ssh.DiscardRequests(requests)

		_, _, err = bastionConn.OpenChannel("direct-tcpip", ssh.Marshal(payload))
		if err == nil {
			t.Error("expected second forward to fail, but it succeeded")
			return
		}

		if count := bastionSrv.Metrics().ForwardRejectionsTotal.Load(); count != 1 {
			t.Errorf("expected cardea_forward_rejections_total 1, got %d", count)
			return
		}

		_ = channel.Close()

		if err := waitFor(2*time.Second, func() error {
			channel, requests, err := bastionConn.OpenChannel("direct-tcpip", ssh.Marshal(payload))
			if err != nil {
				return fmt.Errorf("expected third forward to succeed, but got error: %w", err)
			}
			go ssh.DiscardRequests(requests)
			_ = channel.Close()
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

		if _, err := connectToServer(t, cliGood, bastionSrv); err == nil {
			t.Error("expected authentication to fail due to rate limit, but it succeeded")
			return
		}

		if _, err := connectToServer(t, cliGood, bastionSrv); err == nil {
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

	t.Run("direct_streamlocal_channel", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",permitsocketopen="*",command="nologin" %s`, mockAddr, cliAuthorizedKeyStr),
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
			SocketPath string
			Reserved0  string
			Reserved1  uint32
		}{
			SocketPath: "/tmp/test.sock",
			Reserved0:  "",
			Reserved1:  0,
		}

		channel, requests, err := bastionConn.OpenChannel("direct-streamlocal@openssh.com", ssh.Marshal(payload))
		if err != nil {
			t.Errorf("failed to open direct-streamlocal@openssh.com channel: %v", err)
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
			{channel: "direct-streamlocal@openssh.com"},
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
		)
		if err != nil {
			t.Errorf("failed to setup bastion server: %v", err)
			return
		}

		entries, ok := bastionSrv.authKeysDB[string(cliPublicKey.Marshal())]
		if !ok || len(entries) != 1 {
			t.Fatalf("expected client key with one entry in authorized_keys db, got %d entries", len(entries))
		}
		if pcs := entries[0].PermitConnects; len(pcs) != 1 || pcs[0].User != "alice" {
			t.Errorf("unexpected permitconnects: %+v", pcs)
		}

		if _, err := connectToServer(t, cli, bastionSrv); err != nil {
			t.Errorf("failed to connect to server: %v", err)
		}
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

	t.Run("authorized_keys_revalidation", func(t *testing.T) {
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

		session, _, stdout, err := createShellSession(t, bastionConn)
		if err != nil {
			t.Errorf("failed to create shell session: %v", err)
			return
		}

		if err := waitForInitialPrompt(2*time.Second, t, stdout); err != nil {
			t.Errorf("failed to wait for initial prompt: %v", err)
			return
		}

		if err := os.WriteFile(bastionCfg.AuthorizedKeysFile, []byte(""), 0600); err != nil {
			t.Error(err)
			return
		}

		if err := waitForSessionEnd(30*time.Second, t, session); err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("authorized_keys_revalidation_keeps_authorized", func(t *testing.T) {
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

		session, _, stdout, err := createShellSession(t, bastionConn)
		if err != nil {
			t.Errorf("failed to create shell session: %v", err)
			return
		}

		if err := waitForInitialPrompt(2*time.Second, t, stdout); err != nil {
			t.Errorf("failed to wait for initial prompt: %v", err)
			return
		}

		authorizedKeysContent := fmt.Sprintf(`permitconnect="alice@%s",permitconnect="carol@%s" %s`, mockAddr, mockAddr, cliAuthorizedKeyStr)
		if err := os.WriteFile(bastionCfg.AuthorizedKeysFile, []byte(authorizedKeysContent), 0600); err != nil {
			t.Error(err)
			return
		}

		if err := waitForSessionEnd(3*time.Second, t, session); err == nil {
			t.Error("session was closed after a benign authorized_keys change")
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
			type keyAlgo struct {
				name string
				key  crypto.PrivateKey
			}

			genKey := func(kind string) crypto.PrivateKey {
				t.Helper()
				switch kind {
				case ssh.KeyAlgoED25519:
					_, key, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatalf("failed to generate %s key: %v", kind, err)
					}
					return key
				case ssh.KeyAlgoECDSA256:
					key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						t.Fatalf("failed to generate %s key: %v", kind, err)
					}
					return key
				case ssh.KeyAlgoECDSA384:
					key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						t.Fatalf("failed to generate %s key: %v", kind, err)
					}
					return key
				case ssh.KeyAlgoECDSA521:
					key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
					if err != nil {
						t.Fatalf("failed to generate %s key: %v", kind, err)
					}
					return key
				case ssh.KeyAlgoRSA:
					key, err := rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						t.Fatalf("failed to generate %s key: %v", kind, err)
					}
					return key
				default:
					t.Fatalf("unsupported key type %q", kind)
					return nil
				}
			}

			keys := []keyAlgo{
				{ssh.KeyAlgoED25519, genKey(ssh.KeyAlgoED25519)},
				{ssh.KeyAlgoECDSA256, genKey(ssh.KeyAlgoECDSA256)},
				{ssh.KeyAlgoECDSA384, genKey(ssh.KeyAlgoECDSA384)},
				{ssh.KeyAlgoECDSA521, genKey(ssh.KeyAlgoECDSA521)},
				{ssh.KeyAlgoRSA, genKey(ssh.KeyAlgoRSA)},
			}

			for _, ca := range keys {
				for _, srv := range keys {
					t.Run(fmt.Sprintf("ca_%s/srv_%s", ca.name, srv.name), func(t *testing.T) {
						caSigner, err := ssh.NewSignerFromKey(ca.key)
						if err != nil {
							t.Errorf("failed to create CA signer: %v", err)
							return
						}
						caAuthorizedKeyStr := marshalAuthorizedKey(caSigner.PublicKey())

						srvSigner, err := ssh.NewSignerFromKey(srv.key)
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
					"cardea_node_info",
					"cardea_start_time_seconds",
					"cardea_connections_active",
					"cardea_connections_total",
					"cardea_connection_rejections_total",
					"cardea_sessions_active",
					"cardea_sessions_total",
					"cardea_session_rejections_total",
					"cardea_port_forwards_local_active",
					"cardea_port_forwards_local_total",
					"cardea_port_forwards_remote_active",
					"cardea_port_forwards_remote_total",
					"cardea_socket_forwards_local_active",
					"cardea_socket_forwards_local_total",
					"cardea_socket_forwards_remote_active",
					"cardea_socket_forwards_remote_total",
					"cardea_forward_rejections_total",
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
