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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/config"
	"github.com/hectorm/cardea/internal/server/mock"
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

func waitForInitialPrompt(t testing.TB, stdout io.Reader) error {
	t.Helper()

	if prompt, err := readUntil(stdout, "mock$", 100); err != nil {
		return err
	} else if !strings.Contains(prompt, "mock$") {
		return fmt.Errorf("expected prompt to contain '%s', got: %q", "mock$", prompt)
	}

	return nil
}

func waitForSessionClose(t testing.TB, session *ssh.Session, timeout time.Duration) error {
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

	response, err := readUntil(stdout, "mock$", 200)
	if err != nil {
		return "", err
	}

	return response, nil
}

func readUntil(stdout io.Reader, expected string, maxBytes int) (string, error) {
	result := make([]byte, 0, maxBytes)
	buf := make([]byte, 1)
	timeout := time.After(2 * time.Second)

	for len(result) < maxBytes {
		readChan := make(chan struct {
			data byte
			err  error
		}, 1)

		go func() {
			n, err := stdout.Read(buf)
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
		case <-timeout:
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

		for _, test := range tests {
			t.Run(fmt.Sprintf("%s->%s", test.user, test.pattern), func(t *testing.T) {
				cli.User = test.user

				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="%s" %s`, test.pattern, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				if test.ok {
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

		for _, test := range tests {
			t.Run(fmt.Sprintf("%s->%s", test.target, test.pattern), func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@%s",permitopen="%s" %s`, mockAddr, test.pattern, cliAuthorizedKeyStr),
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

				if test.ok {
					targetConn, err := bastionConn.Dial("tcp", test.target)
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
					if _, err = bastionConn.Dial("tcp", test.target); err == nil {
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

		for _, test := range tests {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to get free port: %v", err)
			}
			bindAddr := listener.Addr().String()
			_ = listener.Close()

			t.Run(fmt.Sprintf("%s->%s", bindAddr, test.pattern), func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@%s",permitlisten="%s" %s`, mockAddr, test.pattern, cliAuthorizedKeyStr),
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

				if test.ok {
					listener, err := bastionConn.Listen("tcp", bindAddr)
					if err != nil {
						t.Errorf("expected listen to succeed, but it failed: %v", err)
						return
					}
					defer func() { _ = listener.Close() }()

					go func() {
						conn, err := net.Dial("tcp", listener.Addr().String())
						if err != nil {
							return
						}
						defer func() { _ = conn.Close() }()
						_, _ = io.Copy(conn, conn)
					}()

					conn, err := listener.Accept()
					if err != nil {
						t.Errorf("failed to accept connection: %v", err)
						return
					}
					defer func() { _ = conn.Close() }()

					testData := []byte("Hello, World!")
					if _, err := conn.Write(testData); err != nil {
						t.Errorf("failed to write data: %v", err)
						return
					}

					buf := make([]byte, len(testData))
					if _, err := io.ReadFull(conn, buf); err != nil {
						t.Errorf("failed to read data: %v", err)
						return
					}

					if string(buf) != string(testData) {
						t.Errorf("expected %q, got %q", testData, buf)
						return
					}
				} else {
					if listener, err := bastionConn.Listen("tcp", bindAddr); err == nil {
						_ = listener.Close()
						t.Error("expected listen to fail, but it succeeded")
						return
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

			time.Sleep(250 * time.Millisecond)

			files, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz"))
			if err != nil {
				t.Errorf("failed to glob for recordings: %v", err)
				return
			}

			if len(files) == 1 {
				if content, err := readGzipFile(files[0]); err != nil {
					t.Errorf("failed to read recording: %v", err)
					return
				} else if !strings.Contains(string(content), "Hello, World!") {
					t.Errorf("recording does not contain expected output: %q", string(content))
					return
				}
			} else {
				t.Errorf("expected 1 recording, got %d", len(files))
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

			time.Sleep(250 * time.Millisecond)

			files, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz"))
			if err != nil {
				t.Errorf("failed to glob for recordings: %v", err)
				return
			}

			if len(files) == 1 {
				if content, err := readGzipFile(files[0]); err != nil {
					t.Errorf("failed to read recording: %v", err)
					return
				} else if strings.Contains(string(content), "mock: rsync: NOOP") {
					t.Errorf("recording does not contain expected output: %q", string(content))
					return
				}
			} else {
				t.Errorf("expected 1 recording, got %d", len(files))
				return
			}
		})

		t.Run("shell", func(t *testing.T) {
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

			session, stdin, stdout, err := createShellSession(t, bastionConn)
			if err != nil {
				t.Errorf("failed to create shell session: %v", err)
				return
			}

			if err := waitForInitialPrompt(t, stdout); err != nil {
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

				if response, err := readUntil(stdout, "mock$", 300); err != nil {
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

				time.Sleep(50 * time.Millisecond)

				if response, err := executeShellCommand(t, stdin, stdout, "printenv LINES"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if !strings.Contains(response, "30") {
					t.Errorf("expected LINES to be 30 after window change, got response: %q", response)
					return
				}

				if response, err := executeShellCommand(t, stdin, stdout, "printenv COLUMNS"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if !strings.Contains(response, "120") {
					t.Errorf("expected COLUMNS to be 120 after window change, got response: %q", response)
					return
				}
			})

			t.Run("exit", func(t *testing.T) {
				if _, err := stdin.Write([]byte("exit 0\r")); err != nil {
					t.Errorf("failed to write exit command: %v", err)
					return
				}

				if err := waitForSessionClose(t, session, 1*time.Second); err != nil {
					t.Errorf("session did not close as expected: %v", err)
					return
				}
			})

			time.Sleep(250 * time.Millisecond)

			files, err := filepath.Glob(filepath.Join(recordingsDir, "*.cast.gz"))
			if err != nil {
				t.Errorf("failed to glob for recordings: %v", err)
				return
			}

			if len(files) == 1 {
				if content, err := readGzipFile(files[0]); err != nil {
					t.Errorf("failed to read recording: %v", err)
					return
				} else if !strings.Contains(string(content), "Hello, World!") ||
					!strings.Contains(string(content), "hello") ||
					!strings.Contains(string(content), "logout") {
					t.Errorf("recording does not contain expected output: %q", string(content))
					return
				}
			} else {
				t.Errorf("expected 1 recording, got %d", len(files))
				return
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
		time.Sleep(50 * time.Millisecond)

		_, err = connectToServer(t, cli, bastionSrv)
		if err != nil {
			t.Errorf("expected third connection to succeed, but got error: %v", err)
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

		time.Sleep(50 * time.Millisecond)

		if _, err := connectToServer(t, cliGood, bastionSrv); err == nil {
			t.Error("expected authentication to fail due to rate limit, but it succeeded")
			return
		}

		if bastionSrv.rateLimit != nil {
			bastionSrv.rateLimit.Reset("127.0.0.1")
			bastionSrv.rateLimit.Reset("::1")
		}

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

		for _, test := range tests {
			t.Run(test.channel, func(t *testing.T) {
				if _, _, err := bastionConn.OpenChannel(test.channel, []byte("invalid")); err == nil {
					t.Errorf("expected malformed %s channel to fail, but it succeeded", test.channel)
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

		for _, test := range tests {
			t.Run(test.req, func(t *testing.T) {
				if ok, _ := session.SendRequest(test.req, test.wantReply, []byte("invalid")); ok {
					t.Errorf("expected malformed %s request to fail, but it succeeded", test.req)
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
		cli.User = "alice@127.0.0.1:1"
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@127.0.0.1:1" %s`, cliAuthorizedKeyStr),
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
		cliPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
		if err != nil {
			t.Errorf("failed to parse authorized key: %v", err)
			return
		}
		cliPublicKeyStr := string(cliPublicKey.Marshal())
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			content  string
			expected map[string][]*AuthorizedKeyOptions
		}{
			{
				content: fmt.Sprintf(`
					#define PUBLIC_KEY %s
					invalid-key
					# Line comment 1
					permitconnect="*@192.168.0.0/16:22",permitconnect="*@172.16.0.0/12:22",permitopen="*:80,*:443",no-port-forwarding PUBLIC_KEY
					# Line comment 2
					permitconnect="*@10.0.0.0/8:22,*@10.0.0.0/8:2222",permitopen="*:80,*:443",permitopen="*:8080",permitopen="*:8880",command="nologin",no-pty PUBLIC_KEY
					# Line comment 3
				`, cliAuthorizedKeyStr),
				expected: map[string][]*AuthorizedKeyOptions{
					cliPublicKeyStr: {
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "192.168.0.0/16", Port: "22"},
								{User: "*", Host: "172.16.0.0/12", Port: "22"},
							},
							PermitOpens: []PermitOpen{
								{Host: "*", Port: "80"},
								{Host: "*", Port: "443"},
							},
							Command:          "",
							NoPortForwarding: true,
							NoPty:            false,
						},
						{
							PermitConnects: []PermitConnect{
								{User: "*", Host: "10.0.0.0/8", Port: "22"},
								{User: "*", Host: "10.0.0.0/8", Port: "2222"},
							},
							PermitOpens: []PermitOpen{
								{Host: "*", Port: "80"},
								{Host: "*", Port: "443"},
								{Host: "*", Port: "8080"},
								{Host: "*", Port: "8880"},
							},
							Command:          "nologin",
							NoPortForwarding: false,
							NoPty:            true,
						},
					},
				},
			},
			{
				content:  `invalid-key`,
				expected: map[string][]*AuthorizedKeyOptions{},
			},
			{
				content:  cliAuthorizedKeyStr,
				expected: map[string][]*AuthorizedKeyOptions{},
			},
			{
				content:  fmt.Sprintf(`permitconnect="invalid" %s`, cliAuthorizedKeyStr),
				expected: map[string][]*AuthorizedKeyOptions{},
			},
			{
				content:  fmt.Sprintf(`permitconnect="alice@127.0.0.1:22",permitopen="invalid" %s`, cliAuthorizedKeyStr),
				expected: map[string][]*AuthorizedKeyOptions{},
			},
		}

		for n, test := range tests {
			t.Run(strconv.Itoa(n), func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t, test.content, "")
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				if len(bastionSrv.authKeysDB) != len(test.expected) {
					t.Errorf("expected %d keys in authorized_keys db, got %d", len(test.expected), len(bastionSrv.authKeysDB))
					return
				}
				for key, optsList := range bastionSrv.authKeysDB {
					if expectedOptsList, ok := test.expected[key]; !ok {
						t.Error("expected key to be in authorized_keys db, but it was not found")
						return
					} else if len(optsList) != len(expectedOptsList) {
						t.Errorf("expected %d options for key, got %d", len(expectedOptsList), len(optsList))
						return
					} else {
						for i, opts := range optsList {
							expectedOpts := expectedOptsList[i]
							if opts.PermitConnects == nil || len(opts.PermitConnects) != len(expectedOpts.PermitConnects) {
								t.Errorf("expected %d permitconnects for key, got %d", len(expectedOpts.PermitConnects), len(opts.PermitConnects))
								return
							} else {
								for j, pc := range opts.PermitConnects {
									expectedPC := expectedOpts.PermitConnects[j]
									if pc.User != expectedPC.User || pc.Host != expectedPC.Host || pc.Port != expectedPC.Port {
										t.Errorf("expected permitconnect %v for key, got %v", expectedPC, pc)
										return
									}
								}
							}
							if opts.PermitOpens == nil || len(opts.PermitOpens) != len(expectedOpts.PermitOpens) {
								t.Errorf("expected %d permitopens for key, got %d", len(expectedOpts.PermitOpens), len(opts.PermitOpens))
								return
							} else {
								for j, po := range opts.PermitOpens {
									expectedPO := expectedOpts.PermitOpens[j]
									if po.Host != expectedPO.Host || po.Port != expectedPO.Port {
										t.Errorf("expected permitopen %v for key, got %v", expectedPO, po)
										return
									}
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
						}
					}
				}
			})
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

		ticker := time.NewTicker(50 * time.Millisecond)
		deadline := time.NewTimer(5 * time.Second)
		defer func() { ticker.Stop(); deadline.Stop() }()

		for {
			select {
			case <-ticker.C:
				if _, err := connectToServer(t, cli, bastionSrv); err == nil {
					return
				}
			case <-deadline.C:
				t.Error("expected connection to succeed after updating authorized_keys, but it failed")
				return
			}
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
