//go:build unix

package server

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBastionSSHServerUnix(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockSrv, err := setupMockServer(t)
	if err != nil {
		t.Errorf("failed to setup mock server: %v", err)
		return
	}
	mockAddr := mockSrv.Address()
	mockAuthorizedKeyStr := marshalAuthorizedKey(mockSrv.Signer().PublicKey())

	t.Run("permitsocketopen", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		tests := []struct {
			pattern string
			target  string
			ok      bool
		}{
			{pattern: "/tmp/test.sock", target: "/tmp/test.sock", ok: true},
			{pattern: "/tmp/*.sock", target: "/tmp/foo.sock", ok: true},
			{pattern: "tmp/*.sock", target: "tmp/foo.sock", ok: true},
			{pattern: "/tmp/*.sock", target: "tmp/foo.sock", ok: false},
			{pattern: "tmp/*.sock", target: "/tmp/foo.sock", ok: false},
			{pattern: "*/tmp/foo.sock", target: "/tmp/foo.sock", ok: false},
			{pattern: "*", target: "/tmp/any.sock", ok: true},
			{pattern: "*", target: "tmp/any.sock", ok: true},
			{pattern: "/test.sock", target: "/tmp/test.sock", ok: false},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s->%s", tt.target, tt.pattern), func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@%s",permitsocketopen="%s" %s`, mockAddr, tt.pattern, cliAuthorizedKeyStr),
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
					targetConn, err := bastionConn.Dial("unix", tt.target)
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
					if _, err = bastionConn.Dial("unix", tt.target); err == nil {
						t.Error("expected dial to fail, but it succeeded")
						return
					}
				}
			})
		}
	})

	t.Run("permitsocketlisten", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr)
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		socketDir, err := os.MkdirTemp(os.TempDir(), "ct-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(socketDir) })

		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		relSocketDir, err := filepath.Rel(wd, socketDir)
		if err != nil {
			t.Fatal(err)
		}

		absSocketPath := filepath.Join(socketDir, "test.sock")
		absSocketGlob := filepath.Join(socketDir, "*.sock")
		relSocketPath := filepath.Join(relSocketDir, "test.sock")
		relSocketGlob := filepath.Join(relSocketDir, "*.sock")

		tests := []struct {
			pattern string
			target  string
			ok      bool
		}{
			{pattern: absSocketPath, target: absSocketPath, ok: true},
			{pattern: absSocketGlob, target: absSocketPath, ok: true},
			{pattern: relSocketPath, target: relSocketPath, ok: true},
			{pattern: relSocketGlob, target: relSocketPath, ok: true},
			{pattern: absSocketGlob, target: relSocketPath, ok: false},
			{pattern: relSocketGlob, target: absSocketPath, ok: false},
			{pattern: "*", target: absSocketPath, ok: true},
			{pattern: "*", target: relSocketPath, ok: true},
			{pattern: "/nonexistent/*.sock", target: absSocketPath, ok: false},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("target=%s,pattern=%s,ok=%t", tt.target, tt.pattern, tt.ok), func(t *testing.T) {
				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@%s",permitsocketlisten="%s" %s`, mockAddr, tt.pattern, cliAuthorizedKeyStr),
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

				_ = os.Remove(tt.target)
				t.Cleanup(func() { _ = os.Remove(tt.target) })

				if tt.ok {
					listener, err := bastionConn.ListenUnix(tt.target)
					if err != nil {
						t.Errorf("expected listen to succeed, but it failed: %v", err)
						return
					}
					defer func() { _ = listener.Close() }()

					go func() {
						time.Sleep(50 * time.Millisecond)
						conn, err := net.Dial("unix", tt.target)
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
					if listener, err := bastionConn.ListenUnix(tt.target); err == nil {
						_ = listener.Close()
						t.Error("expected listen to fail, but it succeeded")
						return
					}
				}
			})
		}
	})

	t.Run("no_socket_forwarding", func(t *testing.T) {
		cli, cliPublicKey, err := setupClient(t)
		if err != nil {
			t.Errorf("failed to setup client: %v", err)
			return
		}
		cli.User = fmt.Sprintf("alice@%s", mockAddr.String())
		cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

		bastionSrv, err := setupBastionServer(t,
			fmt.Sprintf(`permitconnect="alice@%s",no-socket-forwarding,permitsocketopen="*",permitsocketlisten="*" %s`, mockAddr, cliAuthorizedKeyStr),
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

		// Verify local socket forwarding is blocked
		if _, err := bastionConn.Dial("unix", "/tmp/test.sock"); err == nil {
			t.Error("expected dial to fail, but it succeeded")
			return
		}

		// Verify remote socket forwarding is blocked
		socketPath := filepath.Join(t.TempDir(), "test.sock")
		if listener, err := bastionConn.ListenUnix(socketPath); err == nil {
			_ = listener.Close()
			t.Error("expected listen to fail, but it succeeded")
			return
		}
	})

	t.Run("metrics", func(t *testing.T) {
		t.Run("socket_forwards", func(t *testing.T) {
			cli, cliPublicKey, err := setupClient(t)
			if err != nil {
				t.Errorf("failed to setup client: %v", err)
				return
			}
			cli.User = fmt.Sprintf("alice@%s", mockAddr)
			cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

			bastionSrv, err := setupBastionServer(t,
				fmt.Sprintf(`permitconnect="alice@*:*",permitsocketopen="*",permitsocketlisten="*" %s`, cliAuthorizedKeyStr),
				fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
			)
			if err != nil {
				t.Errorf("failed to setup bastion server: %v", err)
				return
			}
			metrics := bastionSrv.Metrics()

			// Create 5 local socket forwards: 3 closed, 2 kept open
			for i := range 5 {
				bastionConn, err := connectToServer(t, cli, bastionSrv)
				if err != nil {
					t.Errorf("failed to connect to server: %v", err)
					return
				}

				dialConn, err := bastionConn.Dial("unix", "/tmp/test.sock")
				if err != nil {
					t.Errorf("failed to open local socket forward: %v", err)
					return
				}

				if i < 3 {
					_ = dialConn.Close()
					_ = bastionConn.Close()
				} else {
					defer func() { _ = dialConn.Close() }()
				}
			}

			// Create 3 remote socket forwards with sessions: 2 closed, 1 kept open
			for i := range 3 {
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

				sockDir, err := os.MkdirTemp(os.TempDir(), "ct-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
				socketPath := filepath.Join(sockDir, fmt.Sprintf("test-%d.sock", i))
				listener, err := bastionConn.ListenUnix(socketPath)
				if err != nil {
					_ = session.Close()
					t.Errorf("failed to request remote socket forward: %v", err)
					return
				}

				go func() {
					time.Sleep(50 * time.Millisecond)
					conn, err := net.Dial("unix", socketPath)
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
				if count := metrics.SocketForwardsLocalActive.Load(); count != 2 {
					return fmt.Errorf("expected cardea_socket_forwards_local_active 2, got %d", count)
				}
				if count := metrics.SocketForwardsLocalTotal.Load(); count != 5 {
					return fmt.Errorf("expected cardea_socket_forwards_local_total 5, got %d", count)
				}
				if count := metrics.SocketForwardsRemoteActive.Load(); count != 1 {
					return fmt.Errorf("expected cardea_socket_forwards_remote_active 1, got %d", count)
				}
				if count := metrics.SocketForwardsRemoteTotal.Load(); count != 3 {
					return fmt.Errorf("expected cardea_socket_forwards_remote_total 3, got %d", count)
				}
				return nil
			}); err != nil {
				t.Error(err)
				return
			}
		})
	})
}
