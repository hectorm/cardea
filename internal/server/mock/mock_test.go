package mock

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func setupServer(t testing.TB, opts ...Option) (*Server, error) {
	t.Helper()

	srv, err := NewServer(opts...)
	if err != nil {
		return nil, err
	}

	if err := srv.Start(); err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Errorf("failed to stop server: %v", err)
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

func TestMockSSHServer(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	cli, _, err := setupClient(t)
	if err != nil {
		t.Errorf("failed to setup client: %v", err)
		return
	}

	t.Run("connect", func(t *testing.T) {
		srv, err := setupServer(t, WithPublicKeyCallback(AlwaysAllowPublicKey))
		if err != nil {
			t.Errorf("failed to setup server: %v", err)
			return
		}

		conn, err := connectToServer(t, cli, srv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := conn.NewSession()
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

	t.Run("deny_authentication", func(t *testing.T) {
		srv, err := setupServer(t, WithPublicKeyCallback(AlwaysDenyPublicKey))
		if err != nil {
			t.Errorf("failed to setup server: %v", err)
			return
		}

		if _, err := ssh.Dial("tcp", srv.Address().String(), cli); err == nil {
			t.Error("expected authentication to fail, but it succeeded")
			return
		} else if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Errorf("expected authentication error, got: %v", err)
			return
		}
	})

	t.Run("direct_tcpip_channel", func(t *testing.T) {
		srv, err := setupServer(t, WithPublicKeyCallback(AlwaysAllowPublicKey))
		if err != nil {
			t.Errorf("failed to setup server: %v", err)
			return
		}

		conn, err := connectToServer(t, cli, srv)
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

		channel, requests, err := conn.OpenChannel("direct-tcpip", ssh.Marshal(payload))
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
		srv, err := setupServer(t, WithPublicKeyCallback(AlwaysAllowPublicKey))
		if err != nil {
			t.Errorf("failed to setup server: %v", err)
			return
		}

		conn, err := connectToServer(t, cli, srv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		if _, _, err := conn.OpenChannel("unsupported", nil); err == nil {
			t.Error("expected unsupported channel to fail, but it succeeded")
			return
		}
	})

	t.Run("unsupported_request", func(t *testing.T) {
		srv, err := setupServer(t, WithPublicKeyCallback(AlwaysAllowPublicKey))
		if err != nil {
			t.Errorf("failed to setup server: %v", err)
			return
		}

		conn, err := connectToServer(t, cli, srv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := conn.NewSession()
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

	t.Run("sftp_subsystem", func(t *testing.T) {
		srv, err := setupServer(t, WithPublicKeyCallback(AlwaysAllowPublicKey))
		if err != nil {
			t.Errorf("failed to setup server: %v", err)
			return
		}

		conn, err := connectToServer(t, cli, srv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := conn.NewSession()
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

	t.Run("unsupported_subsystem", func(t *testing.T) {
		srv, err := setupServer(t, WithPublicKeyCallback(AlwaysAllowPublicKey))
		if err != nil {
			t.Errorf("failed to setup server: %v", err)
			return
		}

		conn, err := connectToServer(t, cli, srv)
		if err != nil {
			t.Errorf("failed to connect to server: %v", err)
			return
		}

		session, err := conn.NewSession()
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
}
