//go:build unix

package mock

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestMockSSHServerUnix(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	cli, _, err := setupClient(t)
	if err != nil {
		t.Errorf("failed to setup client: %v", err)
		return
	}

	t.Run("direct_streamlocal_channel", func(t *testing.T) {
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
			SocketPath string
			Reserved0  string
			Reserved1  uint32
		}{
			SocketPath: "/tmp/test.sock",
			Reserved0:  "",
			Reserved1:  0,
		}

		channel, requests, err := conn.OpenChannel("direct-streamlocal@openssh.com", ssh.Marshal(payload))
		if err != nil {
			t.Errorf("failed to open direct-streamlocal channel: %v", err)
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

	t.Run("streamlocal_forward", func(t *testing.T) {
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

		sockDir, err := os.MkdirTemp(os.TempDir(), "ct-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

		socketPath := filepath.Join(sockDir, "test.sock")

		listener, err := conn.ListenUnix(socketPath)
		if err != nil {
			t.Errorf("failed to request streamlocal forward: %v", err)
			return
		}
		defer func() { _ = listener.Close() }()

		go func() {
			time.Sleep(50 * time.Millisecond)
			c, err := net.Dial("unix", socketPath)
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		}()

		acceptedConn, err := listener.Accept()
		if err != nil {
			t.Errorf("failed to accept connection: %v", err)
			return
		}
		defer func() { _ = acceptedConn.Close() }()

		data := "\x00\x01\x02\x03\xFF"

		if _, err = acceptedConn.Write([]byte(data)); err != nil {
			t.Errorf("failed to write data: %v", err)
			return
		}

		buffer := make([]byte, len(data))
		if _, err = io.ReadFull(acceptedConn, buffer); err != nil {
			t.Errorf("failed to read echoed data: %v", err)
			return
		} else if string(buffer) != data {
			t.Errorf("expected echoed data %q, got %q", data, string(buffer))
			return
		}
	})
}
