package config

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	writeTemp := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		return path
	}

	t.Run("authorized_keys_valid", func(t *testing.T) {
		cfg := &Config{AuthorizedKeysFile: writeTemp(t, `permitconnect="alice@10.0.1.1:22" `+key+"\n")}
		if err := validateAuthorizedKeysFile(cfg); err != nil {
			t.Errorf("expected valid authorized_keys, got error: %v", err)
		}
	})

	t.Run("authorized_keys_invalid", func(t *testing.T) {
		cfg := &Config{AuthorizedKeysFile: writeTemp(t, `permitconnect="alice@10.0.1.1:22" ssh-ed25519 invalid`+"\n")}
		if err := validateAuthorizedKeysFile(cfg); err == nil {
			t.Error("expected error for invalid authorized_keys, got nil")
		}
	})

	t.Run("authorized_keys_missing", func(t *testing.T) {
		cfg := &Config{AuthorizedKeysFile: filepath.Join(t.TempDir(), "authorized_keys")}
		if err := validateAuthorizedKeysFile(cfg); err == nil {
			t.Error("expected error for missing authorized_keys, got nil")
		}
	})

	t.Run("known_hosts_valid", func(t *testing.T) {
		cfg := &Config{KnownHostsFile: writeTemp(t, "[10.0.1.1]:22 "+key+"\n")}
		if err := validateKnownHostsFile(cfg); err != nil {
			t.Errorf("expected valid known_hosts, got error: %v", err)
		}
	})

	t.Run("known_hosts_invalid", func(t *testing.T) {
		cfg := &Config{KnownHostsFile: writeTemp(t, "[10.0.1.1]:22 ssh-ed25519 invalid\n")}
		if err := validateKnownHostsFile(cfg); err == nil {
			t.Error("expected error for invalid known_hosts, got nil")
		}
	})

	t.Run("known_hosts_missing", func(t *testing.T) {
		cfg := &Config{KnownHostsFile: filepath.Join(t.TempDir(), "known_hosts")}
		if err := validateKnownHostsFile(cfg); err == nil {
			t.Error("expected error for missing known_hosts, got nil")
		}
	})
}
