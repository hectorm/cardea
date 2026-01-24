package config

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hectorm/cardea/internal/utils/env"
)

type Config struct {
	Listen                   string
	HealthListen             string
	KeyStrategy              string
	PrivateKeyFile           string
	PrivateKeyPassphrase     string
	PrivateKeyPassphraseFile string
	TPMDevice                string
	TPMParentHandle          string
	TPMParentAuth            string
	TPMParentAuthFile        string
	TPMKeyFile               string
	TPMKeyAuth               string
	TPMKeyAuthFile           string
	AuthorizedKeysFile       string
	KnownHostsFile           string
	UnknownHostsPolicy       string
	BannerFile               string
	ConnectionsMax           int
	RateLimitMax             int
	RateLimitTime            time.Duration
	RecordingsDir            string
	RecordingsRetentionTime  time.Duration
	RecordingsMaxDiskUsage   string
	LogLevel                 string
}

var (
	Version    = "dev"
	Author     = "H\u00E9ctor Molinero Fern\u00E1ndez <hector@molinero.dev>"
	License    = "EUPL-v1.2-or-later, https://interoperable-europe.ec.europa.eu/collection/eupl"
	Repository = "https://github.com/hectorm/cardea"
)

func NewConfig() *Config {
	config := &Config{}
	showVersion := false

	flag.StringVar(
		&config.Listen,
		"listen",
		env.StringEnv(":2222", "CARDEA_LISTEN"),
		"address for the SSH server (env CARDEA_LISTEN)",
	)

	flag.StringVar(
		&config.HealthListen,
		"health-listen",
		env.StringEnv("localhost:9222", "CARDEA_HEALTH_LISTEN"),
		"address for the health/metrics server; disabled if empty (env CARDEA_HEALTH_LISTEN)",
	)

	flag.StringVar(
		&config.KeyStrategy,
		"key-strategy",
		env.StringEnv("file", "CARDEA_KEY_STRATEGY"),
		"key strategy for bastion host/backend authentication: file, tpm (env CARDEA_KEY_STRATEGY)",
	)

	flag.StringVar(
		&config.PrivateKeyFile,
		"private-key-file",
		env.StringEnv("/etc/cardea/private_key", "CARDEA_PRIVATE_KEY_FILE"),
		"path to the host private key (env CARDEA_PRIVATE_KEY_FILE)",
	)

	flag.StringVar(
		&config.PrivateKeyPassphrase,
		"private-key-passphrase",
		env.StringEnv("", "CARDEA_PRIVATE_KEY_PASSPHRASE"),
		"passphrase for the private key (env CARDEA_PRIVATE_KEY_PASSPHRASE)",
	)

	flag.StringVar(
		&config.PrivateKeyPassphraseFile,
		"private-key-passphrase-file",
		env.StringEnv("", "CARDEA_PRIVATE_KEY_PASSPHRASE_FILE"),
		"path to the file containing the private key passphrase (env CARDEA_PRIVATE_KEY_PASSPHRASE_FILE)",
	)

	switch runtime.GOOS {
	case "linux":
		flag.StringVar(
			&config.TPMDevice,
			"tpm-device",
			env.StringEnv("/dev/tpmrm0", "CARDEA_TPM_DEVICE"),
			"path to the TPM device (env CARDEA_TPM_DEVICE)",
		)
	case "windows":
		config.TPMDevice = "tbs"
	}

	flag.StringVar(
		&config.TPMParentHandle,
		"tpm-parent-handle",
		env.StringEnv("", "CARDEA_TPM_PARENT_HANDLE"),
		"persistent handle for the parent key (e.g. 0x81000001); if not set, a transient key is created (env CARDEA_TPM_PARENT_HANDLE)",
	)

	flag.StringVar(
		&config.TPMParentAuth,
		"tpm-parent-auth",
		env.StringEnv("", "CARDEA_TPM_PARENT_AUTH"),
		"authorization value for the parent key (env CARDEA_TPM_PARENT_AUTH)",
	)

	flag.StringVar(
		&config.TPMParentAuthFile,
		"tpm-parent-auth-file",
		env.StringEnv("", "CARDEA_TPM_PARENT_AUTH_FILE"),
		"path to the file containing the parent key authorization (env CARDEA_TPM_PARENT_AUTH_FILE)",
	)

	flag.StringVar(
		&config.TPMKeyFile,
		"tpm-key-file",
		env.StringEnv("/etc/cardea/tpm_key.blob", "CARDEA_TPM_KEY_FILE"),
		"path to the key blob (env CARDEA_TPM_KEY_FILE)",
	)

	flag.StringVar(
		&config.TPMKeyAuth,
		"tpm-key-auth",
		env.StringEnv("", "CARDEA_TPM_KEY_AUTH"),
		"authorization value for the key (env CARDEA_TPM_KEY_AUTH)",
	)

	flag.StringVar(
		&config.TPMKeyAuthFile,
		"tpm-key-auth-file",
		env.StringEnv("", "CARDEA_TPM_KEY_AUTH_FILE"),
		"path to the file containing the key authorization (env CARDEA_TPM_KEY_AUTH_FILE)",
	)

	flag.StringVar(
		&config.AuthorizedKeysFile,
		"authorized-keys-file",
		env.StringEnv("/etc/cardea/authorized_keys", "CARDEA_AUTHORIZED_KEYS_FILE"),
		"path to the authorized keys file (env CARDEA_AUTHORIZED_KEYS_FILE)",
	)

	flag.StringVar(
		&config.KnownHostsFile,
		"known-hosts-file",
		env.StringEnv("/etc/cardea/known_hosts", "CARDEA_KNOWN_HOSTS_FILE"),
		"path to the known hosts file (env CARDEA_KNOWN_HOSTS_FILE)",
	)

	flag.StringVar(
		&config.UnknownHostsPolicy,
		"unknown-hosts-policy",
		env.StringEnv("strict", "CARDEA_UNKNOWN_HOSTS_POLICY"),
		"policy for unknown hosts: strict (deny unknown), tofu (trust on first use) (env CARDEA_UNKNOWN_HOSTS_POLICY)",
	)

	flag.StringVar(
		&config.BannerFile,
		"banner-file",
		env.StringEnv("", "CARDEA_BANNER_FILE"),
		"path to the banner file; disabled if empty (env CARDEA_BANNER_FILE)",
	)

	flag.IntVar(
		&config.ConnectionsMax,
		"connections-max",
		env.IntEnv(1000, "CARDEA_CONNECTIONS_MAX"),
		"maximum number of concurrent connections; 0 for unlimited (env CARDEA_CONNECTIONS_MAX)",
	)

	flag.IntVar(
		&config.RateLimitMax,
		"rate-limit-max",
		env.IntEnv(10, "CARDEA_RATE_LIMIT_MAX"),
		"maximum number of unauthenticated requests per IP address; 0 for unlimited (env CARDEA_RATE_LIMIT_MAX)",
	)

	flag.DurationVar(
		&config.RateLimitTime,
		"rate-limit-time",
		env.DurationEnv(5*time.Minute, "CARDEA_RATE_LIMIT_TIME"),
		"time window for rate limiting unauthenticated requests (env CARDEA_RATE_LIMIT_TIME)",
	)

	flag.StringVar(
		&config.RecordingsDir,
		"recordings-dir",
		env.StringEnv("", "CARDEA_RECORDINGS_DIR"),
		"path to the session recordings directory; disabled if empty (env CARDEA_RECORDINGS_DIR)",
	)

	flag.DurationVar(
		&config.RecordingsRetentionTime,
		"recordings-retention-time",
		env.DurationEnv(30*24*time.Hour, "CARDEA_RECORDINGS_RETENTION_TIME"),
		"retention time for the session recordings (env CARDEA_RECORDINGS_RETENTION_TIME)",
	)

	flag.StringVar(
		&config.RecordingsMaxDiskUsage,
		"recordings-max-disk-usage",
		env.StringEnv("90%", "CARDEA_RECORDINGS_MAX_DISK_USAGE"),
		"maximum disk usage for session recordings; accepts percentage (e.g. 90%) or fixed size (e.g. 1GB) (env CARDEA_RECORDINGS_MAX_DISK_USAGE)",
	)

	flag.StringVar(
		&config.LogLevel,
		"log-level",
		env.StringEnv("info", "CARDEA_LOG_LEVEL"),
		"log level: debug, info, warn, error, quiet (env CARDEA_LOG_LEVEL)",
	)

	flag.BoolVar(
		&showVersion,
		"version",
		false,
		"show version and exit",
	)

	flag.Parse()

	if showVersion {
		var sb strings.Builder
		fmt.Fprintf(&sb, "Cardea %s\n", Version)
		fmt.Fprintf(&sb, "Author: %s\n", Author)
		fmt.Fprintf(&sb, "License: %s\n", License)
		fmt.Fprintf(&sb, "Repository: %s\n", Repository)
		fmt.Print(sb.String())
		os.Exit(0)
	}

	var logger *slog.Logger
	switch config.LogLevel {
	case "debug":
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case "info":
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	case "warn":
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	case "error":
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	case "quiet":
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	default:
		slog.Error("invalid log level", "level", config.LogLevel)
		os.Exit(1)
	}
	slog.SetDefault(logger)

	switch config.KeyStrategy {
	case "file":
		// ok
	case "tpm":
		if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
			slog.Error("tpm support is only available on linux and windows")
			os.Exit(1)
		}
	default:
		slog.Error("invalid key strategy", "strategy", config.KeyStrategy)
		os.Exit(1)
	}

	switch config.UnknownHostsPolicy {
	case "strict", "tofu":
		// ok
	default:
		slog.Error("invalid known hosts policy", "policy", config.UnknownHostsPolicy)
		os.Exit(1)
	}

	return config
}

func ResolveSecret(value, filePath, name string) (string, error) {
	if value != "" && filePath != "" {
		return "", fmt.Errorf("cannot specify both %s and %s file", name, name)
	}
	if filePath != "" {
		data, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			return "", fmt.Errorf("read %s file: %w", name, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return value, nil
}
