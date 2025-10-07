package config

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/hectorm/cardea/internal/utils/env"
)

type Config struct {
	Listen                   string
	PrivateKeyFile           string
	PrivateKeyPassphrase     string
	PrivateKeyPassphraseFile string
	AuthorizedKeysFile       string
	KnownHostsFile           string
	UnknownHostsPolicy       string
	ConnectionsMax           int
	RateLimitMax             int
	RateLimitTime            time.Duration
	RecordingsDir            string
	RecordingsRetentionTime  time.Duration
	RecordingsMaxDiskUsage   string
	LogLevel                 string
}

var (
	version    = "dev"
	author     = "H\u00E9ctor Molinero Fern\u00E1ndez <hector@molinero.dev>"
	license    = "EUPL-v1.2-or-later, https://interoperable-europe.ec.europa.eu/collection/eupl"
	repository = "https://github.com/hectorm/cardea"
)

func NewConfig() *Config {
	config := &Config{}
	showVersion := false

	flag.StringVar(
		&config.Listen,
		"listen",
		env.StringEnv(":2222", "CARDEA_LISTEN"),
		"address to listen on (env CARDEA_LISTEN)",
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
		"path to file containing the private key passphrase (env CARDEA_PRIVATE_KEY_PASSPHRASE_FILE)",
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
		"directory to store session recordings; disabled if empty (env CARDEA_RECORDINGS_DIR)",
	)

	flag.DurationVar(
		&config.RecordingsRetentionTime,
		"recordings-retention-time",
		env.DurationEnv(30*24*time.Hour, "CARDEA_RECORDINGS_RETENTION_TIME"),
		"time to retain session recordings (env CARDEA_RECORDINGS_RETENTION_TIME)",
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
		sb.WriteString(fmt.Sprintf("Cardea %s\n", version))
		sb.WriteString(fmt.Sprintf("Author: %s\n", author))
		sb.WriteString(fmt.Sprintf("License: %s\n", license))
		sb.WriteString(fmt.Sprintf("Repository: %s\n", repository))
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

	switch config.UnknownHostsPolicy {
	case "strict", "tofu":
		// ok
	default:
		slog.Error("invalid known hosts policy", "policy", config.UnknownHostsPolicy)
		os.Exit(1)
	}

	return config
}
