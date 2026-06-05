package config

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/hectorm/cardea/pkg/authkeys"
)

func validateAuthorizedKeysFile(cfg *Config) error {
	content, err := os.ReadFile(cfg.AuthorizedKeysFile)
	if err != nil {
		return err
	}
	_, warnings, err := authkeys.ParseFile(content)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		if w.Context != "" {
			slog.Warn("authorized_keys file parse", "line", w.Line, "reason", w.Message, "context", w.Context)
		} else {
			slog.Warn("authorized_keys file parse", "line", w.Line, "reason", w.Message)
		}
	}
	if n := len(warnings); n > 0 {
		return fmt.Errorf("%d problem(s)", n)
	}
	return nil
}

func validateKnownHostsFile(cfg *Config) error {
	_, err := knownhosts.New(cfg.KnownHostsFile)
	return err
}
