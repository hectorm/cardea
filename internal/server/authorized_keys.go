package server

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/hectorm/cardea/pkg/authkeys"
)

func (srv *Server) newAuthorizedKeysDB(path string) (map[string][]*authkeys.AuthorizedKeyOptions, error) {
	path = filepath.Clean(path)

	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err == nil {
		_ = f.Close()
	} else if !os.IsExist(err) {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	authKeysDB, warnings, err := authkeys.ParseFile(content)
	if err != nil {
		return nil, err
	}

	for _, w := range warnings {
		if w.Context != "" {
			slog.Warn("authorized_keys file parse", "line", w.Line, "reason", w.Message, "context", w.Context)
		} else {
			slog.Warn("authorized_keys file parse", "line", w.Line, "reason", w.Message)
		}
	}

	return authKeysDB, nil
}
