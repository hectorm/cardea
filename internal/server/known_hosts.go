package server

import (
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func (srv *Server) newHostKeysCB(path string) (ssh.HostKeyCallback, error) {
	path = filepath.Clean(path)

	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err == nil {
		_ = f.Close()
	} else if !os.IsExist(err) {
		return nil, err
	}

	hostKeysCB, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}
	return hostKeysCB, nil
}
