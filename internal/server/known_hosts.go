package server

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type hostKeysDB struct {
	cb      ssh.HostKeyCallback
	caLines map[int]struct{}
}

func (srv *Server) newHostKeysDB(path string) (*hostKeysDB, error) {
	path = filepath.Clean(path)

	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err == nil {
		_ = f.Close()
	} else if !os.IsExist(err) {
		return nil, err
	}

	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	caLines := make(map[int]struct{})
	sc := bufio.NewScanner(f)
	for lineNum := 1; sc.Scan(); lineNum++ {
		line := bytes.TrimSpace(sc.Bytes())
		if bytes.HasPrefix(line, []byte("@cert-authority ")) {
			caLines[lineNum] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return &hostKeysDB{cb: cb, caLines: caLines}, nil
}
