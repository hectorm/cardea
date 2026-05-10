package disk

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func ReadFile(path string) ([]byte, error) {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	f, err := root.OpenFile(base, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return io.ReadAll(f)
}

func WriteFile(path string, data []byte, perm os.FileMode) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	var rndBuf [8]byte
	if _, err := rand.Read(rndBuf[:]); err != nil {
		return err
	}
	tmpName := fmt.Sprintf(".tmp.%s", hex.EncodeToString(rndBuf[:]))
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = root.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := root.Rename(tmpName, base); err != nil {
		return err
	}

	if err := SyncDir(dir); err != nil {
		return err
	}

	ok = true
	return nil
}
