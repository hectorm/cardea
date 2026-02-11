//go:build unix

package disk

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func LockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) // #nosec G115
}

func UnlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN) // #nosec G115
}

func SyncDir(path string) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	d, err := root.OpenFile(base, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()

	return d.Sync()
}
