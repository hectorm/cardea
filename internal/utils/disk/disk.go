package disk

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type FileInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
}

func GetFilesBySuffix(dir string, suffix string) ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), strings.ToLower(suffix)) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		files = append(files, FileInfo{
			Path:    path,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.Before(files[j].ModTime)
	})

	return files, nil
}

func GetTotalSizeBySuffix(dir, suffix string) (int64, error) {
	files, err := GetFilesBySuffix(dir, suffix)
	if err != nil {
		return 0, err
	}

	var total int64
	for _, f := range files {
		total += f.Size
	}

	return total, nil
}

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
