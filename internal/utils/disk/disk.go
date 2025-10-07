package disk

import (
	"io/fs"
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
