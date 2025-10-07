package disk

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDisk(t *testing.T) {
	t.Run("get_disk_usage", func(t *testing.T) {
		tempDir := t.TempDir()

		if usage, err := GetDiskUsage(tempDir); err != nil {
			t.Errorf("failed to get disk usage: %v", err)
			return
		} else if usage < 0 || usage > 100 {
			t.Errorf("expected disk usage between 0-100%%, got %f%%", usage)
			return
		}
	})

	t.Run("get_files_by_suffix", func(t *testing.T) {
		tempDir := t.TempDir()

		filenames := []string{
			"20060102-150405-43ceb62ea6ea67455d73.cast.gz",
			"20060102-160506-fc89b5fe3ba17763fb1c.cast.gz",
			"20060102-170607-BFABF579D09DB9B069E1.CAST.GZ",
			"other.cast",
			"regular.txt",
		}

		for i, filename := range filenames {
			path := filepath.Join(tempDir, filename)
			if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
				t.Errorf("failed to create file: %v", err)
				return
			}

			modTime := time.Now().Add(time.Duration(i) * time.Hour)
			if err := os.Chtimes(path, modTime, modTime); err != nil {
				t.Errorf("failed to set file time: %v", err)
				return
			}
		}

		files, err := GetFilesBySuffix(tempDir, ".cast.gz")
		if err != nil {
			t.Errorf("failed to get files: %v", err)
			return
		}

		if len(files) != 3 {
			t.Errorf("expected 3 files, got %d", len(files))
			return
		}

		if len(files) >= 2 {
			if files[0].ModTime.After(files[1].ModTime) {
				t.Error("files are not sorted by modification time")
				return
			}
		}
	})

	t.Run("get_total_size_by_suffix", func(t *testing.T) {
		tempDir := t.TempDir()

		filenames := map[string]int64{
			"20060102-160506-fc89b5fe3ba17763fb1c.cast.gz":        10,
			"20060102-170607-BFABF579D09DB9B069E1.CAST.GZ":        20,
			"nested/20060102-150405-43ceb62ea6ea67455d73.cast.gz": 30,
			"regular.txt": 40,
			"other.txt":   50,
		}

		for filename, size := range filenames {
			path := filepath.Join(tempDir, filename)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Errorf("failed to create directory for file %s: %v", filename, err)
				return
			}
			if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
				t.Errorf("failed to create file %s: %v", filename, err)
				return
			}
		}

		size, err := GetTotalSizeBySuffix(tempDir, ".cast.gz")
		if err != nil {
			t.Errorf("failed to get total size: %v", err)
			return
		}

		if size != 60 {
			t.Errorf("expected total size 60, got %d", size)
			return
		}
	})

	t.Run("lock_unlock_file", func(t *testing.T) {
		tempDir := t.TempDir()
		path := filepath.Join(tempDir, "test.txt")

		if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
			t.Errorf("failed to create file: %v", err)
			return
		}

		file1, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304
		if err != nil {
			t.Errorf("failed to open file #1: %v", err)
			return
		}
		defer func() { _ = file1.Close() }()

		if err := LockFile(file1); err != nil {
			t.Errorf("failed to lock file #1: %v", err)
			return
		}
		defer func() { _ = UnlockFile(file1) }()

		file2, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304
		if err != nil {
			t.Errorf("failed to open file #2: %v", err)
			return
		}
		defer func() { _ = file2.Close() }()

		if err := LockFile(file2); err == nil {
			t.Error("expected error when locking file #2 while file #1 is locked")
			return
		}
		defer func() { _ = UnlockFile(file2) }()

		if err := UnlockFile(file1); err != nil {
			t.Errorf("failed to unlock file #1: %v", err)
			return
		}

		if err := LockFile(file2); err != nil {
			t.Errorf("failed to lock file #2 after unlocking file #1: %v", err)
			return
		}
	})
}
