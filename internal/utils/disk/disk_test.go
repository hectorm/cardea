package disk

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
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

	t.Run("lock_unlock_file", func(t *testing.T) {
		tempDir := t.TempDir()
		path := filepath.Join(tempDir, "test.txt")
		base := filepath.Base(path)

		if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
			t.Errorf("failed to create file: %v", err)
			return
		}

		root, err := os.OpenRoot(tempDir)
		if err != nil {
			t.Errorf("failed to open root: %v", err)
			return
		}
		defer func() { _ = root.Close() }()

		file1, err := root.OpenFile(base, os.O_RDWR, 0600)
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

		file2, err := root.OpenFile(base, os.O_RDWR, 0600)
		if err != nil {
			t.Errorf("failed to open file #2: %v", err)
			return
		}
		defer func() { _ = file2.Close() }()

		if err := LockFile(file2); err == nil {
			t.Error("locking file #2 should fail while file #1 is locked")
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

	t.Run("read_file", func(t *testing.T) {
		t.Run("existing_file", func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "test.txt")
			content := []byte("test content")

			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Errorf("failed to create file: %v", err)
				return
			}

			data, err := ReadFile(path)
			if err != nil {
				t.Errorf("failed to read file: %v", err)
				return
			}

			if string(data) != string(content) {
				t.Errorf("expected %q, got %q", content, data)
				return
			}
		})

		t.Run("non_existent_file", func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "non_existent.txt")

			_, err := ReadFile(path)
			if err == nil {
				t.Error("reading non-existent file should fail")
				return
			}
			if !os.IsNotExist(err) {
				t.Errorf("error should be not exist, got: %v", err)
				return
			}
		})

		t.Run("non_existent_directory", func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "non_existent_dir", "test.txt")

			_, err := ReadFile(path)
			if err == nil {
				t.Error("reading file in non-existent directory should fail")
				return
			}
		})
	})

	t.Run("write_file", func(t *testing.T) {
		t.Run("existing_file", func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "existing.txt")

			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Errorf("failed to create file: %v", err)
				return
			}

			if err := WriteFile(path, []byte("new content"), 0600); err != nil {
				t.Errorf("writing to existing file should succeed: %v", err)
				return
			}

			root, err := os.OpenRoot(tempDir)
			if err != nil {
				t.Errorf("failed to open root: %v", err)
				return
			}
			defer func() { _ = root.Close() }()

			data, err := root.ReadFile("existing.txt")
			if err != nil {
				t.Errorf("failed to read back file: %v", err)
				return
			}
			if string(data) != "new content" {
				t.Errorf("expected %q, got %q", "new content", string(data))
				return
			}
		})

		t.Run("non_existent_file", func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "new.txt")
			content := []byte("new content")

			if err := WriteFile(path, content, 0600); err != nil {
				t.Errorf("failed to write file: %v", err)
				return
			}

			root, err := os.OpenRoot(tempDir)
			if err != nil {
				t.Errorf("failed to open root: %v", err)
				return
			}
			defer func() { _ = root.Close() }()

			data, err := root.ReadFile("new.txt")
			if err != nil {
				t.Errorf("failed to read back file: %v", err)
				return
			}

			if string(data) != string(content) {
				t.Errorf("expected %q, got %q", content, data)
				return
			}

			if runtime.GOOS != "windows" {
				info, err := os.Stat(path)
				if err != nil {
					t.Errorf("failed to stat file: %v", err)
					return
				}

				if info.Mode().Perm() != 0600 {
					t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
					return
				}
			}
		})

		t.Run("non_existent_directory", func(t *testing.T) {
			tempDir := t.TempDir()
			path := filepath.Join(tempDir, "non_existent_dir", "test.txt")

			err := WriteFile(path, []byte("content"), 0600)
			if err == nil {
				t.Error("writing to non-existent directory should fail")
				return
			}
		})
	})
}
