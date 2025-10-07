//go:build unix

package disk

import (
	"os"
	"syscall"
)

func GetDiskUsage(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}

	totalBytes := stat.Blocks * uint64(stat.Bsize) // #nosec G115
	if totalBytes == 0 {
		return 0, nil
	}

	freeBytes := stat.Bavail * uint64(stat.Bsize) // #nosec G115
	usedBytes := totalBytes - freeBytes
	usagePercent := float64(usedBytes) / float64(totalBytes) * 100

	return usagePercent, nil
}

func LockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func UnlockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
