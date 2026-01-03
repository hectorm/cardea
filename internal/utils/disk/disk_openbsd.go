//go:build openbsd

package disk

import "golang.org/x/sys/unix"

func GetDiskUsage(path string) (float64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}

	totalBytes := stat.F_blocks * uint64(stat.F_bsize)
	if totalBytes == 0 {
		return 0, nil
	}

	freeBytes := uint64(stat.F_bavail) * uint64(stat.F_bsize)
	usedBytes := totalBytes - freeBytes
	usagePercent := float64(usedBytes) / float64(totalBytes) * 100

	return usagePercent, nil
}
