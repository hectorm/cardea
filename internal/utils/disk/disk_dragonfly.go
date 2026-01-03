//go:build dragonfly

package disk

import "golang.org/x/sys/unix"

func GetDiskUsage(path string) (float64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}

	totalBytes := uint64(stat.Blocks) * uint64(stat.Bsize)
	if totalBytes == 0 {
		return 0, nil
	}

	freeBytes := uint64(stat.Bavail) * uint64(stat.Bsize)
	usedBytes := totalBytes - freeBytes
	usagePercent := float64(usedBytes) / float64(totalBytes) * 100

	return usagePercent, nil
}
