//go:build netbsd

package disk

import "golang.org/x/sys/unix"

func GetDiskUsage(path string) (float64, error) {
	var stat unix.Statvfs_t
	if err := unix.Statvfs(path, &stat); err != nil {
		return 0, err
	}

	totalBytes := stat.Blocks * uint64(stat.Frsize)
	if totalBytes == 0 {
		return 0, nil
	}

	freeBytes := stat.Bavail * uint64(stat.Frsize)
	usedBytes := totalBytes - freeBytes
	usagePercent := float64(usedBytes) / float64(totalBytes) * 100

	return usagePercent, nil
}
