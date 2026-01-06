//go:build windows

package disk

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	getDiskFreeSpaceEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
)

func GetDiskUsage(path string) (float64, error) {
	var freeBytes, totalBytes uint64

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	ret, _, err := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		0,
	)

	if ret == 0 {
		return 0, err
	}

	if totalBytes == 0 {
		return 0, nil
	}

	usedBytes := totalBytes - freeBytes
	usagePercent := float64(usedBytes) / float64(totalBytes) * 100

	return usagePercent, nil
}

func LockFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0,
		&overlapped,
	)
}

func UnlockFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(
		windows.Handle(file.Fd()),
		0, 1, 0,
		&overlapped,
	)
}

func SyncDir(_ string) error {
	return nil
}
