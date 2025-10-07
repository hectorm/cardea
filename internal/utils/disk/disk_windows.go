//go:build windows

package disk

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex
	LOCKFILE_EXCLUSIVE_LOCK   = 0x00000002
	LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx = kernel32.NewProc("GetDiskFreeSpaceExW")
	lockFileEx         = kernel32.NewProc("LockFileEx")
	unlockFileEx       = kernel32.NewProc("UnlockFileEx")
)

func GetDiskUsage(path string) (float64, error) {
	var freeBytes, totalBytes uint64

	pathPtr, err := syscall.UTF16PtrFromString(path)
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
	var overlapped syscall.Overlapped
	ret, _, err := lockFileEx.Call(
		uintptr(syscall.Handle(file.Fd())),
		uintptr(LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY),
		0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

func UnlockFile(file *os.File) error {
	var overlapped syscall.Overlapped
	ret, _, err := unlockFileEx.Call(
		uintptr(syscall.Handle(file.Fd())),
		0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped)),
	)

	if ret == 0 {
		return err
	}

	return nil
}
