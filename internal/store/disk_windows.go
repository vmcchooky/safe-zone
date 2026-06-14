//go:build windows

package store

import (
	"golang.org/x/sys/windows"
	"path/filepath"
)

func getFreeDiskSpace(path string) (float64, error) {
	dir := filepath.Dir(path)
	u16, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var freeBytes, totalBytes, totalFreeBytes uint64
	err = windows.GetDiskFreeSpaceEx(u16, &freeBytes, &totalBytes, &totalFreeBytes)
	if err != nil {
		return 0, err
	}
	return float64(freeBytes) / 1024.0 / 1024.0 / 1024.0, nil // in GB
}
