//go:build !windows

package store

import (
	"path/filepath"
	"syscall"
)

func getFreeDiskSpace(path string) (float64, error) {
	dir := filepath.Dir(path)
	var stat syscall.Statfs_t
	err := syscall.Statfs(dir, &stat)
	if err != nil {
		return 0, err
	}
	// Available blocks * block size
	freeBytes := uint64(stat.Bavail) * uint64(stat.Bsize)
	return float64(freeBytes) / 1024.0 / 1024.0 / 1024.0, nil // in GB
}
