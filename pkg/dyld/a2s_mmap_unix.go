//go:build unix

package dyld

import (
	"os"
	"syscall"
)

// MAP_PRIVATE (vs MAP_SHARED in openCacheFile) because the a2s cache
// is a self-contained index that doesn't need cross-process visibility.
func a2sMmap(f *os.File, size int) ([]byte, error) {
	return syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ, syscall.MAP_PRIVATE)
}

func a2sMunmap(data []byte) error {
	return syscall.Munmap(data)
}
