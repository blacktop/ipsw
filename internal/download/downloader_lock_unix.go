//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package download

import (
	"os"
	"syscall"
)

// stagingLockSupported reports whether go-download's cross-process staging
// flock actually works for files in dir (mirrors the build tags of the
// engine's lock_unix.go). Even on Unix, network filesystems (SMB, NFSv3)
// can reject flock at runtime, in which case the engine proceeds
// unprotected — probe with a throwaway file and fail closed on any error.
func stagingLockSupported(dir string) bool {
	probe, err := os.CreateTemp(dir, ".ipsw-lock-probe-*")
	if err != nil {
		return false
	}
	defer os.Remove(probe.Name())
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return false
	}
	_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
	return true
}
