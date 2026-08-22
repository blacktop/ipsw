//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package download

// stagingLockSupported is always false where go-download's lock_fallback.go
// is in effect: the engine cannot detect another process's active download,
// so --skip-all must fail closed on staging-file presence instead.
func stagingLockSupported(string) bool { return false }
