//go:build !ios && (darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package download

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func acquireAppStorePatchLock(ctx context.Context, path string, wait bool) (func(), error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			// Keep the inode in place after unlocking. Removing it would let a
			// new opener lock a different inode while an existing waiter holds
			// this one, splitting the critical section.
			return func() {
				_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
				_ = lock.Close()
			}, nil
		}
		if !wait && (errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) ||
			errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) ||
			errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL)) {
			lock.Close()
			return nil, errAppStorePatchLocked
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			lock.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			lock.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
