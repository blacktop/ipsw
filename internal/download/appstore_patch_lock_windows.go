//go:build windows

package download

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func acquireAppStorePatchLock(ctx context.Context, path string, wait bool) (func(), error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	for {
		err = windows.LockFileEx(
			windows.Handle(lock.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			&overlapped,
		)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, &overlapped)
				_ = lock.Close()
			}, nil
		}
		if !wait && errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			lock.Close()
			return nil, errAppStorePatchLocked
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
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
