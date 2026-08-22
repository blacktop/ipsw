//go:build !ios && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package download

import (
	"context"
	"errors"
)

func acquireAppStorePatchLock(_ context.Context, _ string, wait bool) (func(), error) {
	if !wait {
		return nil, errAppStorePatchLocked
	}
	return nil, errors.New("cross-process IPA patch locking is unsupported on this platform")
}
