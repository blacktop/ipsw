//go:build !ipsw_fp || !cgo || (!darwin && !linux)

package fairplay

func offlineAvailable() error { return ErrOfflineUnavailable }

func offlineDecrypt(_, _, _ string) (Result, error) {
	return Result{}, ErrOfflineUnavailable
}

func offlineCapture() ([]byte, error) { return nil, ErrOfflineUnavailable }
