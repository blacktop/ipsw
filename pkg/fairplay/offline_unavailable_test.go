//go:build !ipsw_fp || !cgo || (!darwin && !linux)

package fairplay

import (
	"errors"
	"testing"
)

func TestOfflineUnavailable(t *testing.T) {
	if err := OfflineAvailable(); !errors.Is(err, ErrOfflineUnavailable) {
		t.Fatal(err)
	}
	if _, err := DecryptIPA("fixture.ipa", "authorization.fpauth", "new-output"); !errors.Is(err, ErrOfflineUnavailable) {
		t.Fatal(err)
	}
	if payload, err := CaptureAuthorization(); payload != nil || !errors.Is(err, ErrOfflineUnavailable) {
		t.Fatalf("unexpected capture: %d bytes, %v", len(payload), err)
	}
}
