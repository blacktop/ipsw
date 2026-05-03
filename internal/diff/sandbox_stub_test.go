//go:build !sandbox

package diff

import (
	"errors"
	"testing"
)

func TestParseSandboxProfilesStubReturnsUnavailable(t *testing.T) {
	_, err := (&Diff{}).parseSandboxProfiles()
	if !errors.Is(err, ErrSandboxDiffUnavailable) {
		t.Fatalf("parseSandboxProfiles() error = %v, want %v", err, ErrSandboxDiffUnavailable)
	}
}
