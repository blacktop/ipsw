//go:build sandbox

package diff

import (
	"fmt"
	"testing"

	"github.com/blacktop/ipsw/pkg/sandbox"
	"github.com/blacktop/ipsw/pkg/sandbox/normalize"
)

func TestIsSandboxSourceUnavailableUsesSentinel(t *testing.T) {
	err := fmt.Errorf("failed to load collection data: %w", sandbox.ErrSandboxSourceUnavailable)
	if !isSandboxSourceUnavailable(err) {
		t.Fatal("expected sandbox source unavailable sentinel to be skipped")
	}

	if isSandboxSourceUnavailable(normalize.ErrFormattedOutputTooLarge) {
		t.Fatal("formatter budget errors must not be treated as unavailable sources")
	}
}

func TestUniqueSandboxProfileDocumentNameAvoidsExistingSuffix(t *testing.T) {
	existing := map[string]string{
		"profile":   "first",
		"profile#1": "second",
	}

	got := uniqueSandboxProfileDocumentName(existing, "profile", 1)
	if got != "profile#1.2" {
		t.Fatalf("uniqueSandboxProfileDocumentName() = %q, want %q", got, "profile#1.2")
	}
}
