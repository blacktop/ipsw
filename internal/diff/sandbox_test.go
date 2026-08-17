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

func TestSandboxParserConfigUsesContextProductVersion(t *testing.T) {
	macOS := sandboxParserConfig(&Context{IsMacOS: true, Version: "26.7"}, nil, nil)
	if macOS.CatalogPlatform != "macOS" || macOS.CatalogOSVersion != "26.7" {
		t.Fatalf(
			"macOS catalog selection = %s %s, want macOS 26.7",
			macOS.CatalogPlatform,
			macOS.CatalogOSVersion,
		)
	}

	iOS := sandboxParserConfig(&Context{Version: "26.7"}, nil, nil)
	if iOS.CatalogPlatform != "iOS" || iOS.CatalogOSVersion != "26.7" {
		t.Fatalf(
			"iOS catalog selection = %s %s, want iOS 26.7",
			iOS.CatalogPlatform,
			iOS.CatalogOSVersion,
		)
	}

	fallback := sandboxParserConfig(&Context{IsMacOS: true, Version: "  "}, nil, nil)
	if fallback.CatalogPlatform != "" || fallback.CatalogOSVersion != "" {
		t.Fatalf(
			"missing product version catalog selection = %q %q, want Darwin-family fallback",
			fallback.CatalogPlatform,
			fallback.CatalogOSVersion,
		)
	}
}
