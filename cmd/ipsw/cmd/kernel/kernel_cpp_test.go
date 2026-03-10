package kernel

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

func TestScannerClassFilter(t *testing.T) {
	t.Parallel()

	if got := scannerClassFilter("IOService", true); got != "" {
		t.Fatalf("scannerClassFilter with inheritance = %q, want empty filter", got)
	}
	if got := scannerClassFilter("IOService", false); got != "IOService" {
		t.Fatalf("scannerClassFilter without inheritance = %q, want IOService", got)
	}
}

func TestPrintInheritanceWithFilteredDisplay(t *testing.T) {
	t.Parallel()

	classes := []cpp.Class{
		{
			Name:      "IOService",
			Bundle:    "com.apple.kernel",
			MetaPtr:   0x30,
			SuperMeta: 0x20,
		},
		{
			Name:      "IORegistryEntry",
			Bundle:    "com.apple.kernel",
			MetaPtr:   0x20,
			SuperMeta: 0x10,
		},
		{
			Name:    "OSObject",
			Bundle:  "com.apple.kernel",
			MetaPtr: 0x10,
		},
	}

	display := filterClassesByName(classes, "IOService")
	if len(display) != 1 {
		t.Fatalf("filterClassesByName returned %d classes, want 1", len(display))
	}

	var out bytes.Buffer
	printInheritance(&out, classes, buildSuperIndex(classes), display[0], 1)

	rendered := out.String()
	if !strings.Contains(rendered, "IORegistryEntry") {
		t.Fatalf("missing direct parent in inheritance output: %q", rendered)
	}
	if !strings.Contains(rendered, "OSObject") {
		t.Fatalf("missing ancestor in inheritance output: %q", rendered)
	}
}
