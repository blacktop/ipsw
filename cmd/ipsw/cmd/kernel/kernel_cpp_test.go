package kernel

import (
	"bytes"
	"strings"
	"testing"
	"time"

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

func TestBuildKernelCppTimingLogLinesWithoutTrace(t *testing.T) {
	t.Parallel()

	scanner := cpp.NewScanner(nil, cpp.Config{})
	lines := buildKernelCppTimingLogLines(scanner, false, time.Second, 2*time.Second, 3*time.Second, 6*time.Second)

	if len(lines) != 2 {
		t.Fatalf("buildKernelCppTimingLogLines returned %d lines, want 2", len(lines))
	}
	if !strings.HasPrefix(lines[0], "scan stats:") {
		t.Fatalf("first line = %q, want scan stats summary", lines[0])
	}
	if strings.Contains(strings.Join(lines, "\n"), "trace:") {
		t.Fatalf("unexpected trace lines when includeTrace=false: %#v", lines)
	}
}

func TestBuildKernelCppTimingLogLinesWithTrace(t *testing.T) {
	t.Parallel()

	scanner := cpp.NewScanner(nil, cpp.Config{})
	lines := buildKernelCppTimingLogLines(scanner, true, time.Second, 2*time.Second, 3*time.Second, 6*time.Second)

	if len(lines) < 4 {
		t.Fatalf("buildKernelCppTimingLogLines returned %d lines, want trace block", len(lines))
	}
	if !strings.HasPrefix(lines[0], "scan stats:") {
		t.Fatalf("first line = %q, want scan stats summary", lines[0])
	}
	if !strings.Contains(strings.Join(lines, "\n"), "trace: anchors") {
		t.Fatalf("trace output missing anchors line: %#v", lines)
	}
	if !strings.HasPrefix(lines[len(lines)-1], "timings: open=") {
		t.Fatalf("last line = %q, want timings summary", lines[len(lines)-1])
	}
}
