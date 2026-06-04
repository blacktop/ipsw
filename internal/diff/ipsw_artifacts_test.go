package diff

import (
	"os"
	"testing"

	"github.com/blacktop/go-macho"
)

// TestKernelKeySegmentsEqualMatchesRebuiltKernel exercises the kernelcache
// short-circuit against two real extracted kernelcaches. The files are
// expected at /tmp/kc-diff/{23F77,23F81}/<build>__iPhone18,1/kernelcache...
// (produced by `ipsw extract --kernel`). When the fixtures are absent the
// test is skipped — it's a manual regression check, not part of CI.
func TestKernelKeySegmentsEqualMatchesRebuiltKernel(t *testing.T) {
	oldPath := "/tmp/kc-diff/23F77/23F77__iPhone18,1/kernelcache.release.iPhone18,1"
	newPath := "/tmp/kc-diff/23F81/23F81__iPhone18,1/kernelcache.release.iPhone18,1"

	for _, p := range []string{oldPath, newPath} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("fixture missing (%s); extract via `ipsw extract --kernel`", p)
		}
	}

	oldKC, err := macho.Open(oldPath)
	if err != nil {
		t.Fatalf("macho.Open(old) = %v", err)
	}
	defer oldKC.Close()

	newKC, err := macho.Open(newPath)
	if err != nil {
		t.Fatalf("macho.Open(new) = %v", err)
	}
	defer newKC.Close()

	// File bytes differ (UUID + build-root strings + plist digests), but the
	// kernel code (__TEXT_EXEC) and constant data (__DATA_CONST, where the
	// sandbox profile collection lives) should match for this 26.5 → 26.5.1
	// rebuild-only release.
	if !kernelKeySegmentsEqual(oldKC, newKC) {
		t.Fatal("kernelKeySegmentsEqual(23F77, 23F81) = false; expected true (kernel is functionally identical, only wrapper metadata changed)")
	}
}
