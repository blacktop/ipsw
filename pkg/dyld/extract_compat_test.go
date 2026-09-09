package dyld_test

import (
	"path/filepath"
	"testing"

	"github.com/blacktop/ipsw/pkg/dyld"
)

func TestExtractLegacySignature(t *testing.T) {
	// Downstream callers may use Extract directly or as a function value.
	var extract func(string, string, string, []string, bool, bool) ([]string, error) = dyld.Extract
	root := t.TempDir()
	paths, err := extract(filepath.Join(root, "missing.ipsw"), root, "", nil, false, false)
	if err == nil || len(paths) != 0 {
		t.Fatalf("missing IPSW returned paths %v, error %v", paths, err)
	}
}
