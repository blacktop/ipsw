package syms

import (
	"errors"
	"testing"
)

func TestDeviceDatabaseScansRejectBeforeIO(t *testing.T) {
	for _, device := range []string{"Mac99,2", "J992AP"} {
		// A nonexistent input and nil database ensure rejection happens before
		// reading firmware or creating/replacing any database graph.
		if err := ScanForDevice("missing.ipsw", "", "", device, nil); !errors.Is(err, ErrDeviceScopedDatabaseScan) {
			t.Fatalf("ScanForDevice(%q): %v", device, err)
		}
		if err := RescanForDevice("missing.ipsw", "", "", device, nil); !errors.Is(err, ErrDeviceScopedDatabaseScan) {
			t.Fatalf("RescanForDevice(%q): %v", device, err)
		}
	}
}
