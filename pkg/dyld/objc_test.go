package dyld

import "testing"

// TestObjCOptimizationHeaderGetVersionReportsHashTableV16 verifies that the NEW
// LargeSharedCache header always reports v16 for hash-table parsing, regardless
// of its own (independently versioned) header layout. StringHash.Read switches
// to the v16 layout on GetVersion() >= 16, so a newer header version (e.g. the
// v4 introduced in iOS 27) must NOT fall through to the legacy stringHash.
func TestObjCOptimizationHeaderGetVersionReportsHashTableV16(t *testing.T) {
	for _, headerVersion := range []uint32{1, 2, 3, 4, 16} {
		o := &ObjCOptimizationHeader{Version: headerVersion}
		if got := o.GetVersion(); got != 16 {
			t.Errorf("header v%d: GetVersion() = %d, want 16", headerVersion, got)
		}
	}
}
