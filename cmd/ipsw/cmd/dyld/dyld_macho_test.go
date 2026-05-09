package dyld

import "testing"

func TestReexportLibraryName(t *testing.T) {
	libs := []string{"/usr/lib/libA.dylib", "/usr/lib/libB.dylib"}

	name, err := reexportLibraryName(libs, 1)
	if err != nil {
		t.Fatalf("reexportLibraryName returned error: %v", err)
	}
	if name != "/usr/lib/libA.dylib" {
		t.Fatalf("expected libA, got %s", name)
	}

	for _, ordinal := range []uint64{0, 3} {
		if _, err := reexportLibraryName(libs, ordinal); err == nil {
			t.Fatalf("expected error for ordinal %d", ordinal)
		}
	}
}
