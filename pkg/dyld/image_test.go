package dyld

import "testing"

func TestRelativeSelectorBaseSkipsOldLibObjC(t *testing.T) {
	img := &CacheImage{
		Name:  "/usr/lib/libobjc.A.dylib",
		cache: &File{},
	}

	base, err := img.relativeSelectorBase()
	if err != nil {
		t.Fatalf("relativeSelectorBase returned error: %v", err)
	}
	if base != 0 {
		t.Fatalf("expected zero relative selector base, got %#x", base)
	}
}

func TestRelativeSelectorBaseMissingLibObjC(t *testing.T) {
	img := &CacheImage{
		Name:  "/usr/lib/libA.dylib",
		cache: &File{},
	}

	base, err := img.relativeSelectorBase()
	if err != nil {
		t.Fatalf("relativeSelectorBase returned error: %v", err)
	}
	if base != 0 {
		t.Fatalf("expected zero relative selector base, got %#x", base)
	}
}

func TestReexportLibraryName(t *testing.T) {
	libs := []string{"/usr/lib/libA.dylib", "/usr/lib/libB.dylib"}

	name, err := reexportLibraryName(libs, 2)
	if err != nil {
		t.Fatalf("reexportLibraryName returned error: %v", err)
	}
	if name != "/usr/lib/libB.dylib" {
		t.Fatalf("expected libB, got %s", name)
	}

	for _, ordinal := range []uint64{0, 3} {
		if _, err := reexportLibraryName(libs, ordinal); err == nil {
			t.Fatalf("expected error for ordinal %d", ordinal)
		}
	}
}
