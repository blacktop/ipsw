package dyld

import (
	"fmt"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestPartialRelativeSelectorBaseSkipsLibObjC(t *testing.T) {
	img := &CacheImage{
		Name:  "/usr/lib/libobjc.A.dylib",
		cache: &File{IsDyld4: true},
	}

	base, err := img.partialRelativeSelectorBase()
	if err != nil {
		t.Fatalf("partialRelativeSelectorBase returned error: %v", err)
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

func TestLegacyRelativeSelectorBaseUsesObjCOptRoAddr(t *testing.T) {
	for _, version := range []uint32{15, 16} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			f := fileWithSharedRegionStart(0x180000000)
			f.objcOptRoAddr = 0x1a0004000
			opt := &ObjcOptT{
				Version: version,
				RelativeMethodSelectorBaseAddressCacheOffset: 0x120,
			}

			base := f.relativeSelectorBaseForOptimization(opt)
			if base != 0x1a0004120 {
				t.Fatalf("expected legacy relative selector base %#x, got %#x", uint64(0x1a0004120), base)
			}
		})
	}
}

func TestNewRelativeSelectorBaseAddsSharedRegionStart(t *testing.T) {
	f := fileWithSharedRegionStart(0x180000000)
	opt := &ObjCOptimizationHeader{
		RelativeMethodSelectorBaseAddressOffset: 0x40120,
	}

	base := f.relativeSelectorBaseForOptimization(opt)
	if base != 0x180040120 {
		t.Fatalf("expected new relative selector base %#x, got %#x", uint64(0x180040120), base)
	}
}

func fileWithSharedRegionStart(sharedRegionStart uint64) *File {
	uuid := mtypes.UUID{1}
	return &File{
		UUID: uuid,
		Headers: map[mtypes.UUID]CacheHeader{
			uuid: {
				SharedRegionStart: sharedRegionStart,
			},
		},
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
