package dyld

import (
	"fmt"
	"io"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestPartialRelativeSelectorBaseSkipsLibObjC(t *testing.T) {
	for _, name := range []string{"/usr/lib/libobjc.A.dylib", "/System/ExclaveKit/usr/lib/libobjc.A.dylib"} {
		t.Run(name, func(t *testing.T) {
			// A nil cache detects attempts to look up selector metadata
			img := &CacheImage{Name: name}
			base, err := img.partialRelativeSelectorBase()
			if err != nil || base != 0 {
				t.Fatalf("partialRelativeSelectorBase() = %#x, %v; want 0, nil", base, err)
			}
		})
	}
}

func TestPartialRelativeSelectorBaseDoesNotReadTrie(t *testing.T) {
	f := libObjCFixture(t, "/usr/lib/libobjc.A.dylib", false)
	want, err := f.relativeSelectorBase()
	if err != nil {
		t.Fatal(err)
	}
	hdr := f.Headers[f.UUID]
	hdr.MappingOffset = 0x1000
	hdr.DylibsTrieAddr = 0x180000800
	hdr.DylibsTrieSize = 16
	f.Headers[f.UUID] = hdr
	r := &countingReaderAt{ReaderAt: f.r[f.UUID]}
	f.r[f.UUID] = r
	img := &CacheImage{Name: "/usr/lib/libA.dylib", cache: f}

	base, err := img.partialRelativeSelectorBase()
	if err != nil || base != want {
		t.Fatalf("partialRelativeSelectorBase() = %#x, %v; want %#x, nil", base, err, want)
	}
	// Reusing the selector base must not reread the image-name trie
	if r.reads != 0 {
		t.Fatalf("partialRelativeSelectorBase read the cache %d times", r.reads)
	}
}

type countingReaderAt struct {
	io.ReaderAt
	reads int
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	return r.ReaderAt.ReadAt(p, off)
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
