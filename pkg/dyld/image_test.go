package dyld

import (
	"bytes"
	"encoding/binary"
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

func TestLocalSymbolsPointerWidth(t *testing.T) {
	for _, tt := range []struct {
		magic string
		size  int
	}{
		{magic: "dyld_v1  arm64e", size: 16},
		{magic: "dyld_v1arm64_32", size: 12},
	} {
		t.Run(tt.magic, func(t *testing.T) {
			values := []uint64{0x12345678, 0x23456789}
			names := []string{"_first", "_second"}
			data := make([]byte, 0x100)
			strings := []byte("\x00")
			for n, value := range values {
				off := 16 + n*tt.size
				binary.LittleEndian.PutUint32(data[off:], uint32(len(strings)))
				data[off+4] = 0x0e
				data[off+5] = 1
				if tt.size == 16 {
					binary.LittleEndian.PutUint64(data[off+8:], value)
				} else {
					binary.LittleEndian.PutUint32(data[off+8:], uint32(value))
				}
				strings = append(strings, names[n]...)
				strings = append(strings, 0)
			}
			copy(data[0x80:], strings)
			uuid := mtypes.UUID{1}
			hdr := CacheHeader{LocalSymbolsOffset: 1}
			copy(hdr.Magic[:], tt.magic)
			f := &File{
				UUID:            uuid,
				Headers:         map[mtypes.UUID]CacheHeader{uuid: hdr},
				r:               map[mtypes.UUID]io.ReaderAt{uuid: bytes.NewReader(data)},
				AddressToSymbol: NewA2STable(0),
			}
			f.LocalSymInfo.NListFileOffset = 16
			f.LocalSymInfo.StringsFileOffset = 0x80
			f.LocalSymInfo.StringsSize = uint32(len(strings))
			img := &CacheImage{Name: "/usr/lib/libSynthetic.dylib", cache: f}
			img.NlistCount = uint32(len(values))
			f.Images = cacheImages{img}

			if name, err := img.FindLocalSymbolAtAddr(values[1]); err != nil || name != names[1] {
				t.Fatalf("FindLocalSymbolAtAddr(%#x) = %q, %v; want %q", values[1], name, err, names[1])
			}
			if err := img.ParseLocalSymbols(false); err != nil {
				t.Fatal(err)
			}
			if len(img.LocalSymbols) != len(values) {
				t.Fatalf("parsed %d local symbols, want %d", len(img.LocalSymbols), len(values))
			}
			for n, sym := range img.LocalSymbols {
				if sym.Name != names[n] || sym.Value != values[n] {
					t.Errorf("symbol %d = %s %#x, want %s %#x", n, sym.Name, sym.Value, names[n], values[n])
				}
			}
		})
	}
}
