package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
)

func TestPartialRelativeSelectorBaseSkipsLibObjC(t *testing.T) {
	for _, name := range []string{"/usr/lib/libobjc.A.dylib", "/System/ExclaveKit/usr/lib/libobjc.A.dylib", "/System/NewKit/usr/lib/LIBOBJC.A.DYLIB"} {
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

// fileReading returns a one-file cache whose reader serves data
func fileReading(data []byte) *File {
	uuid := mtypes.UUID{1}
	return &File{
		UUID:            uuid,
		ByteOrder:       binary.LittleEndian,
		AddressToSymbol: NewA2STable(0),
		r:               map[mtypes.UUID]io.ReaderAt{uuid: bytes.NewReader(data)},
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
			hdr := CacheHeader{LocalSymbolsOffset: 1}
			copy(hdr.Magic[:], tt.magic)
			f := fileReading(data)
			f.Headers = map[mtypes.UUID]CacheHeader{f.UUID: hdr}
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

func TestSegmentRebases(t *testing.T) {
	// one v5 page with two 8-byte pointers at offsets 0x18 and 0x20
	hdr := CacheSlideInfo5{Version: 5, PageSize: 0x1000, PageStartsCount: 2, ValueAdd: 0x180000000}
	var info bytes.Buffer
	for _, v := range []any{hdr, []uint16{0x18, DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE}} {
		if err := binary.Write(&info, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	mapping := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{
		Address: hdr.ValueAdd, Size: 0x2000, FileOffset: 0x1000,
		SlideInfoOffset: 0x100, SlideInfoSize: uint64(info.Len()),
	}}
	data := make([]byte, 0x3000)
	copy(data[mapping.SlideInfoOffset:], info.Bytes())
	binary.LittleEndian.PutUint64(data[0x1018:], 0x1234|1<<52)
	binary.LittleEndian.PutUint64(data[0x1020:], 0x5678)
	f := fileReading(data)
	header := CacheHeader{}
	copy(header.Magic[:], "dyld_v1  arm64e")
	f.Headers = map[mtypes.UUID]CacheHeader{f.UUID: header}
	f.MappingsWithSlideInfo = map[mtypes.UUID]cacheMappingsWithSlideInfo{f.UUID: {mapping}}
	f.SlideInfo = hdr
	img := &CacheImage{Name: "/usr/lib/libSynthetic.dylib", cache: f}

	for _, tt := range []struct {
		name    string
		filesz  uint64
		want    int
		wantErr bool
	}{
		{name: "both pointers fit", filesz: 0x28, want: 2},
		{name: "pointer straddling the end is dropped", filesz: 0x24, want: 1},
		{name: "segment past its mapping", filesz: 0x3000, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			seg := &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__DATA", Addr: mapping.Address, Filesz: tt.filesz}}
			rebases, err := img.SegmentRebases(seg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SegmentRebases(filesz %#x) returned %d rebases, want error", tt.filesz, len(rebases))
				}
				return
			}
			if err != nil || len(rebases) != tt.want {
				t.Fatalf("SegmentRebases(filesz %#x) = %d rebases, %v; want %d", tt.filesz, len(rebases), err, tt.want)
			}
		})
	}
}

// sharedPoolCache builds a one-file cache holding two dylibs whose LC_SYMTABs
// point at one string pool in a shared __LINKEDIT, as every dylib in a real
// cache does. Image k's symtab holds the names in want[k].
func sharedPoolCache(t *testing.T, want [2][]string) (*countingReaderAt, [2]*CacheImage) {
	t.Helper()
	const (
		base     = 0x180000000
		linkedit = 0x3000
		poolOff  = linkedit + 0x100
		fileSize = 0x4000
	)
	pool := "\x00"
	for _, names := range want {
		for _, name := range names {
			pool += name + "\x00"
		}
	}
	data := make([]byte, fileSize)
	copy(data[poolOff:], pool)

	uuid := mtypes.UUID{1}
	r := &countingReaderAt{data: data, watchOff: poolOff, watchEnd: poolOff + int64(len(pool))}
	f := &File{
		UUID:      uuid,
		ByteOrder: binary.LittleEndian,
		Mappings: map[mtypes.UUID]cacheMappings{uuid: {
			{CacheMappingInfo: CacheMappingInfo{Address: base, Size: fileSize}},
		}},
		r: map[mtypes.UUID]io.ReaderAt{uuid: r},
	}

	var images [2]*CacheImage
	for k, names := range want {
		hdrOff := uint64(0x1000 * (k + 1))
		symOff := uint32(linkedit + 0x20*k)
		segment := func(name string, off uint64) mtypes.Segment64 {
			seg := mtypes.Segment64{LoadCmd: mtypes.LC_SEGMENT_64, Len: 72, Addr: base + off, Memsz: 0x1000, Offset: off, Filesz: 0x1000}
			copy(seg.Name[:], name)
			return seg
		}
		var buf bytes.Buffer
		for _, v := range []any{
			mtypes.FileHeader{Magic: mtypes.Magic64, CPU: mtypes.CPUArm64, Type: mtypes.MH_DYLIB, NCommands: 3, SizeCommands: 72*2 + 24},
			segment("__TEXT", hdrOff),
			segment("__LINKEDIT", linkedit),
			mtypes.SymtabCmd{LoadCmd: mtypes.LC_SYMTAB, Len: 24, Symoff: symOff, Nsyms: 2, Stroff: poolOff, Strsize: uint32(len(pool))},
		} {
			if err := binary.Write(&buf, binary.LittleEndian, v); err != nil {
				t.Fatal(err)
			}
		}
		copy(data[hdrOff:], buf.Bytes())

		buf.Reset()
		for n, name := range names {
			sym := mtypes.Nlist64{
				Nlist: mtypes.Nlist{Name: uint32(strings.Index(pool, "\x00"+name+"\x00") + 1), Type: mtypes.N_SECT | mtypes.N_EXT, Sect: 1},
				Value: base + hdrOff + uint64(0x10*n),
			}
			if err := binary.Write(&buf, binary.LittleEndian, sym); err != nil {
				t.Fatal(err)
			}
		}
		copy(data[symOff:], buf.Bytes())

		images[k] = &CacheImage{
			Name:               fmt.Sprintf("/usr/lib/libSynthetic%d.dylib", k),
			CacheImageTextInfo: CacheImageTextInfo{LoadAddress: base + hdrOff, TextSegmentSize: 0x1000},
			cache:              f,
			cuuid:              uuid,
		}
		f.Images = append(f.Images, images[k])
	}
	return r, images
}

// TestGetMachoSharesStringPool checks that GetMacho serves symbol names out
// of the cache's shared string pool: a second dylib pointing at the same
// pool gets its names without reading the pool again.
func TestGetMachoSharesStringPool(t *testing.T) {
	want := [2][]string{{"_a_one", "_a_two"}, {"_b_one", "_b_two"}}
	r, images := sharedPoolCache(t, want)
	names := func(img *CacheImage) []string {
		t.Helper()
		m, err := img.GetMacho()
		if err != nil {
			t.Fatalf("%s: %v", img.Name, err)
		}
		if m.Symtab == nil {
			t.Fatalf("%s: no symtab", img.Name)
		}
		var got []string
		for _, sym := range m.Symtab.Syms {
			got = append(got, sym.Name)
		}
		return got
	}

	if got := names(images[0]); !slices.Equal(got, want[0]) {
		t.Fatalf("first image symbols = %q, want %q", got, want[0])
	}
	if r.reads == 0 {
		t.Fatal("first image did not read the string pool")
	}
	reads := r.reads
	if got := names(images[1]); !slices.Equal(got, want[1]) {
		t.Fatalf("second image symbols = %q, want %q", got, want[1])
	}
	if r.reads != reads {
		t.Fatalf("second image read the shared string pool %d more times, want 0", r.reads-reads)
	}
}
