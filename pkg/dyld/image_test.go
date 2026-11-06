package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
)

func TestNormalizeCacheSectionOffsets(t *testing.T) {
	const base = 0x180000000
	const fileOffset = 0x10000
	for _, tt := range []struct {
		name   string
		addr   uint64
		size   uint64
		offset uint32
		flags  mtypes.SectionFlag
		want   uint32
	}{
		{"relative text", base + 0x400, 0x100, 0x400, 0, fileOffset + 0x400},
		{"absolute text", base + 0x400, 0x100, fileOffset + 0x400, 0, fileOffset + 0x400},
		{"relative offset overlapping another segment", base + 0x1200, 16, 0x1200, 0, fileOffset + 0x1200},
		{"zero sized boundary", base + 0x1800, 0, 0x1800, 0, fileOffset + 0x1800},
		{"absent zero sized section", 0, 0, 0, 0, 0},
		{"zero fill", base + 0x2000, 0x1000, 0, mtypes.Zerofill, 0},
		{"zero fill with stale offset", base + 0x2000, 0x1000, 0x1234, mtypes.Zerofill, 0},
		{"large zero fill", base + 0x2000, 0x1000, 0, mtypes.GbZerofill, 0},
		{"thread local zero fill", base + 0x2000, 0x1000, 0, mtypes.ThreadLocalZerofill, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			section := &mtypes.Section{SectionHeader: mtypes.SectionHeader{
				Seg: "__TEXT", Name: "__text", Addr: tt.addr, Size: tt.size,
				Offset: tt.offset, Flags: tt.flags,
			}}
			m := &macho.File{
				FileTOC: macho.FileTOC{
					Loads: []macho.Load{
						&macho.Segment{SegmentHeader: macho.SegmentHeader{
							Name: "__TEXT", Addr: base, Offset: fileOffset, Memsz: 0x3000, Filesz: 0x1800,
						}},
						&macho.Segment{SegmentHeader: macho.SegmentHeader{
							Name: "__LINKEDIT", Addr: base + 0x4000, Offset: 0x1000, Memsz: 0x1000, Filesz: 0x1000,
						}},
					},
					Sections: []*mtypes.Section{section},
				},
			}
			if err := normalizeCacheSectionOffsets(m); err != nil {
				t.Fatal(err)
			}
			if section.Offset != tt.want {
				t.Fatalf("offset = %#x, want %#x", section.Offset, tt.want)
			}
			if section.Addr != tt.addr || section.Size != tt.size || section.Flags != tt.flags {
				t.Fatal("normalization changed section VM layout")
			}
			if err := normalizeCacheSectionOffsets(m); err != nil || section.Offset != tt.want {
				t.Fatalf("normalization is not idempotent: %v", err)
			}
		})
	}
}

func TestNormalizeCacheSectionOffsetsRejectsInvalidLayout(t *testing.T) {
	for _, tt := range []struct {
		name   string
		seg    string
		addr   uint64
		size   uint64
		offset uint32
		segOff uint64
	}{
		{"missing segment", "__MISSING", 0x1100, 1, 0x100, 0x2000},
		{"before segment", "__TEXT", 0xfff, 1, 0, 0x2000},
		{"beyond segment", "__TEXT", 0x1201, 0, 0x201, 0x2000},
		{"beyond file backing", "__TEXT", 0x1180, 0x81, 0x180, 0x2000},
		{"overflowing size", "__TEXT", 0x1180, math.MaxUint64, 0x180, 0x2000},
		{"wrong source offset", "__TEXT", 0x1100, 1, 0x80, 0x2000},
		{"overflowing file offset", "__TEXT", 0x1100, 1, 0x100, math.MaxUint64},
		{"overflowing section offset", "__TEXT", 0x1100, 1, 0x100, math.MaxUint32},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := &macho.File{FileTOC: macho.FileTOC{
				Loads: []macho.Load{&macho.Segment{SegmentHeader: macho.SegmentHeader{
					Name: "__TEXT", Addr: 0x1000, Memsz: 0x300, Filesz: 0x200, Offset: tt.segOff,
				}}},
				Sections: []*mtypes.Section{{SectionHeader: mtypes.SectionHeader{
					Seg: tt.seg, Name: "__text", Addr: tt.addr, Size: tt.size, Offset: tt.offset,
				}}},
			}}
			if err := normalizeCacheSectionOffsets(m); err == nil {
				t.Fatal("expected invalid-layout error")
			}
		})
	}
}

func TestExportMachoMixedSectionOffsets(t *testing.T) {
	for _, tt := range []struct {
		name       string
		textOffset uint32
		dataOffset uint64
	}{
		{"relative text", 0xc00, 0x3000},
		{"relative text overlapping data file range", 0xc00, 0xb00},
		{"absolute text", 0x1c00, 0x3000},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const base = uint64(0x180000000)
			const textOffset = uint64(0x1000)
			const linkeditOffset = uint64(0x4000)
			cacheBytes := make([]byte, 0x5000)
			textBytes := []byte{0x1f, 0x20, 0x03, 0xd5}
			dataBytes := []byte{0xaa, 0xbb, 0xcc, 0xdd}
			imageUUID := mtypes.UUID{1, 2, 3, 4}
			var commands bytes.Buffer
			write := func(value any) {
				t.Helper()
				if err := binary.Write(&commands, binary.LittleEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			segment := func(name string, addr, offset, size uint64, section *mtypes.Section64) {
				t.Helper()
				seg := mtypes.Segment64{
					LoadCmd: mtypes.LC_SEGMENT_64, Len: uint32(binary.Size(mtypes.Segment64{})),
					Addr: addr, Offset: offset, Memsz: size, Filesz: size,
				}
				copy(seg.Name[:], name)
				if section != nil {
					seg.Nsect = 1
					seg.Len += uint32(binary.Size(*section))
					copy(section.Seg[:], name)
				}
				write(seg)
				if section != nil {
					write(*section)
				}
			}
			text := mtypes.Section64{
				Addr: base + 0xc00, Size: uint64(len(textBytes)), Offset: tt.textOffset,
			}
			copy(text.Name[:], "__text")
			data := mtypes.Section64{
				Addr: base + 0x4040, Size: uint64(len(dataBytes)), Offset: uint32(tt.dataOffset + 0x40),
			}
			copy(data.Name[:], "__const")
			segment("__TEXT", base, textOffset, 0x1000, &text)
			segment("__DATA_CONST", base+0x4000, tt.dataOffset, 0x200, &data)
			segment("__LINKEDIT", base+0x8000, linkeditOffset, 0x100, nil)
			write(mtypes.UUIDCmd{LoadCmd: mtypes.LC_UUID, Len: 24, UUID: imageUUID})
			write(mtypes.SymtabCmd{
				LoadCmd: mtypes.LC_SYMTAB, Len: 24,
				Symoff: uint32(linkeditOffset), Stroff: uint32(linkeditOffset + 0x80), Strsize: 1,
			})
			write(mtypes.DysymtabCmd{LoadCmd: mtypes.LC_DYSYMTAB, Len: 80})
			header := mtypes.FileHeader{
				Magic: mtypes.Magic64, CPU: mtypes.CPUArm64, SubCPU: 2, Type: mtypes.MH_DYLIB,
				NCommands: 6, SizeCommands: uint32(commands.Len()), Flags: mtypes.DylibInCache,
			}
			headerSize := header.Put(cacheBytes[textOffset:], binary.LittleEndian)
			copy(cacheBytes[textOffset+uint64(headerSize):], commands.Bytes())
			copy(cacheBytes[textOffset+0xc00:], textBytes)
			copy(cacheBytes[tt.dataOffset+0x40:], dataBytes)
			original := bytes.Clone(cacheBytes)
			cache := fileWithSharedRegionStart(base)
			cache.ByteOrder = binary.LittleEndian
			cache.Mappings = map[mtypes.UUID]cacheMappings{cache.UUID: {
				{Address: base, Size: 0x1000, FileOffset: textOffset},
				{Address: base + 0x4000, Size: 0x200, FileOffset: tt.dataOffset},
				{Address: base + 0x8000, Size: 0x100, FileOffset: linkeditOffset},
			}}
			cache.r = map[mtypes.UUID]io.ReaderAt{cache.UUID: bytes.NewReader(cacheBytes)}
			image := &CacheImage{
				Name: "/usr/lib/libSynthetic.dylib", cache: cache, cuuid: cache.UUID,
				LoadAddress: base, TextSegmentSize: 0x1000,
			}
			cache.Images = cacheImages{image}
			m, err := image.GetMacho()
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if got := m.Section("__TEXT", "__text").Offset; got != tt.textOffset {
				t.Fatalf("inspection changed original text offset: %#x", got)
			}
			path := filepath.Join(t.TempDir(), "libSynthetic.dylib")
			if err := ExportMacho(m, path, nil, base, nil); err != nil {
				t.Fatal(err)
			}
			exported, err := macho.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer exported.Close()
			if exported.UUID().UUID != imageUUID {
				t.Fatal("export changed image UUID")
			}
			for _, want := range []struct {
				seg, name string
				addr      uint64
				data      []byte
			}{
				{"__TEXT", "__text", text.Addr, textBytes},
				{"__DATA_CONST", "__const", data.Addr, dataBytes},
			} {
				section := exported.Section(want.seg, want.name)
				if section == nil {
					t.Fatalf("export lost %s.%s", want.seg, want.name)
				}
				got, err := section.Data()
				if err != nil {
					t.Fatal(err)
				}
				if section.Addr != want.addr || !bytes.Equal(got, want.data) {
					t.Fatalf("%s.%s: address = %#x, bytes = %x; want %#x, %x",
						want.seg, want.name, section.Addr, got, want.addr, want.data)
				}
			}
			if !bytes.Equal(cacheBytes, original) {
				t.Fatal("export changed original cache bytes")
			}
		})
	}
}

func TestExportMachoRejectsInvalidSectionsBeforeWriting(t *testing.T) {
	m := &macho.File{FileTOC: macho.FileTOC{Sections: []*mtypes.Section{
		{SectionHeader: mtypes.SectionHeader{Seg: "__TEXT", Name: "__text", Size: 1}},
	}}}
	path := filepath.Join(t.TempDir(), "invalid.dylib")
	err := ExportMacho(m, path, nil, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid cached sections: __TEXT.__text") {
		t.Fatalf("expected contextual invalid-section error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid export created an output file: %v", err)
	}
}

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
				data[off+5] = uint8(1 - n) // Exercise both section 1 and NO_SECT.
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
			img.pm = &macho.File{}
			img.pm.Sections = []*mtypes.Section{{Addr: values[0], Size: 0x1000}}
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

func TestLocalSymbolsSectionFilter(t *testing.T) {
	for _, tt := range []struct {
		name       string
		sect       uint8
		value      uint64
		size       int
		allDropped bool
	}{
		{name: "empty_section", sect: 1, value: 0x1000, size: 16},
		{name: "missing_section_3", sect: 3, value: 0x1000, size: 16},
		{name: "missing_section_255", sect: 255, value: 0x1000, size: 16},
		{name: "below_section", sect: 2, value: 0x100f, size: 16},
		{name: "at_section_end", sect: 2, value: 0x1110, size: 16},
		{name: "above_section", sect: 2, value: 0x1111, size: 16},
		{name: "32_bit_outside_section", sect: 2, value: 0x1110, size: 12},
		{name: "all_dropped", sect: 2, value: 0x1110, size: 16, allDropped: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// One stale local precedes a valid local, just as in the .symbols
			// file after the builder empties __objc_stubs.
			data := make([]byte, 0x100)
			pool := []byte("\x00_stale\x00_normal\x00")
			for n, section := range []uint8{tt.sect, 2} {
				off := 16 + n*tt.size
				binary.LittleEndian.PutUint32(data[off:], uint32(1+n*7))
				data[off+4] = 0x0e
				data[off+5] = section
				value := tt.value
				if n == 1 {
					value = 0x1010 // The inclusive section start is kept.
				}
				if tt.size == 16 {
					binary.LittleEndian.PutUint64(data[off+8:], value)
				} else {
					binary.LittleEndian.PutUint32(data[off+8:], uint32(value))
				}
			}
			copy(data[0x80:], pool)
			hdr := CacheHeader{LocalSymbolsOffset: 1}
			if tt.size == 16 {
				copy(hdr.Magic[:], "dyld_v1  arm64e")
			} else {
				copy(hdr.Magic[:], "dyld_v1arm64_32")
			}
			f := fileReading(data)
			f.Headers = map[mtypes.UUID]CacheHeader{f.UUID: hdr}
			f.LocalSymInfo.NListFileOffset = 16
			f.LocalSymInfo.StringsFileOffset = 0x80
			f.LocalSymInfo.StringsSize = uint32(len(pool))
			img := &CacheImage{Name: "/usr/lib/libSynthetic.dylib", cache: f}
			img.NlistCount = 2
			if tt.allDropped {
				img.NlistCount = 1
			}
			img.pm = &macho.File{}
			img.pm.Sections = []*mtypes.Section{
				{Name: "__objc_stubs", Seg: "__TEXT", Size: 0},
				{Name: "__text", Seg: "__TEXT", Addr: 0x1010, Size: 0x100},
			}
			f.Images = cacheImages{img}

			if name, err := img.FindLocalSymbolAtAddr(tt.value); err == nil || name != "" {
				t.Fatalf("stale lookup = %q, %v; want no symbol", name, err)
			}
			if tt.allDropped {
				_, buf, size, err := img.localNlistBuffer()
				if err != nil || len(buf) != 0 || size != tt.size {
					t.Fatalf("all-dropped buffer = %x, %d, %v", buf, size, err)
				}
				if err := img.ParseLocalSymbols(false); err != nil || len(img.LocalSymbols) != 0 {
					t.Fatalf("all-dropped locals = %v, %v", img.LocalSymbols, err)
				}
				return
			}
			if name, err := img.FindLocalSymbolAtAddr(0x1010); err != nil || name != "_normal" {
				t.Fatalf("normal lookup = %q, %v", name, err)
			}
			if err := img.ParseLocalSymbols(false); err != nil {
				t.Fatal(err)
			}
			if len(img.LocalSymbols) != 1 || img.LocalSymbols[0].Name != "_normal" {
				t.Fatalf("published locals = %v; want only _normal", img.LocalSymbols)
			}
			if name, ok := f.AddressToSymbol.Get(tt.value); ok {
				t.Fatalf("published stale a2s entry %q", name)
			}
			if name, ok := f.AddressToSymbol.Get(0x1010); !ok || name != "_normal" {
				t.Fatalf("normal a2s entry = %q, %v", name, ok)
			}
		})
	}
}

func TestLocalSymbolsPartialMachoFailureKeepsEntries(t *testing.T) {
	data := make([]byte, 16+3*16)
	for n, sect := range []uint8{0, 1, 255} {
		off := 16 + n*16
		binary.LittleEndian.PutUint32(data[off:], uint32(n+1))
		data[off+4] = 0x0e
		data[off+5] = sect
		binary.LittleEndian.PutUint64(data[off+8:], uint64(0x1000+n*16))
	}
	f := fileReading(data)
	hdr := CacheHeader{LocalSymbolsOffset: 1}
	copy(hdr.Magic[:], "dyld_v1  arm64e")
	f.Headers = map[mtypes.UUID]CacheHeader{f.UUID: hdr}
	f.LocalSymInfo.NListFileOffset = 16
	img := &CacheImage{Name: "/usr/lib/libMissing.dylib", cache: f}
	img.NlistCount = 3
	f.Images = cacheImages{img}
	// No image mappings are available, but the local-symbol table is readable.
	if _, err := img.GetPartialMacho(); err == nil {
		t.Fatal("expected partial Mach-O lookup to fail")
	}
	uuid, buf, size, err := img.localNlistBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if uuid != f.UUID || size != 16 || !bytes.Equal(buf, data[16:]) {
		t.Fatalf("localNlistBuffer() = %v, %x, %d; want %v, %x, 16", uuid, buf, size, f.UUID, data[16:])
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
	mapping := &CacheMappingWithSlideInfo{
		Address: hdr.ValueAdd, Size: 0x2000, FileOffset: 0x1000,
		SlideInfoOffset: 0x100, SlideInfoSize: uint64(info.Len())}
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
			seg := &macho.Segment{Name: "__DATA", Addr: mapping.Address, Filesz: tt.filesz}
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
			{Address: base, Size: fileSize},
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
				Name: uint32(strings.Index(pool, "\x00"+name+"\x00") + 1), Type: mtypes.N_SECT | mtypes.N_EXT, Sect: 1,
				Value: base + hdrOff + uint64(0x10*n),
			}
			if err := binary.Write(&buf, binary.LittleEndian, sym); err != nil {
				t.Fatal(err)
			}
		}
		copy(data[symOff:], buf.Bytes())

		images[k] = &CacheImage{
			Name:        fmt.Sprintf("/usr/lib/libSynthetic%d.dylib", k),
			LoadAddress: base + hdrOff, TextSegmentSize: 0x1000,
			cache: f,
			cuuid: uuid,
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

func TestSlidePointerMappingBoundaries(t *testing.T) {
	uuid := mtypes.UUID{1}
	f := &File{
		MappingsWithSlideInfo: map[mtypes.UUID]cacheMappingsWithSlideInfo{uuid: {
			{Address: 0x1000, Size: 0x100},
		}},
		SlideInfo: CacheSlideInfo2{ValueAdd: 0x100000, DeltaMask: 0xff00000000000000},
	}
	image := &CacheImage{cache: f}
	for _, tt := range []struct{ address, want uint64 }{
		{0, 0}, {0x1000, 0x1000}, {0x10ff, 0x10ff}, {0x1100, 0x101100}, {0x8000000000000010, 0x100010},
	} {
		if got := image.SlidePointer(tt.address); got != tt.want {
			t.Fatalf("SlidePointer(%#x)=%#x want=%#x", tt.address, got, tt.want)
		}
	}
	// New subcache registration must remain visible without rebuilding an index.
	f.MappingsWithSlideInfo[mtypes.UUID{2}] = cacheMappingsWithSlideInfo{{Address: 0x1100, Size: 0x100}}
	if got := image.SlidePointer(0x1100); got != 0x1100 {
		t.Fatalf("new mapping returned %#x", got)
	}
}

func TestSlidePointerEncodedDoesNotAllocate(t *testing.T) {
	image := &CacheImage{cache: &File{SlideInfo: CacheSlideInfo2{ValueAdd: 0x100000, DeltaMask: 0xff00000000000000}}}
	if got := testing.AllocsPerRun(100, func() { _ = image.SlidePointer(0x8000000000000010) }); got != 0 {
		t.Fatalf("encoded pointer allocated %v times", got)
	}
}

func TestSlidePointerMappingHint(t *testing.T) {
	mappings := cacheMappingsWithSlideInfo{
		{Address: 0x1000, Size: 0x100},
		{Address: 0x2000, Size: 0x100},
	}
	image := &CacheImage{cache: &File{
		MappingsWithSlideInfo: map[mtypes.UUID]cacheMappingsWithSlideInfo{{1}: mappings},
		SlideInfo:             CacheSlideInfo2{ValueAdd: 0x100000, DeltaMask: 0xff00000000000000},
	}}
	for _, mapping := range mappings {
		for _, addr := range []uint64{mapping.Address, mapping.Address + mapping.Size - 1} {
			if got := image.SlidePointer(addr); got != addr {
				t.Fatalf("SlidePointer(%#x) = %#x", addr, got)
			}
			if image.lastMapping.Load() != mapping {
				t.Fatal("hint did not retain the latest matching mapping")
			}
		}
	}
	for _, tt := range []struct{ addr, want uint64 }{{0, 0}, {0x2100, 0x102100}, {0x8000000000000010, 0x100010}} {
		if got := image.SlidePointer(tt.addr); got != tt.want {
			t.Fatalf("SlidePointer(%#x) = %#x, want %#x", tt.addr, got, tt.want)
		}
		if image.lastMapping.Load() != mappings[1] {
			t.Fatal("non-mapping pointer discarded the hint")
		}
	}
}

func TestSlidePointerConcurrentImages(t *testing.T) {
	f := &File{
		MappingsWithSlideInfo: make(map[mtypes.UUID]cacheMappingsWithSlideInfo),
		SlideInfo:             CacheSlideInfo2{ValueAdd: 0x100000, DeltaMask: 0xff00000000000000},
	}
	for n := range 4 {
		f.MappingsWithSlideInfo[mtypes.UUID{byte(n + 1)}] = cacheMappingsWithSlideInfo{{Address: 0x1000 + uint64(n)*0x1000, Size: 0x100}}
	}
	images := [2]*CacheImage{{cache: f}, {cache: f}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for n, image := range images {
		// Two readers per image exercise both independent hints and concurrent
		// loads/stores of a shared hint. The mapping registry stays read-only.
		for reader := range 2 {
			wg.Go(func() {
				<-start
				for call := range 1000 {
					addr := 0x1000 + uint64(2*n+(call+reader)%2)*0x1000 + uint64(call%0x100)
					if got := image.SlidePointer(addr); got != addr {
						t.Errorf("image %d: SlidePointer(%#x) = %#x", n, addr, got)
						return
					}
					if got := image.SlidePointer(0x8000000000000010); got != 0x100010 {
						t.Errorf("image %d: encoded pointer = %#x, want 0x100010", n, got)
						return
					}
				}
			})
		}
	}
	close(start)
	wg.Wait()
	for n, image := range images {
		mapping := image.lastMapping.Load()
		if mapping == nil || (mapping.Address != 0x1000+uint64(2*n)*0x1000 && mapping.Address != 0x2000+uint64(2*n)*0x1000) {
			t.Errorf("image %d did not retain its own mapping hint", n)
		}
	}
}

func TestSlidePointerMappingAlternation(t *testing.T) {
	mappings := cacheMappingsWithSlideInfo{
		{Address: 0x1000, Size: 0x100},
		{Address: 0x2000, Size: 0x100},
		{Address: 0x3000, Size: 0x100},
	}
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%v", reverse), func(t *testing.T) {
			image := &CacheImage{cache: &File{
				MappingsWithSlideInfo: map[mtypes.UUID]cacheMappingsWithSlideInfo{{1}: mappings},
			}}
			fallbacks := 0
			lookup := func(addr uint64) (mtypes.UUID, *CacheMappingWithSlideInfo) {
				fallbacks++
				return image.cache.mappingForVMAddress(addr)
			}
			for call := range 1000 {
				n := call % 2
				if reverse {
					n = 1 - n
				}
				addr := mappings[n].Address + uint64(call%0x100)
				if got := image.slidePointer(addr, lookup); got != addr {
					t.Fatalf("call %d: got %#x, want %#x", call, got, addr)
				}
				if fallbacks > 2 {
					t.Fatalf("call %d: %d fallbacks, want at most two", call, fallbacks)
				}
			}
			if fallbacks != 2 {
				t.Fatalf("got %d cold fallbacks, want two", fallbacks)
			}
			// Exercise eviction with each slot as the most recently useful one.
			for _, hot := range []int{0, 1} {
				image.slidePointer(mappings[hot].Address, lookup)
				image.slidePointer(mappings[2].Address, lookup)
				before := fallbacks
				image.slidePointer(mappings[hot].Address, lookup)
				if fallbacks != before {
					t.Fatalf("evicted most recently useful mapping %d", hot)
				}
			}
		})
	}
}

// A stripped cache image with no LC_SYMTAB is still named by its export trie,
// and parsing its public symbols must not dereference the missing symtab.
func TestPublicSymbolsWithoutSymtab(t *testing.T) {
	data := []byte{0, 1, '_', 's', 'y', 'n', 't', 'h', 'e', 't', 'i', 'c', 0, 14, 2, 0, 0x20, 0}
	f := fileReading(data)
	f.Mappings = map[mtypes.UUID]cacheMappings{f.UUID: {&CacheMapping{Address: 0x1000, Size: uint64(len(data))}}}
	img := objcSectionImage(t, "/usr/lib/libSynthetic.dylib", "", nil, 0)
	img.cache, img.cuuid = f, f.UUID
	img.LoadAddress = 0x100000000
	img.CacheImageInfoExtra = CacheImageInfoExtra{ExportsTrieAddr: 0x1000, ExportsTrieSize: uint32(len(data))}
	if img.m.Symtab != nil {
		t.Fatal("fixture unexpectedly has a symtab")
	}
	exports, err := f.GetExportTrieSymbols(img)
	if err != nil || len(exports) != 1 || exports[0].Name != "_synthetic" {
		t.Fatalf("fixture exports = %v, %v", exports, err)
	}
	if err := img.ParsePublicSymbols(false); err != nil {
		t.Fatal(err)
	}
	if name, ok := f.AddressToSymbol.Get(0x100000020); !ok || name != "_synthetic" {
		t.Fatalf("name = %q (%v)", name, ok)
	}
}
