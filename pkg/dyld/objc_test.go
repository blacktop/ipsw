package dyld

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

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

func TestGetAllObjcMethods(t *testing.T) {
	data := make([]byte, 0x60)
	binary.LittleEndian.PutUint32(data, 24) // absolute method entry size
	binary.LittleEndian.PutUint32(data[4:], 1)
	binary.LittleEndian.PutUint64(data[8:], 0x100000140)
	binary.LittleEndian.PutUint64(data[16:], 0x100000150)
	binary.LittleEndian.PutUint64(data[24:], 0x100000180)
	copy(data[0x40:], "testMethod\x00")
	copy(data[0x50:], "v16@0:8\x00")
	f := &File{
		AddressToSymbol: NewA2STable(0),
		Images: []*CacheImage{
			objcSectionImage(t, "/usr/lib/libNoMethods.dylib", "", nil, 0),
			objcSectionImage(t, "/usr/lib/libMethods.dylib", "__objc_methlist", data, 32),
		},
	}
	if err := f.GetAllObjcMethods(); err != nil {
		t.Fatal(err)
	}
	if got := f.AddressToSymbol.GetValue(0x100000180); got != "testMethod" {
		t.Fatalf("method symbol = %q, want testMethod", got)
	}
}

func TestGetAllObjCStubs(t *testing.T) {
	// adrp x16, 0x100000000; add x16, x16, #0x180; br x16
	data := make([]byte, 12)
	for i, instruction := range []uint32{0x90000010, 0x91060210, 0xd61f0200} {
		binary.LittleEndian.PutUint32(data[i*4:], instruction)
	}
	f := &File{
		AddressToSymbol: NewA2STable(0),
		Images: []*CacheImage{
			objcSectionImage(t, "/usr/lib/libNoStubs.dylib", "", nil, 0),
			objcSectionImage(t, "/usr/lib/libStubs.dylib", "__objc_stubs", data, uint64(len(data))),
		},
	}
	f.AddressToSymbol.Set(0x100000180, "testSelector")
	if err := f.GetAllObjCStubs(); err != nil {
		t.Fatal(err)
	}
	if got := f.AddressToSymbol.GetValue(0x100000100); got != "j__objc_msgSend(x0, \"testSelector\")" {
		t.Fatalf("stub symbol = %q", got)
	}
}

func TestObjCSectionsRejectTruncatedData(t *testing.T) {
	for _, section := range []string{"__objc_methlist", "__objc_stubs"} {
		t.Run(section, func(t *testing.T) {
			f := &File{
				AddressToSymbol: NewA2STable(0),
				Images: []*CacheImage{
					objcSectionImage(t, "/usr/lib/libMissing.dylib", "", nil, 0),
					objcSectionImage(t, "/usr/lib/libTruncated.dylib", section, []byte{0}, 8),
				},
			}
			var err error
			if section == "__objc_methlist" {
				err = f.GetAllObjcMethods()
			} else {
				err = f.GetAllObjCStubs()
			}
			if err == nil || !strings.Contains(err.Error(), "/usr/lib/libTruncated.dylib") {
				t.Fatalf("expected error identifying truncated image, got %v", err)
			}
		})
	}
}

func objcSectionImage(t *testing.T, name, section string, payload []byte, size uint64) *CacheImage {
	t.Helper()
	data := make([]byte, 0x100+len(payload))
	header := types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Flags: types.DylibInCache}
	header.Put(data, binary.LittleEndian)
	copy(data[0x100:], payload)
	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	m.Loads = append(m.Loads, &macho.Segment{SegmentHeader: macho.SegmentHeader{
		Name: "__TEXT", Addr: 0x100000000, Memsz: uint64(len(data)), Filesz: uint64(len(data)),
	}})
	if section != "" {
		m.Sections = append(m.Sections, &types.Section{SectionHeader: types.SectionHeader{
			Seg: "__TEXT", Name: section, Addr: 0x100000100, Offset: 0x100, Size: size,
		}})
	}
	return &CacheImage{Name: name, m: m}
}

func TestLibObjCImageFindsRelocatedLibObjC(t *testing.T) {
	for _, name := range []string{"/usr/lib/libobjc.A.dylib", "/System/ExclaveKit/usr/lib/libobjc.A.dylib"} {
		t.Run(name, func(t *testing.T) {
			f := libObjCFixture(t, name)
			image, err := f.libObjCImage()
			if err != nil || image.Name != name {
				t.Fatalf("libObjCImage() = %v, %v; want %s", image, err, name)
			}
			if base, err := f.relativeSelectorBase(); err != nil || base != 0x180000320 {
				t.Fatalf("relativeSelectorBase() = %#x, %v; want 0x180000320, nil", base, err)
			}
		})
	}
}

// libObjCFixture builds a one-image cache whose libobjc carries a legacy
// __TEXT.__objc_opt_ro optimization header. It contains no real device data.
func libObjCFixture(t *testing.T, name string) *File {
	t.Helper()
	const base = uint64(0x180000000)
	data := make([]byte, 0x1000)
	write := func(off int, value any) {
		t.Helper()
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
		copy(data[off:off+b.Len()], b.Bytes())
	}
	seg := types.Segment64{
		LoadCmd: types.LC_SEGMENT_64, Len: uint32(binary.Size(types.Segment64{}) + binary.Size(types.Section64{})),
		Addr: base, Memsz: 0x1000, Filesz: 0x1000, Nsect: 1,
	}
	copy(seg.Name[:], "__TEXT")
	sec := types.Section64{Addr: base + 0x200, Offset: 0x200, Size: uint64(binary.Size(ObjcOptT{}))}
	copy(sec.Seg[:], "__TEXT")
	copy(sec.Name[:], "__objc_opt_ro")
	mh := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_DYLIB,
		NCommands: 1, SizeCommands: seg.Len, Flags: types.DylibInCache,
	}
	off := mh.Put(data, binary.LittleEndian)
	write(off, seg)
	write(off+binary.Size(seg), sec)
	write(0x200, ObjcOptT{Version: 16, RelativeMethodSelectorBaseAddressCacheOffset: 0x120})
	f := fileWithSharedRegionStart(base)
	f.ByteOrder = binary.LittleEndian
	f.Mappings = map[types.UUID]cacheMappings{
		f.UUID: {{CacheMappingInfo: CacheMappingInfo{Address: base, Size: uint64(len(data))}}},
	}
	f.r = map[types.UUID]io.ReaderAt{f.UUID: bytes.NewReader(data)}
	f.Images = cacheImages{{Name: name, cache: f, cuuid: f.UUID,
		CacheImageTextInfo: CacheImageTextInfo{LoadAddress: base, TextSegmentSize: uint32(len(data))},
	}}
	return f
}
