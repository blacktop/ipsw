package dyld

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestSlideV5PointerTargets(t *testing.T) {
	for _, tt := range []struct {
		name      string
		raw, want uint64
	}{
		{name: "regular", raw: 0x1234, want: 0x180001234},
		{name: "high byte", raw: 0x80<<34 | 0x1234, want: 0x8000000180001234},
		{name: "all high bits", raw: 0xff<<34 | 0x1234, want: 0xff00000180001234},
		{name: "maximum offset", raw: 0x3ffffffff, want: 0x57fffffff},
		{name: "high byte and maximum offset", raw: 0xff<<34 | 0x3ffffffff, want: 0xff0000057fffffff},
		{name: "unused bits", raw: 0x3ff<<42 | 0x1234, want: 0x180001234},
		{name: "authenticated", raw: 1<<63 | 0xffff<<34 | 3<<50 | 0x1234, want: 0x180001234},
		{name: "authenticated maximum offset", raw: 1<<63 | 0xffff<<34 | 3<<50 | 0x3ffffffff, want: 0x57fffffff},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hdr := CacheSlideInfo5{Version: 5, PageSize: 0x1000, PageStartsCount: 2, ValueAdd: 0x180000000}
			var info bytes.Buffer
			if err := binary.Write(&info, binary.LittleEndian, hdr); err != nil {
				t.Fatal(err)
			}
			if err := binary.Write(&info, binary.LittleEndian, []uint16{0x18, DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE}); err != nil {
				t.Fatal(err)
			}
			mapping := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{
				Address: hdr.ValueAdd, Size: 0x2000, FileOffset: 0x1000,
				SlideInfoOffset: 0x100, SlideInfoSize: uint64(info.Len()),
			}}
			data := make([]byte, 0x3000)
			copy(data[mapping.SlideInfoOffset:], info.Bytes())
			// Both pointers have the same target; only the first has a next link
			binary.LittleEndian.PutUint64(data[0x1018:], tt.raw|1<<52)
			binary.LittleEndian.PutUint64(data[0x1020:], tt.raw)
			uuid := types.UUID{1}
			f := &File{
				UUID: uuid, ByteOrder: binary.LittleEndian, AddressToSymbol: NewA2STable(0),
				r: map[types.UUID]io.ReaderAt{uuid: bytes.NewReader(data)},
			}
			rebases, err := f.GetRebaseInfoForPages(uuid, mapping, PageRange{End: 1})
			if err != nil {
				t.Fatal(err)
			}
			if len(rebases) != 2 {
				t.Fatalf("got %d rebases, want 2", len(rebases))
			}
			for i, got := range rebases {
				offset := uint64(0x18 + i*8)
				wantAddr := mapping.Address + offset
				wantOffset := mapping.FileOffset + offset
				if got.Target != tt.want || got.CacheVMAddress != wantAddr || got.CacheFileOffset != wantOffset {
					t.Errorf("rebase %d = target %#x, VM %#x, file offset %#x; want target %#x, VM %#x, file offset %#x",
						i, got.Target, got.CacheVMAddress, got.CacheFileOffset, tt.want, wantAddr, wantOffset)
				}
			}
			if got := hdr.SlidePointer(tt.raw | 0x7ff<<52); got != tt.want {
				t.Errorf("SlidePointer() = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestSlideV5CacheOffsets(t *testing.T) {
	for _, tt := range []struct {
		name      string
		raw, want uint64
	}{
		{name: "zero"},
		{name: "offset bit 32", raw: 1 << 32, want: 1 << 32},
		{name: "offset bit 33", raw: 1 << 33, want: 1 << 33},
		{name: "regular", raw: 0x7ff<<52 | 0xa5<<34 | 0x3ffffffff, want: 0x3ffffffff},
		{name: "authenticated", raw: 1<<63 | 0x7ff<<52 | 3<<50 | 0xbeef<<34 | 0x3ffffffff, want: 0x3ffffffff},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := CacheSlidePointer5(tt.raw).OffsetFromSharedCacheBase(); got != tt.want {
				t.Errorf("OffsetFromSharedCacheBase() = %#x, want %#x", got, tt.want)
			}
		})
	}
}
