package dyld

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestSlidePagesForRange(t *testing.T) {
	for _, tt := range []struct {
		name               string
		offset, size       uint64
		wantStart, wantEnd uint64
	}{
		{name: "first byte", offset: 0, size: 1, wantStart: 0, wantEnd: 1},
		{name: "exactly one page", offset: 0, size: 0x1000, wantStart: 0, wantEnd: 1},
		{name: "one byte into the next page", offset: 0, size: 0x1001, wantStart: 0, wantEnd: 2},
		{name: "unaligned start and end", offset: 0x1800, size: 0x1000, wantStart: 1, wantEnd: 3},
		{name: "aligned end excludes the next page", offset: 0x3000, size: 0x2000, wantStart: 3, wantEnd: 5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start, end := SlidePagesForRange(tt.offset, tt.size, 0x1000)
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("SlidePagesForRange(%#x, %#x) = [%d, %d), want [%d, %d)",
					tt.offset, tt.size, start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestSlidePageRange(t *testing.T) {
	for _, tt := range []struct {
		name               string
		start, end         uint64
		count              int
		wantStart, wantEnd uint64
		wantErr            bool
	}{
		{name: "zero end selects every page", start: 0, end: 0, count: 4, wantStart: 0, wantEnd: 4},
		{name: "last page is kept", start: 3, end: 4, count: 4, wantStart: 3, wantEnd: 4},
		{name: "end past the table is clamped", start: 1, end: 9, count: 4, wantStart: 1, wantEnd: 4},
		{name: "start past the table", start: 5, end: 6, count: 4, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := slidePageRange(tt.start, tt.end, tt.count)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("slidePageRange(%d, %d, %d) = [%d, %d), want error", tt.start, tt.end, tt.count, start, end)
				}
				return
			}
			if err != nil || start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("slidePageRange(%d, %d, %d) = [%d, %d), %v; want [%d, %d)",
					tt.start, tt.end, tt.count, start, end, err, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestSlideV4RebaseAddresses(t *testing.T) {
	for _, tt := range []struct {
		name   string
		page   uint64
		extras bool
	}{
		{name: "first page"},
		{name: "later page", page: 1},
		{name: "multiple chains", page: 1, extras: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mapping := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{
				Address: 0x10000000, Size: 0x2000, FileOffset: 0x1000, SlideInfoOffset: 0x100,
			}}
			hdr := CacheSlideInfo4{
				Version: 4, PageSize: 0x1000, PageStartsOffset: 40, PageStartsCount: 2,
				PageExtrasOffset: 44, DeltaMask: 0xc0000000, ValueAdd: mapping.Address,
			}
			starts := []uint16{DYLD_CACHE_SLIDE4_PAGE_NO_REBASE, DYLD_CACHE_SLIDE4_PAGE_NO_REBASE}
			starts[tt.page] = 0x18 / 4
			var extras []uint16
			if tt.extras {
				starts[tt.page] = DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA
				extras = []uint16{0x18 / 4, DYLD_CACHE_SLIDE4_PAGE_EXTRA_END | 0x38/4}
				hdr.PageExtrasCount = uint32(len(extras))
			}
			var info bytes.Buffer
			for _, value := range []any{hdr, starts, extras} {
				if err := binary.Write(&info, binary.LittleEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			mapping.SlideInfoSize = uint64(info.Len())
			data := make([]byte, 0x3000)
			copy(data[mapping.SlideInfoOffset:], info.Bytes())
			// Nonzero chain offsets distinguish pointer locations within the VM page
			pointers := []struct {
				offset uint64
				raw    uint32
				target uint64
			}{
				{offset: 0x18, raw: 0x80018000, target: 0x10018000},
				{offset: 0x20, raw: 0x00018010, target: 0x10018010},
				{offset: 0x38, raw: 0x00018020, target: 0x10018020},
			}
			if !tt.extras {
				pointers = pointers[:2]
			}
			pageOffset := tt.page * uint64(hdr.PageSize)
			for _, p := range pointers {
				binary.LittleEndian.PutUint32(data[mapping.FileOffset+pageOffset+p.offset:], p.raw)
			}
			uuid := types.UUID{1}
			f := &File{
				UUID: uuid, ByteOrder: binary.LittleEndian, AddressToSymbol: NewA2STable(0),
				r: map[types.UUID]io.ReaderAt{uuid: bytes.NewReader(data)},
			}
			rebases, err := f.GetRebaseInfoForPages(uuid, mapping, tt.page, tt.page+1)
			if err != nil {
				t.Fatal(err)
			}
			if len(rebases) != len(pointers) {
				t.Fatalf("got %d rebases, want %d", len(rebases), len(pointers))
			}
			for i, p := range pointers {
				got := rebases[i]
				wantAddr := mapping.Address + pageOffset + p.offset
				wantOffset := mapping.FileOffset + pageOffset + p.offset
				if got.CacheVMAddress != wantAddr || got.CacheFileOffset != wantOffset || got.Target != p.target {
					t.Errorf("rebase %d = VM %#x, file offset %#x, target %#x; want VM %#x, file offset %#x, target %#x",
						i, got.CacheVMAddress, got.CacheFileOffset, got.Target, wantAddr, wantOffset, p.target)
				}
			}
		})
	}
}

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
			rebases, err := f.GetRebaseInfoForPages(uuid, mapping, 0, 1)
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
