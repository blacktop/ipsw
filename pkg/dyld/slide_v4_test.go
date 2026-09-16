package dyld

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/blacktop/go-macho/types"
)

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
			rebases, err := f.GetRebaseInfoForPages(uuid, mapping, PageRange{Start: tt.page, End: tt.page + 1})
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
