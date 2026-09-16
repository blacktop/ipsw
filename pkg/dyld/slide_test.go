package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func TestSlidePageRanges(t *testing.T) {
	for _, version := range []uint32{2, 3, 4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			for _, tt := range []struct {
				name      string
				pageCount uint32
				pages     PageRange
				want      int
				wantErr   string
			}{
				{name: "all pages", pageCount: 2, pages: AllPages, want: 2},
				{name: "all-pages sentinel", pageCount: 2, pages: PageRange{End: math.MaxUint64}, want: 2},
				{name: "first page", pageCount: 2, pages: PageRange{End: 1}, want: 1},
				{name: "last page", pageCount: 2, pages: PageRange{Start: 1, End: 2}, want: 1},
				{name: "explicit whole table", pageCount: 2, pages: PageRange{End: 2}, want: 2},
				{name: "end past table", pageCount: 2, pages: PageRange{Start: 1, End: 3}, wantErr: "exceeds number of pages: 2"},
				{name: "single page", pageCount: 1, pages: AllPages, want: 1},
				{name: "empty table", pages: AllPages},
				{name: "range in empty table", pages: PageRange{End: 1}, wantErr: "exceeds number of pages: 0"},
				{name: "empty range", pageCount: 2, pages: PageRange{Start: 2, End: 2}, wantErr: "invalid slide page range"},
				{name: "start past table", pageCount: 2, pages: PageRange{Start: 3, End: 4}, wantErr: "exceeds number of pages: 2"},
				{name: "reversed range", pageCount: 2, pages: PageRange{Start: 2, End: 1}, wantErr: "invalid slide page range"},
				{name: "zero range", pageCount: 2, pages: PageRange{}, wantErr: "invalid slide page range [0, 0)"},
				{name: "maximum end", pageCount: 2, pages: PageRange{Start: 1, End: math.MaxUint64}, wantErr: "exceeds number of pages: 2"},
				{name: "maximum bounds", pageCount: 2, pages: PageRange{Start: math.MaxUint64, End: math.MaxUint64}, wantErr: "invalid slide page range"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					f, mapping, target := slidePagesFixture(t, version, tt.pageCount)
					rebases, err := f.GetRebaseInfoForPages(f.UUID, mapping, tt.pages)
					if tt.wantErr != "" {
						if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
							t.Fatalf("GetRebaseInfoForPages() = %v, want error containing %q", err, tt.wantErr)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(rebases) != tt.want {
						t.Fatalf("got %d rebases, want %d", len(rebases), tt.want)
					}
					for i, rebase := range rebases {
						wantOffset := mapping.FileOffset + (tt.pages.Start+uint64(i))*0x1000
						if rebase.CacheFileOffset != wantOffset || rebase.Target != target {
							t.Fatalf("rebase file offset = %#x -> %#x, want %#x -> %#x", rebase.CacheFileOffset, rebase.Target, wantOffset, target)
						}
					}
				})
			}
		})
	}
}

func TestSlideInfoRejectsZeroPageSize(t *testing.T) {
	for _, version := range []uint32{2, 3, 4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			f, mapping, _ := slidePagesFixture(t, version, 0)
			if err := f.GetSlideInfo(f.UUID, mapping); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 0x1000)
			if _, err := f.r[f.UUID].ReadAt(data, 0); err != nil {
				t.Fatal(err)
			}
			binary.LittleEndian.PutUint32(data[0x104:], 0)
			f.r[f.UUID] = bytes.NewReader(data)
			err := f.GetSlideInfo(f.UUID, mapping)
			if err == nil || !strings.Contains(err.Error(), "invalid slide info page size: 0") {
				t.Fatalf("GetSlideInfo() = %v, want invalid page size error", err)
			}
			if got := f.SlideInfo.GetPageSize(); got != 0x1000 {
				t.Fatalf("invalid header replaced the previous slide info: page size = %#x", got)
			}
		})
	}
}

func TestSlideInfoV1(t *testing.T) {
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, CacheSlideInfo{Version: 1}); err != nil {
		t.Fatal(err)
	}
	uuid := types.UUID{1}
	f := &File{UUID: uuid, ByteOrder: binary.LittleEndian, r: map[types.UUID]io.ReaderAt{uuid: bytes.NewReader(data.Bytes())}}
	mapping := &CacheMappingWithSlideInfo{}
	if err := f.GetSlideInfo(uuid, mapping); err != nil {
		t.Fatal(err)
	}
	t.Run("page size", func(t *testing.T) {
		if got := f.SlideInfo.GetPageSize(); got != 4096 {
			t.Fatalf("page size = %d, want 4096", got)
		}
	})
	t.Run("invalid page range", func(t *testing.T) {
		_, err := f.GetRebaseInfoForPages(uuid, mapping, PageRange{})
		const wantErr = "invalid slide page range [0, 0)"
		if err == nil || err.Error() != wantErr {
			t.Fatalf("GetRebaseInfoForPages() = %v, want error %q", err, wantErr)
		}
	})
}

func slidePagesFixture(t *testing.T, version, pages uint32) (*File, *CacheMappingWithSlideInfo, uint64) {
	t.Helper()
	const base = uint64(0x180000000)
	var header any
	var raw, target uint64
	switch version {
	case 2:
		header = CacheSlideInfo2{Version: 2, PageSize: 0x1000, PageStartsOffset: 40, PageStartsCount: pages, DeltaMask: 0xc000000000000000, ValueAdd: base}
		raw, target = 0x1234, base+0x1234
	case 3:
		header = CacheSlideInfo3{Version: 3, PageSize: 0x1000, PageStartsCount: pages, AuthValueAdd: base}
		raw, target = 1<<63|0x1234, base+0x1234
	case 4:
		header = CacheSlideInfo4{Version: 4, PageSize: 0x1000, PageStartsOffset: 40, PageStartsCount: pages, DeltaMask: 0xc0000000, ValueAdd: 0x10000000}
		raw, target = 0x12348000, 0x22348000
	case 5:
		header = CacheSlideInfo5{Version: 5, PageSize: 0x1000, PageStartsCount: pages, ValueAdd: base}
		raw, target = 1<<63|0x1234, base+0x1234
	}
	var info bytes.Buffer
	if err := binary.Write(&info, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&info, binary.LittleEndian, make([]uint16, pages)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 0x1000+int(pages)*0x1000)
	copy(data[0x100:], info.Bytes())
	for i := uint32(0); i < pages; i++ {
		binary.LittleEndian.PutUint64(data[0x1000+int(i)*0x1000:], raw)
	}
	uuid := types.UUID{1}
	f := &File{UUID: uuid, ByteOrder: binary.LittleEndian, AddressToSymbol: NewA2STable(0), r: map[types.UUID]io.ReaderAt{uuid: bytes.NewReader(data)}}
	mapping := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{
		Address: base, Size: uint64(pages) * 0x1000, FileOffset: 0x1000, SlideInfoOffset: 0x100, SlideInfoSize: uint64(info.Len()),
	}}
	return f, mapping, target
}

func TestSlidePagesSkipEmptyPages(t *testing.T) {
	for _, version := range []uint32{2, 3, 4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			f, mapping, target := slidePagesFixture(t, version, 3)
			data := make([]byte, 0x4000)
			if _, err := f.r[f.UUID].ReadAt(data, 0); err != nil {
				t.Fatal(err)
			}
			startsOffset, start := 24, uint16(0x18)
			if version == 2 || version == 4 {
				startsOffset, start = 40, 0x18/4
			}
			noRebase := uint16(0xffff)
			if version == 2 {
				noRebase = 0x4000
			}
			// Only the final page has a chain, starting partway into the page
			for i, value := range []uint16{noRebase, noRebase, start} {
				binary.LittleEndian.PutUint16(data[0x100+startsOffset+i*2:], value)
			}
			copy(data[0x3018:0x3020], data[0x3000:0x3008])
			f.r[f.UUID] = bytes.NewReader(data)
			rebases, err := f.GetRebaseInfoForPages(f.UUID, mapping, AllPages)
			if err != nil {
				t.Fatal(err)
			}
			if len(rebases) != 1 {
				t.Fatalf("got %d rebases, want 1", len(rebases))
			}
			got := rebases[0]
			if got.CacheFileOffset != 0x3018 || got.Target != target {
				t.Fatalf("rebase = %+v, want file offset 0x3018, target %#x", got, target)
			}
		})
	}
}

func TestImageSlidePageRanges(t *testing.T) {
	for _, version := range []uint32{2, 3, 4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			for _, tt := range []struct {
				name           string
				offset, filesz uint64
				memsz          uint64
				mappingSize    uint64
				wantPages      []int
				wantErr        string
			}{
				{name: "aligned first page", filesz: 0x1000, wantPages: []int{0}},
				{name: "aligned mapping end", offset: 0x1000, filesz: 0x1000, wantPages: []int{1}},
				{name: "partial last page", offset: 0x1000, filesz: 8, wantPages: []int{1}},
				{name: "partial boundaries", offset: 0x800, filesz: 0x1000, wantPages: []int{0, 1}},
				{name: "zero-fill tail", offset: 0x1000, filesz: 8, memsz: 0x4000, wantPages: []int{1}},
				{name: "empty unmapped segment", offset: 0x4000, memsz: 0x1000},
				{name: "extent exceeds mapping", offset: 0x1000, filesz: 0x1001, wantErr: "exceeds remaining mapping size"},
				{name: "extent would wrap", offset: 0x1000, filesz: math.MaxUint64, wantErr: "exceeds remaining mapping size"},
				{name: "short page table", offset: 0x2000, filesz: 0x1000, mappingSize: 0x3000, wantErr: "exceeds number of pages: 2"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					f, mapping, target := slidePagesFixture(t, version, 2)
					data := make([]byte, 0x3000)
					if _, err := f.r[f.UUID].ReadAt(data, 0); err != nil {
						t.Fatal(err)
					}
					// Distinct pointers reveal an unintended read of a neighboring page
					raw := binary.LittleEndian.Uint64(data[0x1000:])
					binary.LittleEndian.PutUint64(data[0x2000:], raw+0x100)
					if tt.mappingSize != 0 {
						mapping.Size = tt.mappingSize
					}
					f.r[f.UUID] = bytes.NewReader(data)
					f.MappingsWithSlideInfo = map[types.UUID]cacheMappingsWithSlideInfo{f.UUID: {mapping}}
					if err := f.GetSlideInfo(f.UUID, mapping); err != nil {
						t.Fatal(err)
					}
					memsz := tt.memsz
					if memsz == 0 {
						memsz = tt.filesz
					}
					img := &CacheImage{
						Name: "/usr/lib/libTest.dylib", cache: f,
						pm: &macho.File{FileTOC: macho.FileTOC{Loads: []macho.Load{
							&macho.Segment{SegmentHeader: macho.SegmentHeader{
								Name: "__DATA", Addr: mapping.Address + tt.offset,
								Filesz: tt.filesz, Memsz: memsz,
							}},
						}}},
					}
					err := img.ParseSlideInfo()
					if tt.wantErr != "" {
						if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
							t.Fatalf("ParseSlideInfo() = %v, want error containing %q", err, tt.wantErr)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(img.sinfo) != len(tt.wantPages) {
						t.Fatalf("got %d slide entries, want %d", len(img.sinfo), len(tt.wantPages))
					}
					for _, page := range tt.wantPages {
						want := target + uint64(page)*0x100
						if got := img.sinfo[raw+uint64(page)*0x100]; got != want {
							t.Errorf("page %d target = %#x, want %#x", page, got, want)
						}
					}
				})
			}
		})
	}
}
