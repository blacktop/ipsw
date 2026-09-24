package dyld

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestSlidePagesForRangeHelper(t *testing.T) {
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
			start, end := slidePagesForRange(tt.offset, tt.size, 0x1000)
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("slidePagesForRange(%#x, %#x) = [%d, %d), want [%d, %d)",
					tt.offset, tt.size, start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestClampSlidePages(t *testing.T) {
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
			start, end, err := clampSlidePages(tt.start, tt.end, tt.count)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("clampSlidePages(%d, %d, %d) = [%d, %d), want error", tt.start, tt.end, tt.count, start, end)
				}
				return
			}
			if err != nil || start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("clampSlidePages(%d, %d, %d) = [%d, %d), %v; want [%d, %d)",
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
			f := fileReading(data)
			rebases, err := f.GetRebaseInfoForPages(f.UUID, mapping, tt.page, tt.page+1)
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
			f := fileReading(data)
			rebases, err := f.GetRebaseInfoForPages(f.UUID, mapping, 0, 1)
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

// strtabPool is a synthetic LC_SYMTAB string table: NUL at offset 0,
// NUL-terminated names, and a final name that runs to the end of the table
// with no terminator.
const strtabPool = "\x00_main\x00_foo\x00tail"

const strtabOff = 16

// strtabFile lays strtabPool at strtabOff inside a larger cache file, with
// bytes after the table so that a name running to the table's end must stop
// there rather than at the next NUL in the file.
func strtabFile() []byte {
	file := make([]byte, strtabOff)
	file = append(file, strtabPool...)
	return append(file, "ZZZZ\x00"...)
}

// countingReaderAt is a cache file that is not mmap'd. It counts the reads
// that touch [watchOff, watchEnd).
type countingReaderAt struct {
	data               []byte
	watchOff, watchEnd int64
	reads              int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < c.watchEnd && off+int64(len(p)) > c.watchOff {
		c.reads++
	}
	return bytes.NewReader(c.data).ReadAt(p, off)
}

func strtabReader() *countingReaderAt {
	return &countingReaderAt{data: strtabFile(), watchOff: strtabOff, watchEnd: strtabOff + int64(len(strtabPool))}
}

// strtabTestFile builds a File whose single cache file is r.
func strtabTestFile(r io.ReaderAt) (*File, mtypes.UUID) {
	uuid := mtypes.UUID{7}
	return &File{r: map[mtypes.UUID]io.ReaderAt{uuid: r}}, uuid
}

func checkStrtabNames(t *testing.T, nameAt func(uint64) string) {
	t.Helper()
	for _, tc := range []struct {
		off  uint64
		want string
	}{
		{0, ""},
		{1, "_main"},
		{3, "ain"},
		{7, "_foo"},
		{12, "tail"}, // stops at the table's end, not at the file's next NUL
		{uint64(len(strtabPool)), ""},
		{1 << 40, ""},
	} {
		if got := nameAt(tc.off); got != tc.want {
			t.Errorf("name at %#x = %q, want %q", tc.off, got, tc.want)
		}
	}
}

func TestStringTableLookupCopyPath(t *testing.T) {
	r := strtabReader()
	f, uuid := strtabTestFile(r)

	nameAt, err := f.stringTableLookup(uuid, strtabOff, uint64(len(strtabPool)))
	if err != nil {
		t.Fatal(err)
	}
	checkStrtabNames(t, nameAt)
	if r.reads == 0 {
		t.Fatal("first lookup did not read the pool")
	}

	// A second dylib pointing at the same pool, and one whose table is a
	// sub-range of it, are both served from the cached copy.
	reads := r.reads
	if _, err := f.stringTableLookup(uuid, strtabOff, uint64(len(strtabPool))); err != nil {
		t.Fatal(err)
	}
	sub, err := f.stringTableLookup(uuid, strtabOff+7, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := sub(0); got != "_fo" {
		t.Errorf("sub-range name at 0 = %q, want %q (bounded by the sub-range)", got, "_fo")
	}
	if r.reads != reads {
		t.Fatalf("cached lookups read the pool %d more times, want 0", r.reads-reads)
	}

	// A table that starts before the cached range is read as the union, and
	// still leaves exactly one buffer pinned for this cache file.
	wider, err := f.stringTableLookup(uuid, strtabOff-8, uint64(len(strtabPool))+8)
	if err != nil {
		t.Fatal(err)
	}
	if got := wider(8 + 1); got != "_main" {
		t.Errorf("wider-range name at 9 = %q, want %q", got, "_main")
	}
	if r.reads == reads {
		t.Fatal("widening did not read the pool")
	}
	if len(f.strtabs) != 1 {
		t.Fatalf("%d buffers pinned, want 1", len(f.strtabs))
	}
	if c := f.strtabs[uuid]; c.off != strtabOff-8 || len(c.buf) != len(strtabPool)+8 {
		t.Fatalf("pinned range is %#x+%d, want %#x+%d", c.off, len(c.buf), strtabOff-8, len(strtabPool)+8)
	}
	reads = r.reads
	if _, err := f.stringTableLookup(uuid, strtabOff, uint64(len(strtabPool))); err != nil {
		t.Fatal(err)
	}
	if r.reads != reads {
		t.Fatalf("lookup inside the widened range read the pool %d more times, want 0", r.reads-reads)
	}
}

func TestSharedStringTableBounds(t *testing.T) {
	f, uuid := strtabTestFile(strtabReader())

	if _, err := f.sharedStringTable(uuid, strtabOff, uint64(len(strtabFile()))); err == nil {
		t.Error("table past the end of the cache file was accepted")
	} else if !strings.Contains(err.Error(), "extends past the end") {
		t.Errorf("unexpected error for oversized table: %v", err)
	}
	if len(f.strtabs) != 0 {
		t.Errorf("rejected table pinned %d buffers", len(f.strtabs))
	}

	empty, err := f.stringTableLookup(uuid, strtabOff, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := empty(0); got != "" {
		t.Errorf("empty table yielded %q", got)
	}

	if _, err := f.sharedStringTable(mtypes.UUID{9}, strtabOff, 1); err == nil {
		t.Error("unknown cache UUID was accepted")
	}
}

// TestSharedStringTableRejectsOversizedWithoutAllocating advertises a table far
// larger than the cache file; rejecting it must not allocate the advertised
// size first. TotalAlloc is process-wide, so the threshold is a tolerance.
func TestSharedStringTableRejectsOversizedWithoutAllocating(t *testing.T) {
	const advertised = 16 << 20
	f, uuid := strtabTestFile(strtabReader())
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := f.sharedStringTable(uuid, strtabOff, advertised)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("oversized table accepted")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > advertised/16 {
		t.Fatalf("rejecting a %d-byte table allocated %d bytes", advertised, got)
	}
}

// failingReaderAt serves its first ok reads from data and fails every later
// read with err.
type failingReaderAt struct {
	data []byte
	ok   int
	err  error
}

func (r *failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.ok == 0 {
		return 0, r.err
	}
	r.ok--
	return bytes.NewReader(r.data).ReadAt(p, off)
}

func TestSharedStringTableReportsReadErrors(t *testing.T) {
	errDisk := errors.New("synthetic I/O error")
	for _, tc := range []struct {
		name string
		ok   int
	}{
		{"bounds probe fails", 0},
		{"table read fails", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, uuid := strtabTestFile(&failingReaderAt{data: strtabFile(), ok: tc.ok, err: errDisk})
			if _, err := f.sharedStringTable(uuid, strtabOff, uint64(len(strtabPool))); !errors.Is(err, errDisk) {
				t.Fatalf("error = %v, want it to wrap the reader's error", err)
			}
			if len(f.strtabs) != 0 {
				t.Fatalf("failed read pinned %d buffers", len(f.strtabs))
			}
		})
	}
}

func TestCloseDropsStringTableCopies(t *testing.T) {
	data := syntheticPrimaryBytes(t, layoutSelfContained)
	poolOff := int64(len(data))
	data = append(data, strtabPool...)
	f, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	nameAt, err := f.stringTableLookup(f.UUID, poolOff, uint64(len(strtabPool)))
	if err != nil {
		t.Fatal(err)
	}
	if got := nameAt(1); got != "_main" {
		t.Fatalf("name at 1 = %q, want %q", got, "_main")
	}
	if c := f.strtabs[f.UUID]; len(c.buf) == 0 {
		t.Fatal("lookup did not keep a copy of the string table")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if len(f.strtabs) != 0 {
		t.Fatalf("Close kept %d string table copies", len(f.strtabs))
	}
}

// TestHasImagePathFallsBackToImageNames covers headers that predate the dylibs
// trie fields: HasImagePath matches image names and never reads a trie.
func TestHasImagePathFallsBackToImageNames(t *testing.T) {
	f, r := trieTestFile(t, testDylibPaths)
	h := f.Headers[f.UUID]
	h.MappingOffset = dylibsTrieFieldEnd() - 1
	f.Headers[f.UUID] = h
	f.Images = cacheImages{
		{Name: "/usr/lib/libA.dylib", Index: 0},
		{Name: "/usr/lib/libB.dylib", Index: 1},
	}

	if idx, err := f.HasImagePath("/usr/lib/libB.dylib"); err != nil || idx != 1 {
		t.Fatalf("HasImagePath(libB) = %d, %v; want 1", idx, err)
	}
	if _, err := f.HasImagePath("/usr/lib/libAlias.dylib"); err == nil {
		t.Error("an alias resolved without a dylibs trie")
	}
	if r.reads != 0 {
		t.Fatalf("legacy header read the trie %d times, want 0", r.reads)
	}
}

func TestCloseDropsDylibsTrie(t *testing.T) {
	f, _ := trieTestFile(t, testDylibPaths)
	if _, err := f.GetDylibIndex("/usr/lib/libA.dylib"); err != nil {
		t.Fatal(err)
	}
	if len(f.dylibsTrieData) == 0 {
		t.Fatal("lookup did not keep the dylibs trie")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if f.dylibsTrieData != nil {
		t.Fatal("Close kept the dylibs trie")
	}
}
