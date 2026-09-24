package dyld

import (
	"bytes"
	"io"
	"strings"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

// strtabPool is a string table as LC_SYMTAB would describe it: NUL at offset
// 0, NUL-terminated names, and a final name that runs to the end of the table
// with no terminator.
const strtabPool = "\x00_main\x00_foo\x00tail"

// strtabFile lays strtabPool at strtabOff inside a larger cache file, with
// bytes after the table so that a name running to the table's end must stop
// there rather than at the next NUL in the file.
const strtabOff = 16

func strtabFile() []byte {
	file := make([]byte, strtabOff)
	file = append(file, strtabPool...)
	return append(file, "ZZZZ\x00"...)
}

// countingReaderAt is a cache file that is not mmap'd; it counts pool reads so
// the tests can check the pool is read once. The one-byte bounds probe that
// precedes each pool read is not counted.
type countingReaderAt struct {
	data  []byte
	reads int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > 1 {
		c.reads++
	}
	return bytes.NewReader(c.data).ReadAt(p, off)
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
	data := strtabFile()
	r := &countingReaderAt{data: data}
	f, uuid := strtabTestFile(r)

	nameAt, err := f.stringTableLookup(uuid, strtabOff, uint64(len(strtabPool)))
	if err != nil {
		t.Fatal(err)
	}
	checkStrtabNames(t, nameAt)
	if r.reads != 1 {
		t.Fatalf("first lookup issued %d reads, want 1", r.reads)
	}

	// A second dylib pointing at the same pool, and one whose table is a
	// sub-range of it, are both served from the cached copy.
	if _, err := f.stringTableLookup(uuid, strtabOff, uint64(len(strtabPool))); err != nil {
		t.Fatal(err)
	}
	sub, err := f.stringTableLookup(uuid, strtabOff+7, 5)
	if err != nil {
		t.Fatal(err)
	}
	if got := sub(0); got != "_foo" {
		t.Errorf("sub-range name at 0 = %q, want %q", got, "_foo")
	}
	if got := sub(4); got != "" {
		t.Errorf("sub-range name at 4 = %q, want %q (bounded by the sub-range)", got, "")
	}
	if r.reads != 1 {
		t.Fatalf("cached lookups issued %d reads in total, want 1", r.reads)
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
	if r.reads != 2 {
		t.Fatalf("widening issued %d reads in total, want 2", r.reads)
	}
	if len(f.strtabs) != 1 {
		t.Fatalf("%d buffers pinned, want 1", len(f.strtabs))
	}
	if c := f.strtabs[uuid]; c.off != strtabOff-8 || len(c.buf) != len(strtabPool)+8 {
		t.Fatalf("pinned range is %#x+%d, want %#x+%d", c.off, len(c.buf), strtabOff-8, len(strtabPool)+8)
	}
	if _, err := f.stringTableLookup(uuid, strtabOff, uint64(len(strtabPool))); err != nil {
		t.Fatal(err)
	}
	if r.reads != 2 {
		t.Fatalf("lookup inside the widened range issued a read (%d total), want none", r.reads)
	}
}

func TestSharedStringTableBounds(t *testing.T) {
	data := strtabFile()
	f, uuid := strtabTestFile(&countingReaderAt{data: data})

	if _, err := f.sharedStringTable(uuid, strtabOff, uint64(len(data))); err == nil {
		t.Error("table past the end of the cache file was accepted")
	} else if !strings.Contains(err.Error(), "extends past the end") {
		t.Errorf("unexpected error for oversized table: %v", err)
	}
	if _, err := f.sharedStringTable(uuid, strtabOff, 1<<32-1); err == nil {
		t.Error("4 GiB table in a tiny cache file was accepted")
	}
	if len(f.strtabs) != 0 {
		t.Errorf("rejected tables pinned %d buffers", len(f.strtabs))
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
