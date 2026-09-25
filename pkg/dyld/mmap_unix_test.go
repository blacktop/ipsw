//go:build unix

package dyld

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestStringTableLookupMmapPath(t *testing.T) {
	data := strtabFile()
	uuid := mtypes.UUID{7}
	// The mapping's own length is the bound.
	f := &File{r: map[mtypes.UUID]io.ReaderAt{uuid: &mmapReaderAt{data: data}}}

	nameAt, err := f.stringTableLookup(uuid, strtabOff, uint64(len(strtabPool)))
	if err != nil {
		t.Fatal(err)
	}
	checkStrtabNames(t, nameAt)
	if len(f.strtabs) != 0 {
		t.Fatalf("mmap path pinned %d buffers, want none", len(f.strtabs))
	}

	// The names come straight out of the mapping: a change to the mapped
	// bytes shows up in the next lookup, proving the table was not copied.
	copy(data[strtabOff+1:], "_MAIN")
	if got := nameAt(1); got != "_MAIN" {
		t.Errorf("name at 1 after patching the mapping = %q, want %q", got, "_MAIN")
	}

	if _, err := f.sharedStringTable(uuid, strtabOff, uint64(len(data))); err == nil {
		t.Error("table past the end of the mapping was accepted")
	} else if !strings.Contains(err.Error(), "extends past the end") {
		t.Errorf("unexpected error for oversized table: %v", err)
	}
	if _, err := f.sharedStringTable(uuid, -1, 1); err == nil {
		t.Error("negative table offset was accepted")
	}
}

func TestStringTableLookupMmapPathEOF(t *testing.T) {
	data := syntheticPrimaryBytes(t, layoutSelfContained)
	poolOff := int64(len(data))
	data = append(data, strtabPool...)
	path := filepath.Join(t.TempDir(), "cache")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	r, closer, size, err := openCacheFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, ok := r.(*mmapReaderAt); !ok {
		t.Fatalf("reader is %T, want *mmapReaderAt", r)
	}
	if size != poolOff+int64(len(strtabPool)) {
		t.Fatalf("mapped length = %d, want pool end %d", size, poolOff+int64(len(strtabPool)))
	}
	f, uuid := strtabTestFile(r)
	nameAt, err := f.stringTableLookup(uuid, poolOff, uint64(len(strtabPool)))
	if err != nil {
		t.Fatal(err)
	}
	checkStrtabNames(t, nameAt)
	if len(f.strtabs) != 0 {
		t.Fatalf("mmap path cached %d copied pools, want 0", len(f.strtabs))
	}
	if _, err := f.stringTableLookup(uuid, poolOff, uint64(len(strtabPool)+1)); err == nil || !strings.Contains(err.Error(), "extends past the end") {
		t.Fatalf("oversized pool error = %v, want extends past the end", err)
	}
}
