package dyld

import (
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestDylibsTrieInfoRejectsOldHeader(t *testing.T) {
	f := fileWithHeader(CacheHeader{
		MappingOffset:    dylibsTrieFieldEnd() - 1,
		DylibsTrieAddr:   0x180000000,
		DylibsTrieSize:   0x180028000,
		SharedRegionSize: 0x100000,
	}, 0x100000)

	_, _, err := f.dylibsTrieInfo()
	if err == nil {
		t.Fatal("expected old header error")
	}
	if !strings.Contains(err.Error(), "does not contain dylibs trie info") {
		t.Fatalf("expected missing trie error, got %v", err)
	}
}

func TestDylibsTrieInfoRejectsImpossibleSize(t *testing.T) {
	f := fileWithHeader(CacheHeader{
		MappingOffset:  dylibsTrieFieldEnd(),
		DylibsTrieAddr: 0x180000000,
		DylibsTrieSize: 0x1001,
	}, 0x1000)

	_, _, err := f.dylibsTrieInfo()
	if err == nil {
		t.Fatal("expected oversized trie error")
	}
	if !strings.Contains(err.Error(), "exceeds cache size") {
		t.Fatalf("expected size guard error, got %v", err)
	}
}

func TestDylibsTrieInfoAcceptsPresentFields(t *testing.T) {
	f := fileWithHeader(CacheHeader{
		MappingOffset:  dylibsTrieFieldEnd(),
		DylibsTrieAddr: 0x180000000,
		DylibsTrieSize: 0x20,
	}, 0x1000)

	addr, size, err := f.dylibsTrieInfo()
	if err != nil {
		t.Fatalf("dylibsTrieInfo returned error: %v", err)
	}
	if addr != 0x180000000 {
		t.Fatalf("expected trie addr 0x180000000, got %#x", addr)
	}
	if size != 0x20 {
		t.Fatalf("expected trie size 0x20, got %#x", size)
	}
}

func dylibsTrieFieldEnd() uint32 {
	return uint32(unsafe.Offsetof(CacheHeader{}.DylibsTrieSize) + unsafe.Sizeof(CacheHeader{}.DylibsTrieSize))
}

func fileWithHeader(header CacheHeader, size int64) *File {
	var uuid mtypes.UUID
	return &File{
		UUID: uuid,
		Headers: map[mtypes.UUID]CacheHeader{
			uuid: header,
		},
		size: size,
	}
}

// testDylibPaths maps each path in a synthetic dylibs trie to its image index.
// libAlias.dylib is a second path for image 0, as dyld records symlinked
// install names.
var testDylibPaths = map[string]uint64{
	"/usr/lib/libA.dylib":     0,
	"/usr/lib/libAlias.dylib": 0,
	"/usr/lib/libB.dylib":     1,
}

// dylibsTrieBytes encodes paths as a dylibs trie: a root node with one edge per
// path, each leading to a terminal node holding the image index.
func dylibsTrieBytes(t *testing.T, paths map[string]uint64) []byte {
	t.Helper()
	names := slices.Sorted(func(yield func(string) bool) {
		for name := range paths {
			if !yield(name) {
				return
			}
		}
	})
	rootSize := 2
	for _, name := range names {
		rootSize += len(name) + 2 // NUL + one-byte child offset
	}
	trie := []byte{0, byte(len(names))}
	for i, name := range names {
		child := rootSize + 3*i
		if child > 0x7f || paths[name] > 0x7f {
			t.Fatal("synthetic trie needs multi-byte ULEBs")
		}
		trie = append(trie, name...)
		trie = append(trie, 0, byte(child))
	}
	for _, name := range names {
		trie = append(trie, 1, byte(paths[name]), 0) // terminal size, index, no children
	}
	return trie
}

// trieTestFile builds a one-file cache whose dylibs trie encodes paths. Its
// reader counts the reads that touch the trie.
func trieTestFile(t *testing.T, paths map[string]uint64) (*File, *countingReaderAt) {
	t.Helper()
	const base, trieOff = 0x180000000, 0x100
	trie := dylibsTrieBytes(t, paths)
	data := make([]byte, trieOff+len(trie)+0x10)
	copy(data[trieOff:], trie)
	uuid := mtypes.UUID{1}
	r := &countingReaderAt{data: data, watchOff: trieOff, watchEnd: trieOff + int64(len(trie))}
	f := &File{
		UUID: uuid,
		Headers: map[mtypes.UUID]CacheHeader{uuid: {
			MappingOffset:  dylibsTrieFieldEnd(),
			DylibsTrieAddr: base + trieOff,
			DylibsTrieSize: uint64(len(trie)),
		}},
		Mappings: map[mtypes.UUID]cacheMappings{uuid: {
			{CacheMappingInfo: CacheMappingInfo{Address: base, Size: uint64(len(data))}},
		}},
		r:    map[mtypes.UUID]io.ReaderAt{uuid: r},
		size: int64(len(data)),
	}
	return f, r
}

func TestDylibsTrieIsReadOnceAcrossLookups(t *testing.T) {
	f, r := trieTestFile(t, testDylibPaths)

	if idx, err := f.GetDylibIndex("/usr/lib/libA.dylib"); err != nil || idx != 0 {
		t.Fatalf("GetDylibIndex(libA) = %d, %v; want 0", idx, err)
	}
	if r.reads != 1 {
		t.Fatalf("first lookup read the trie %d times, want 1", r.reads)
	}

	if idx, err := f.HasImagePath("/usr/lib/libAlias.dylib"); err != nil || idx != 0 {
		t.Errorf("HasImagePath(alias) = %d, %v; want 0", idx, err)
	}
	if idx, err := f.GetDylibIndex("/usr/lib/libAlias.dylib"); err != nil || idx != 0 {
		t.Errorf("GetDylibIndex(alias) = %d, %v; want 0", idx, err)
	}
	if idx, err := f.HasImagePath("/usr/lib/libB.dylib"); err != nil || idx != 1 {
		t.Errorf("HasImagePath(libB) = %d, %v; want 1", idx, err)
	}
	nodes, err := f.GetDylibsImageArrayIDs()
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, n := range nodes {
		paths = append(paths, string(n.Data))
	}
	if want := []string{"/usr/lib/libA.dylib", "/usr/lib/libAlias.dylib", "/usr/lib/libB.dylib"}; !slices.Equal(paths, want) {
		t.Errorf("GetDylibsImageArrayIDs paths = %q, want %q", paths, want)
	}
	if _, err := f.GetDylibIndex("/usr/lib/libMissing.dylib"); err == nil {
		t.Error("GetDylibIndex found a path the trie does not hold")
	}
	if _, err := f.HasImagePath("/usr/lib/libMissing.dylib"); err == nil {
		t.Error("HasImagePath found a path the trie does not hold")
	}

	if r.reads != 1 {
		t.Fatalf("lookups after the first read the trie %d more times, want 0", r.reads-1)
	}
}

func TestDylibsTrieRetriesAfterTruncatedRead(t *testing.T) {
	f, full := trieTestFile(t, testDylibPaths)
	uuid := f.UUID
	truncated := &countingReaderAt{data: full.data[:full.watchEnd-4]}
	f.r[uuid] = truncated

	if _, err := f.GetDylibIndex("/usr/lib/libA.dylib"); !errors.Is(err, io.EOF) {
		t.Fatalf("truncated trie read error = %v, want io.EOF", err)
	}
	if f.dylibsTrieData != nil {
		t.Fatal("a truncated read was cached")
	}

	f.r[uuid] = full
	if idx, err := f.GetDylibIndex("/usr/lib/libB.dylib"); err != nil || idx != 1 {
		t.Fatalf("GetDylibIndex after retry = %d, %v; want 1", idx, err)
	}
	if full.reads != 1 {
		t.Fatalf("retry read the trie %d times, want 1", full.reads)
	}
}

func TestDylibsTrieFirstUseIsSynchronized(t *testing.T) {
	f, r := trieTestFile(t, testDylibPaths)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if idx, err := f.GetDylibIndex("/usr/lib/libB.dylib"); err != nil || idx != 1 {
				t.Errorf("GetDylibIndex = %d, %v; want 1", idx, err)
			}
		})
	}
	wg.Wait()
	if r.reads != 1 {
		t.Fatalf("concurrent first lookups read the trie %d times, want 1", r.reads)
	}
}
