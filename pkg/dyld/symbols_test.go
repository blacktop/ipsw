package dyld

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Keep the pre-reuse naming loop as an independent reference for the real-cache
// replay as well as the synthetic invalidation tests.
func uncachedStubNames(f *File) map[uint64]string {
	names := make(map[uint64]string)
	for stub, target := range f.islandStubs {
		if name, ok := f.AddressToSymbol.Get(target); ok {
			names[stub] = name
		}
	}
	return names
}

func TestStubNamesInvalidation(t *testing.T) {
	table := NewA2STable(0)
	table.Set(1, "first")
	f := &File{AddressToSymbol: table, islandStubs: map[uint64]uint64{10: 1, 20: 2}}
	check := func() map[uint64]string {
		t.Helper()
		got, err := f.GetStubIslands()
		if err != nil {
			t.Fatal(err)
		}
		if want := uncachedStubNames(f); !maps.Equal(got, want) {
			t.Fatalf("names = %v, want %v", got, want)
		}
		return got
	}
	got := check()
	cached := table.stubNames
	got[10] = "caller replacement"
	got[99] = "caller addition"
	delete(got, 10)
	check()
	if table.stubNames != cached {
		t.Fatal("unchanged table rebuilt cache")
	}
	table.Set(1, "first")
	check()
	if table.stubNames != cached {
		t.Fatal("same-name Set invalidated cache")
	}
	table.Set(1, "replacement")
	if table.Len() != 1 {
		t.Fatal("replacement changed Len")
	}
	check()
	if table.stubNames == cached {
		t.Fatal("different-name Set reused stale cache")
	}
	table.Set(2, "added")
	check()
	f.islandStubs[30] = 2
	if got := check(); got[30] != "added" {
		t.Fatal("island count change reused stale cache")
	}
	// A table can be attached to another File with the same island count.
	other := &File{AddressToSymbol: table, islandStubs: map[uint64]uint64{40: 1, 50: 2, 60: 2}}
	if names, err := other.GetStubIslands(); err != nil || !maps.Equal(names, uncachedStubNames(other)) {
		t.Fatalf("shared table leaked another File's names: %v, %v", names, err)
	}
	check()

	// Loading a different table with identical cardinality must invalidate.
	replacement := NewA2STable(0)
	replacement.Set(1, "loaded")
	replacement.Set(2, "loaded too")
	path := filepath.Join(t.TempDir(), "cache.a2s")
	in, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := replacement.Save(in); err != nil {
		t.Fatal(err)
	}
	info, err := in.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Load(in, info.Size()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { table.Close() })
	if got := check(); got[10] != "loaded" {
		t.Fatal("Load reused stale cache")
	}
	if err := table.Close(); err != nil {
		t.Fatal(err)
	}
	if got := check(); len(got) != 0 {
		t.Fatal("Close reused stale cache")
	}
}

func TestStubNamesConcurrentReaders(t *testing.T) {
	table := NewA2STable(0)
	table.Set(1, "name")
	f := &File{AddressToSymbol: table, islandStubs: map[uint64]uint64{10: 1}}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			names, err := f.GetStubIslands()
			if err != nil || names[10] != "name" {
				t.Errorf("names = %v, err = %v", names, err)
			}
			names[10] = "private to caller"
		})
	}
	readers.Wait()
}

func TestParseTrieExportsRejectsCycles(t *testing.T) {
	_, err := parseTrieExports([]byte{
		0x00,      // no terminal
		0x01,      // one child
		'A', 0x00, // edge
		0x00, // child offset points back to root
	}, 0)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestParseTrieExportsUsesUlebTerminalSizeWidth(t *testing.T) {
	data := []byte{0x82, 0x01} // terminal size 130, encoded in two bytes
	terminal := make([]byte, 130)
	terminal[0] = 0x00 // regular export flags
	terminal[1] = 0x05 // exported address delta
	terminal[129] = 0x01
	data = append(data, terminal...)
	data = append(data, 0x00) // no children

	exports, err := parseTrieExports(data, 0x1000)
	if err != nil {
		t.Fatalf("parseTrieExports returned error: %v", err)
	}
	if len(exports) != 1 {
		t.Fatalf("expected 1 export, got %d", len(exports))
	}
	if exports[0].Address != 0x1005 {
		t.Fatalf("expected address 0x1005, got %#x", exports[0].Address)
	}
}

func TestParseTrieExportsRejectsOversizedTerminal(t *testing.T) {
	_, err := parseTrieExports([]byte{
		0x03,       // terminal size claims three bytes
		0x00, 0x01, // terminal data has no room for child count
	}, 0)
	if err == nil {
		t.Fatal("expected oversized terminal error")
	}
	if !strings.Contains(err.Error(), "exceeds trie size") {
		t.Fatalf("expected bounds error, got %v", err)
	}
}

func TestGetPublicSymbolDuringReentrantParse(t *testing.T) {
	img := &CacheImage{
		Name: "/usr/lib/libA.dylib",
		PublicSymbols: []*Symbol{
			{Name: "_foo", Address: 0x1000},
		},
	}
	if !img.Analysis.State.BeginExports() {
		t.Fatal("failed to mark image as parsing")
	}
	defer img.Analysis.State.FinishExports(false)

	sym, err := img.GetPublicSymbol("_foo")
	if err != nil {
		t.Fatalf("GetPublicSymbol returned error: %v", err)
	}
	if sym.Address != 0x1000 {
		t.Fatalf("expected address 0x1000, got %#x", sym.Address)
	}

	if _, err := img.GetPublicSymbol("_missing"); err == nil {
		t.Fatal("expected missing symbol error")
	}
}
