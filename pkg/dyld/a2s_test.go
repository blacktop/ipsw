package dyld

import (
	"encoding/binary"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// saveAndLoad writes table to a file and loads it back in mmap mode.
func saveAndLoad(t *testing.T, table *A2STable) (*A2STable, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "table.a2s")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Save(out); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	loaded := NewA2STable(0)
	if err := loaded.Load(in, int64(len(raw))); err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { loaded.Close() })
	return loaded, raw
}

func TestA2STableSaveRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names map[uint64]string
	}{
		{"empty", map[uint64]string{}},
		{"mixed lengths and multibyte", map[uint64]string{
			0x1000: "_a",
			0x0800: "",
			0x2000: "日本語シンボル",
			0x3000: "ü",
			0x4000: strings.Repeat("_long", 64),
			0x5000: "-[NSObject description]",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := NewA2STable(0)
			wantSize := 0
			for addr, name := range tc.names {
				table.Set(addr, name)
				wantSize += len(name) + 1
			}
			loaded, raw := saveAndLoad(t, table)
			if got := int(binary.LittleEndian.Uint32(raw[8:12])); got != wantSize {
				t.Errorf("string table size = %d, want %d", got, wantSize)
			}
			got := map[uint64]string{}
			loaded.Range(func(addr uint64, name string) bool {
				got[addr] = name
				return true
			})
			if !maps.Equal(got, tc.names) {
				t.Errorf("round trip = %v, want %v", got, tc.names)
			}
		})
	}
}

func TestA2SStringTableSizeLimit(t *testing.T) {
	names := map[uint64]string{1: "ab", 2: "c"} // 3 + 2 bytes with terminators
	if size, err := a2sStringTableSize(names, 5); err != nil || size != 5 {
		t.Errorf("at the limit: size %d, err %v; want 5, nil", size, err)
	}
	if _, err := a2sStringTableSize(names, 4); err == nil {
		t.Error("a table one byte over the limit was accepted")
	}
	if size, err := a2sStringTableSize(map[uint64]string{}, 0); err != nil || size != 0 {
		t.Errorf("empty table: size %d, err %v; want 0, nil", size, err)
	}
}
