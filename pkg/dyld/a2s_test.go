package dyld

import (
	"encoding/binary"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
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

// TestA2STableSaveOrdersFullRangeAddresses covers addresses that a signed or
// subtracting comparison would misorder; lookups in the loaded table binary
// search the saved order. The two-entry tables force the sort to compare a
// pair more than 1<<63 apart.
func TestA2STableSaveOrdersFullRangeAddresses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names map[uint64]string
	}{
		{"across the range", map[uint64]string{
			0:                  "_zero",
			1:                  "_one",
			0x180000000:        "_cache",
			math.MaxInt64 - 1:  "_below_sign",
			math.MaxInt64:      "_max_signed",
			1 << 63:            "_sign_bit",
			1<<63 + 0x1000:     "_above_sign",
			math.MaxUint64 - 1: "_below_max",
			math.MaxUint64:     "_max",
		}},
		{"one and max", map[uint64]string{1: "_one", math.MaxUint64: "_max"}},
		{"low and above the sign bit", map[uint64]string{0x10: "_low", 1<<63 + 0x20: "_high"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := NewA2STable(0)
			for addr, name := range tc.names {
				table.Set(addr, name)
			}
			loaded, _ := saveAndLoad(t, table)
			var addrs []uint64
			loaded.Range(func(addr uint64, _ string) bool {
				addrs = append(addrs, addr)
				return true
			})
			if len(addrs) != len(tc.names) || !slices.IsSorted(addrs) {
				t.Fatalf("saved addresses = %#x, want %d addresses in ascending order", addrs, len(tc.names))
			}
			for addr, want := range tc.names {
				if got, ok := loaded.Get(addr); !ok || got != want {
					t.Errorf("Get(%#x) = %q, %v; want %q", addr, got, ok, want)
				}
			}
		})
	}
}
