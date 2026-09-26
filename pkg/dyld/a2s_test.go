package dyld

import (
	"bytes"
	"encoding/binary"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestA2SChangeCounter(t *testing.T) {
	table := NewA2STable(0)
	table.Set(1, "first")
	version := table.changes
	table.Set(1, "first")
	if table.changes != version {
		t.Fatal("same-name Set advanced the counter")
	}
	table.Set(1, "replacement")
	if table.Len() != 1 || table.changes != version+1 {
		t.Fatal("replacement must advance the counter without changing Len")
	}
	version = table.changes
	table.Set(2, "")
	if table.changes != version+1 {
		t.Fatal("adding an empty name must advance the counter")
	}
	version = table.changes
	var out bytes.Buffer
	if err := table.Save(&out); err != nil {
		t.Fatal(err)
	}
	if table.changes != version {
		t.Fatal("Save mutated the counter")
	}
	path := filepath.Join(t.TempDir(), "cache.a2s")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := table.Load(in, int64(out.Len())); err != nil {
		t.Fatal(err)
	}
	if table.changes != version+1 {
		t.Fatal("Load did not advance the counter")
	}
	version = table.changes
	if err := table.Close(); err != nil {
		t.Fatal(err)
	}
	if table.changes != version+1 {
		t.Fatal("Close did not advance the counter")
	}
}

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

func TestA2SLoadedUnion(t *testing.T) {
	original := NewA2STable(0)
	original.Set(20, "untouched")
	original.Set(40, "old")
	original.Set(60, "tail")
	table, _ := saveAndLoad(t, original)
	version := table.changes
	table.Set(20, "untouched")
	if table.changes != version {
		t.Error("unchanged mmap value advanced revision")
	}
	table.Set(10, "new")
	table.Set(40, "replacement")
	if table.changes != version+2 {
		t.Error("union mutations must advance revision exactly twice")
	}
	want := map[uint64]string{10: "new", 20: "untouched", 40: "replacement", 60: "tail"}
	for addr, name := range want {
		if got, ok := table.Get(addr); !ok || got != name {
			t.Errorf("Get(%d) = %q, %v; want %q", addr, got, ok, name)
		}
		if !table.Has(addr) || table.GetValue(addr) != name {
			t.Errorf("Has/GetValue(%d) missing %q", addr, name)
		}
	}
	if table.Has(30) || table.GetValue(30) != "" {
		t.Error("missing address found")
	}
	if table.Len() != len(want) {
		t.Errorf("Len = %d, want %d", table.Len(), len(want))
	}
	var addresses []uint64
	got := map[uint64]string{}
	table.Range(func(addr uint64, name string) bool {
		addresses = append(addresses, addr)
		got[addr] = name
		return true
	})
	if !slices.Equal(addresses, []uint64{10, 20, 40, 60}) || !maps.Equal(got, want) {
		t.Errorf("Range = %v, %v", addresses, got)
	}
	calls := 0
	table.Range(func(uint64, string) bool { calls++; return false })
	if calls != 1 {
		t.Errorf("early stop called %d times", calls)
	}
	loaded, raw := saveAndLoad(t, table)
	for addr, name := range want {
		if value, ok := loaded.Get(addr); !ok || value != name {
			t.Errorf("round-trip Get(%d) = %q, %v", addr, value, ok)
		}
	}
	_, again := saveAndLoad(t, loaded)
	if !bytes.Equal(raw, again) {
		t.Error("loaded union save is not byte-identical")
	}
	fresh := NewA2STable(0)
	for addr, name := range want {
		fresh.Set(addr, name)
	}
	for range 10 {
		var out bytes.Buffer
		if err := fresh.Save(&out); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, out.Bytes()) {
			t.Error("fresh and loaded union serialization differs")
		}
	}
	strBase := a2sHeaderSize + len(want)*a2sEntrySize
	if string(raw[strBase:]) != "new\x00untouched\x00replacement\x00tail\x00" {
		t.Errorf("names not in address order: %q", raw[strBase:])
	}
}

func TestA2SSaveSortedNames(t *testing.T) {
	table := NewA2STable(0)
	table.Set(1, "z")
	table.Set(2, "a")
	table.Set(3, "a")
	table.Set(4, "")
	var out bytes.Buffer
	if err := table.Save(&out); err != nil {
		t.Fatal(err)
	}
	raw := out.Bytes()
	if got := string(raw[a2sHeaderSize+4*a2sEntrySize:]); got != "z\x00a\x00a\x00\x00" {
		t.Errorf("string table = %q, want address order", got)
	}
	for i, want := range []uint32{0, 2, 4, 6} {
		if got := binary.LittleEndian.Uint32(raw[a2sHeaderSize+i*a2sEntrySize+8:]); got != want {
			t.Errorf("entry %d offset = %d, want %d", i, got, want)
		}
	}
	var again bytes.Buffer
	if err := table.Save(&again); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again.Bytes()) {
		t.Error("saving the same table twice is not byte-identical")
	}
}
