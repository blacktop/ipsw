package dyld

import (
	"cmp"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"testing"
)

const benchmarkA2SEntries = 4096

func BenchmarkA2STableBuildSet(b *testing.B) {
	names := benchmarkA2SNames()
	b.ReportAllocs()

	for b.Loop() {
		table := NewA2STable(benchmarkA2SEntries)
		for addr, name := range names {
			table.Set(uint64(addr), name)
		}
	}
}

func BenchmarkA2STableBuildGet(b *testing.B) {
	table := NewA2STable(benchmarkA2SEntries)
	for addr, name := range benchmarkA2SNames() {
		table.Set(uint64(addr), name)
	}
	b.ReportAllocs()

	for b.Loop() {
		for addr := range benchmarkA2SEntries {
			if _, ok := table.Get(uint64(addr)); !ok {
				b.Fatalf("missing address %#x", addr)
			}
		}
	}
}

func benchmarkA2SNames() []string {
	names := make([]string, benchmarkA2SEntries)
	for i := range names {
		names[i] = fmt.Sprintf("_symbol_%04d", i)
	}
	return names
}

func BenchmarkA2STableSave(b *testing.B) {
	table := NewA2STable(0)
	for i := range 100_000 {
		table.Set(uint64(i)*16, fmt.Sprintf("_symbol_%d_%s", i, strings.Repeat("x", i%64)))
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := table.Save(io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

// a2sSortEntry has the layout of the entries Save sorts.
type a2sSortEntry struct {
	addr   uint64
	strOff uint32
}

// BenchmarkA2SEntrySort compares Save's previous and current sort calls on
// the same shuffled input, restored before every iteration.
func BenchmarkA2SEntrySort(b *testing.B) {
	rng := rand.New(rand.NewPCG(1, 2))
	src := make([]a2sSortEntry, 1_000_000)
	for i := range src {
		src[i] = a2sSortEntry{addr: rng.Uint64(), strOff: uint32(i)}
	}
	work := make([]a2sSortEntry, len(src))
	for _, bc := range []struct {
		name string
		sort func([]a2sSortEntry)
	}{
		{"impl=sort.Slice", func(e []a2sSortEntry) {
			sort.Slice(e, func(i, j int) bool { return e[i].addr < e[j].addr })
		}},
		{"impl=slices.SortFunc", func(e []a2sSortEntry) {
			slices.SortFunc(e, func(x, y a2sSortEntry) int { return cmp.Compare(x.addr, y.addr) })
		}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				copy(work, src)
				b.StartTimer()
				bc.sort(work)
			}
		})
	}
}
