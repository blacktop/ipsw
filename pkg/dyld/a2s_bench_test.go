package dyld

import (
	"fmt"
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
