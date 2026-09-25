package dyld

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestStubReuseReplay measures the extract --stubs symbol sequence without
// extracting images. Run alone, without -race, to avoid distorting the costs:
//
//	env DSC=/path/to/dyld_shared_cache_arm64e A2S=/tmp/w11-stubmap/cache.a2s go test -run '^TestStubReuseReplay$' -count=1 -v ./pkg/dyld
//
// Run again after creating A2S: creation itself parses locals, whereas loading
// an existing A2S leaves each image's locals to be parsed in the extraction loop.
func TestStubReuseReplay(t *testing.T) {
	dsc := os.Getenv("DSC")
	if dsc == "" {
		t.Skip("set DSC and A2S to measure a real cache")
	}
	a2s := filepath.Clean(os.Getenv("A2S"))
	if !strings.HasPrefix(a2s, "/tmp/w11-stubmap/") && !strings.HasPrefix(a2s, "/private/tmp/w11-stubmap/") {
		t.Fatal("A2S must name a cache file under /tmp/w11-stubmap")
	}
	if err := os.MkdirAll(filepath.Dir(a2s), 0o755); err != nil {
		t.Fatal(err)
	}
	// Keep OpenOrCreateA2SCache's fallback paths in the same scratch directory.
	t.Setenv("TMPDIR", filepath.Dir(a2s))
	f, err := Open(dsc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := f.OpenOrCreateA2SCache(a2s); err != nil {
		t.Fatal(err)
	}
	if len(f.Images) < 64 {
		t.Fatalf("need 64 images, got %d", len(f.Images))
	}
	t.Logf("DSC=%s A2S=%s loaded=%t Go=%s", dsc, a2s, f.SymCacheLoaded, runtime.Version())
	var stubNS, stubAllocs, localNS, localAllocs []uint64
	changedCalls, changedPairs, reuseCount := 0, 0, 0
	for index, image := range f.Images[:64] {
		// ParseLocalSymbols records every successful Set in LocalSymbols. Comparing
		// all writes with the original map detects even A->B->A replacements;
		// comparing only final maps or Len would miss those. Set starts an empty
		// build map on the first write after mmap loading, so snapshot m itself.
		before := maps.Clone(f.AddressToSymbol.m)
		beforeChanges := f.AddressToSymbol.changes
		alreadyParsed := image.Analysis.State.IsPrivatesDone()
		var parseErr error
		ns, allocs := measureStubReplayCall(func() { parseErr = image.ParseLocalSymbols(false) })
		if parseErr != nil && !errors.Is(parseErr, ErrNoLocals) {
			t.Fatal(parseErr)
		}
		localNS = append(localNS, ns)
		localAllocs = append(localAllocs, allocs)
		var stubs map[uint64]string
		var stubErr error
		cached := f.AddressToSymbol.stubNames
		ns, allocs = measureStubReplayCall(func() { stubs, stubErr = f.GetStubIslands() })
		if stubErr != nil {
			t.Fatal(stubErr)
		}
		stubNS = append(stubNS, ns)
		stubAllocs = append(stubAllocs, allocs)
		if cached != nil && cached == f.AddressToSymbol.stubNames {
			reuseCount++
		}
		encoded := stubReplayBytes(stubs)
		if !bytes.Equal(encoded, stubReplayBytes(uncachedStubNames(f))) {
			t.Fatalf("image %d: cached names differ from uncached reference", index)
		}
		changed := false
		if !alreadyParsed {
			for _, symbol := range image.LocalSymbols {
				if old, ok := before[symbol.Value]; !ok || old != symbol.Name {
					changed = true
					break
				}
			}
		}
		if changed != (beforeChanges != f.AddressToSymbol.changes) {
			t.Fatalf("image %d: local-symbol writes and change counter disagree", index)
		}
		if changed {
			changedCalls++
			if index > 0 {
				changedPairs++
			}
		}
		t.Logf("image=%02d name=%s local_ns=%d local_allocs=%d stub_ns=%d stub_allocs=%d changed=%t stubs=%d sha256=%x",
			index, image.Name, localNS[index], localAllocs[index], ns, allocs, changed, len(stubs), sha256.Sum256(encoded))
	}
	stubMedian, stubTotal := stubReplayStats(stubNS)
	allocMedian, allocTotal := stubReplayStats(stubAllocs)
	localMedian, localTotal := stubReplayStats(localNS)
	localAllocMedian, localAllocTotal := stubReplayStats(localAllocs)
	noReuse := stubMedian < localMedian/100 || changedPairs*100 >= 90*63
	t.Logf("SUMMARY stub_median_ns=%.1f stub_total_ns=%d stub_median_allocs=%.1f stub_total_allocs=%d local_median_ns=%.1f local_total_ns=%d local_median_allocs=%.1f local_total_allocs=%d changed_calls=%d/64 changed_consecutive=%d/63 reuse_count=%d/64 no_reuse=%t",
		stubMedian, stubTotal, allocMedian, allocTotal, localMedian, localTotal, localAllocMedian, localAllocTotal, changedCalls, changedPairs, reuseCount, noReuse)
}

// ReadMemStats is outside the timer; deltas count process-wide mallocs. This
// gated test must run alone, with no parallel tests or background workload.
func measureStubReplayCall(fn func()) (ns, allocs uint64) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	fn()
	ns = uint64(time.Since(start).Nanoseconds())
	runtime.ReadMemStats(&after)
	return ns, after.Mallocs - before.Mallocs
}

func stubReplayStats(values []uint64) (median float64, total uint64) {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	for _, value := range sorted {
		total += value
	}
	return (float64(sorted[31]) + float64(sorted[32])) / 2, total
}

// Encode sorted addresses and length-prefixed names, independent of map order.
func stubReplayBytes(stubs map[uint64]string) []byte {
	var out []byte
	var buf [8]byte
	for _, addr := range slices.Sorted(maps.Keys(stubs)) {
		binary.LittleEndian.PutUint64(buf[:], addr)
		out = append(out, buf[:]...)
		binary.LittleEndian.PutUint64(buf[:], uint64(len(stubs[addr])))
		out = append(out, buf[:]...)
		out = append(out, stubs[addr]...)
	}
	return out
}
