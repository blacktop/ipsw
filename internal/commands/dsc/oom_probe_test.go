package dsc

import (
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// TestOOMProbe is a manual memory-profiling harness for the DSC dylib diff.
// It is gated on the OLD_DSC / NEW_DSC env vars so it never runs in normal CI.
//
// Set STRS=1 / STARTS=1 to mirror the ipsw-diffs CI command, which passes
// --strs and --starts (those inflate both the per-image DiffInfo transients
// and the rendered Updated text).
//
//	OLD_DSC=/path/dyld_shared_cache_arm64e \
//	NEW_DSC=/path/dyld_shared_cache_arm64e \
//	STRS=1 STARTS=1 \
//	HEAP_OUT=/tmp/dsc.heap.pprof \
//	go test ./internal/commands/dsc -run TestOOMProbe -v -timeout 120m
func TestOOMProbe(t *testing.T) {
	oldPath := os.Getenv("OLD_DSC")
	newPath := os.Getenv("NEW_DSC")
	if oldPath == "" || newPath == "" {
		t.Skip("set OLD_DSC and NEW_DSC to run the memory probe")
	}

	// Peak-RAM sampler.
	var peakHeapInuse, peakHeapAlloc, peakSys uint64
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Go(func() {
		var ms runtime.MemStats
		for !stop.Load() {
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peakHeapInuse {
				peakHeapInuse = ms.HeapInuse
			}
			if ms.HeapAlloc > peakHeapAlloc {
				peakHeapAlloc = ms.HeapAlloc
			}
			if ms.Sys > peakSys {
				peakSys = ms.Sys
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	gb := func(b uint64) float64 { return float64(b) / (1 << 30) }

	t.Logf("opening OLD %s", oldPath)
	f1, err := dyld.Open(oldPath)
	if err != nil {
		t.Fatalf("open old: %v", err)
	}
	defer f1.Close()
	t.Logf("opening NEW %s", newPath)
	f2, err := dyld.Open(newPath)
	if err != nil {
		t.Fatalf("open new: %v", err)
	}
	defer f2.Close()
	t.Logf("old images=%d new images=%d", len(f1.Images), len(f2.Images))

	// Mirror diff.dscDiffConfig() + the ipsw-diffs CI flags. STRS/STARTS toggle
	// CStrings/FuncStarts; the block-list matches the CI command.
	conf := &mcmd.DiffConfig{
		Markdown:           true,
		Color:              false,
		DiffTool:           "git",
		IgnoreLoadCommands: true,
		CStrings:           os.Getenv("STRS") != "",
		FuncStarts:         os.Getenv("STARTS") != "",
		BlockList:          []string{"__TEXT.__info_plist", "__AUTH_CONST.__auth_ptr"},
	}
	t.Logf("config: CStrings=%v FuncStarts=%v", conf.CStrings, conf.FuncStarts)

	start := time.Now()
	out, err := Diff(f1, f2, conf)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}

	var updatedKeys, updatedBytes int
	if out != nil {
		updatedKeys = len(out.Updated)
		for _, v := range out.Updated {
			updatedBytes += len(v)
		}
	}

	// Force a GC and snapshot the RETAINED live set: the memoized-Mach-O leak
	// persists until f.Close, so post-GC inuse_space isolates the retained
	// floor (plus, with a real cross-version diff, the accumulated Updated map).
	runtime.GC()
	var afterGC runtime.MemStats
	runtime.ReadMemStats(&afterGC)

	if hp := os.Getenv("HEAP_OUT"); hp != "" {
		fh, ferr := os.Create(hp)
		if ferr != nil {
			t.Fatalf("create heap out: %v", ferr)
		}
		if werr := pprof.WriteHeapProfile(fh); werr != nil {
			t.Fatalf("write heap profile: %v", werr)
		}
		fh.Close()
		t.Logf("wrote heap profile (inuse_space, post-GC) to %s", hp)
	}

	stop.Store(true)
	wg.Wait()

	t.Logf("==== DSC diff memory probe ====")
	t.Logf("elapsed              : %s", elapsed.Round(time.Second))
	t.Logf("updated dylibs       : %d", updatedKeys)
	t.Logf("updated text total   : %.2f GB", gb(uint64(updatedBytes)))
	t.Logf("new dylibs           : %d", len(out.New))
	t.Logf("removed dylibs       : %d", len(out.Removed))
	t.Logf("PEAK HeapAlloc       : %.2f GB", gb(peakHeapAlloc))
	t.Logf("PEAK HeapInuse       : %.2f GB", gb(peakHeapInuse))
	t.Logf("PEAK Sys (total)     : %.2f GB", gb(peakSys))
	t.Logf("retained HeapAlloc post-GC (leak floor): %.2f GB", gb(afterGC.HeapAlloc))
}
