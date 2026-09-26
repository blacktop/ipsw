package dyld

import (
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestW17Index(t *testing.T) {
	if os.Getenv("SEGMENT_INDEX_SWEEP") != "1" {
		t.Skip("set SEGMENT_INDEX_SWEEP=1 and the sweep input/output paths")
	}
	f, err := Open(os.Getenv("DSC"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = f.OpenOrCreateA2SCache(os.Getenv("A2S")); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	if len(f.Images) == 0 {
		t.Fatal("no images")
	}
	name := "/usr/lib/system/libsystem_malloc.dylib"
	var before, first, repeat runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	index, err := f.GetDylibIndex(name)
	firstNS := time.Since(start).Nanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&first)
	start = time.Now()
	for range 100 {
		next, err := f.GetDylibIndex(name)
		if err != nil {
			t.Fatal(err)
		}
		if next != index {
			t.Fatal("index changed on repeat")
		}
	}
	repeatNS := time.Since(start).Nanoseconds() / 100
	runtime.ReadMemStats(&repeat)
	runtime.GC()
	var retained runtime.MemStats
	runtime.ReadMemStats(&retained)
	runtime.KeepAlive(f)
	result := map[string]any{"name": name, "index": index, "first_ns": firstNS, "repeat_ns_per_query": repeatNS, "first_total_alloc": first.TotalAlloc - before.TotalAlloc, "repeat_total_alloc_per_query": (repeat.TotalAlloc - first.TotalAlloc) / 100, "first_mallocs": first.Mallocs - before.Mallocs, "repeat_mallocs_per_query": (repeat.Mallocs - first.Mallocs) / 100, "retained_heap": retained.HeapAlloc}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("METRICS_OUT"), data, 0600); err != nil {
		t.Fatal(err)
	}
	stable, err := json.Marshal(map[string]any{"name": name, "index": index, "repeat_count": 100})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("RESULT_OUT"), stable, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestW17SegmentIndex(t *testing.T) {
	if os.Getenv("SEGMENT_INDEX_SWEEP") != "1" {
		t.Skip("set SEGMENT_INDEX_SWEEP=1 and the sweep input/output paths")
	}
	f, err := Open(os.Getenv("DSC"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = f.OpenOrCreateA2SCache(os.Getenv("A2S")); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	addr, err := strconv.ParseUint(os.Getenv("ADDR"), 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	var before, first, repeat runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	img, err := f.GetImageContainingVMAddr(addr)
	firstNS := time.Since(start).Nanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	if img.Name != "/usr/lib/system/libsystem_malloc.dylib" {
		t.Fatalf("unexpected image %s", img.Name)
	}
	runtime.ReadMemStats(&first)
	start = time.Now()
	for range 100 {
		again, err := f.GetImageContainingVMAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		if again != img {
			t.Fatal("image changed on repeat")
		}
	}
	repeatNS := time.Since(start).Nanoseconds() / 100
	runtime.ReadMemStats(&repeat)
	runtime.GC()
	var retained, closed runtime.MemStats
	runtime.ReadMemStats(&retained)
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&closed)
	runtime.KeepAlive(f)
	result := map[string]any{"first_ns": firstNS, "repeat_ns_per_query": repeatNS, "first_total_alloc": first.TotalAlloc - before.TotalAlloc, "repeat_total_alloc_per_query": (repeat.TotalAlloc - first.TotalAlloc) / 100, "first_mallocs": first.Mallocs - before.Mallocs, "repeat_mallocs_per_query": (repeat.Mallocs - first.Mallocs) / 100, "retained_heap": retained.HeapAlloc, "heap_after_close": closed.HeapAlloc}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("METRICS_OUT"), data, 0600); err != nil {
		t.Fatal(err)
	}
	stable, err := json.Marshal(map[string]any{"address": addr, "image": img.Name, "repeat_count": 100})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(os.Getenv("RESULT_OUT"), stable, 0600); err != nil {
		t.Fatal(err)
	}
}
