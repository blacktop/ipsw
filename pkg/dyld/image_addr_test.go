package dyld

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"
	"testing"

	"github.com/blacktop/go-macho"
)

// linearImageContainingVMAddr preserves the original lookup as a test oracle.
func linearImageContainingVMAddr(f *File, address uint64) (*CacheImage, error) {
	for _, img := range f.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			return nil, err
		}
		defer m.Close()
		if seg := m.FindSegmentForVMAddr(address); seg != nil {
			return img, nil
		}
	}
	return nil, fmt.Errorf("address %#x not in any dylib", address)
}

func openImageAddrCache(t testing.TB) *File {
	t.Helper()
	path := os.Getenv("DSC")
	if path == "" {
		t.Skip("set DSC to test a real dyld cache")
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func BenchmarkGetImageContainingVMAddr(b *testing.B) {
	f := openImageAddrCache(b)
	var addresses [64]uint64
	found := false
	// Use a late image so the benchmark exercises a substantial linear scan.
	for i := len(f.Images) - 1; i >= 0; i-- {
		m, err := f.Images[i].GetPartialMacho()
		if err != nil {
			b.Fatal(err)
		}
		seg := m.Segment("__DATA")
		if seg != nil && seg.Memsz >= uint64(len(addresses)) {
			for j := range addresses {
				addresses[j] = seg.Addr + uint64(j)*(seg.Memsz/uint64(len(addresses)))
			}
			found = true
			break
		}
	}
	if !found {
		b.Fatal("cache has no image with a suitable __DATA segment")
	}
	if _, err := f.GetImageContainingVMAddr(addresses[0]); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.GetImageContainingVMAddr(addresses[i%len(addresses)]); err != nil {
			b.Fatal(err)
		}
	}
}

func TestImageContainingVMAddrSynthetic(t *testing.T) {
	image := func(name string, start, size uint64) *CacheImage {
		m := &macho.File{}
		m.Loads = append(m.Loads, &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__DATA", Addr: start, Memsz: size}})
		return &CacheImage{Name: name, pm: m}
	}
	first := image("first", 200, 100)
	second := image("second", 100, 300)
	third := image("third", 500, 10)
	f := &File{Images: cacheImages{first, second, third}}
	// No __TEXT index: these lookups must resolve from the segment index.
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for _, tc := range []struct {
				addr uint64
				want *CacheImage
			}{
				{100, second}, {199, second}, {200, first}, {250, first},
				{299, first}, {300, second}, {399, second}, {500, third}, {509, third},
			} {
				got, err := f.GetImageContainingVMAddr(tc.addr)
				if err != nil || got != tc.want {
					t.Errorf("address %d: got %p, %v; want %p", tc.addr, got, err, tc.want)
				}
			}
		})
	}
	wg.Wait()
	if len(f.imageSegments) != 3 {
		t.Fatalf("built %d ranges, want exactly 3 from one build", len(f.imageSegments))
	}
	// A second build would see the altered cached Mach-O. The snapshot must stay
	// immutable after all concurrent first callers have returned.
	first.pm = &macho.File{}
	got, err := f.GetImageContainingVMAddr(250)
	if err != nil || got != first {
		t.Fatalf("index rebuilt: got %p, %v", got, err)
	}
	for _, addr := range []uint64{0, 99, 400, 499, 510, ^uint64(0)} {
		got, err := f.GetImageContainingVMAddr(addr)
		want := fmt.Sprintf("address %#x not in any dylib", addr)
		if got != nil || err == nil || err.Error() != want {
			t.Fatalf("miss %d: got %p, %v; want %q", addr, got, err, want)
		}
	}
}

func TestImageContainingVMAddrTextUsesSegmentIndex(t *testing.T) {
	m := &macho.File{}
	m.Loads = append(m.Loads, &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 100, Memsz: 100}})
	img := &CacheImage{pm: m}
	img.LoadAddress, img.TextSegmentSize = 100, 100
	f := &File{Images: cacheImages{img}, sortedImages: []*CacheImage{img}}
	got, err := f.GetImageContainingVMAddr(150)
	if got != img || err != nil {
		t.Fatalf("text lookup = %p, %v", got, err)
	}
	if len(f.imageSegments) != 1 {
		t.Fatalf("text lookup built %d ranges, want 1", len(f.imageSegments))
	}
}

func TestImageContainingVMAddrParseError(t *testing.T) {
	m := &macho.File{}
	m.Loads = append(m.Loads, &macho.Segment{SegmentHeader: macho.SegmentHeader{Addr: 100, Memsz: 10}})
	good := &CacheImage{pm: m}
	f := &File{Images: cacheImages{good}}
	f.Images = append(f.Images, &CacheImage{cache: f}) // no mapping for this image
	for _, addr := range []uint64{100, 109, 110, 0} {
		want, wantErr := linearImageContainingVMAddr(f, addr)
		got, err := f.GetImageContainingVMAddr(addr)
		if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("address %d: got %p, %v; want %p, %v", addr, got, err, want, wantErr)
		}
	}
}

func TestImageContainingVMAddrRealCache(t *testing.T) {
	f := openImageAddrCache(t)
	count := 0
	check := func(addr uint64) {
		t.Helper()
		want, wantErr := linearImageContainingVMAddr(f, addr)
		got, err := f.GetImageContainingVMAddr(addr)
		if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			name := func(img *CacheImage) string {
				if img == nil {
					return "<nil>"
				}
				return img.Name
			}
			t.Fatalf("address %#x (sample %d): got %s, %v; want %s, %v", addr, count, name(got), err, name(want), wantErr)
		}
		count++
	}
	for _, img := range f.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			t.Fatal(err)
		}
		for _, seg := range m.Segments() {
			if seg.Memsz == 0 {
				continue
			}
			check(seg.Addr)
			check(seg.Addr + seg.Memsz/2)
			check(seg.Addr + seg.Memsz - 1)
		}
	}
	segmentCount := count
	type interval struct{ start, size uint64 }
	var mappings []interval
	for _, group := range f.Mappings {
		for _, m := range group {
			if m.Size != 0 {
				mappings = append(mappings, interval{m.Address, m.Size})
			}
		}
	}
	if len(mappings) == 0 {
		t.Fatal("cache has no mappings")
	}
	sort.Slice(mappings, func(i, j int) bool { return mappings[i].start < mappings[j].start })
	rng := rand.New(rand.NewSource(0x1a6add))
	for range 10000 {
		m := mappings[rng.Intn(len(mappings))]
		check(m.start + rng.Uint64()%m.size)
	}
	outside := 0
	for outside < 1000 {
		addr := rng.Uint64()
		inside := false
		for _, m := range mappings {
			if addr >= m.start && addr-m.start < m.size {
				inside = true
				break
			}
		}
		if !inside {
			check(addr)
			outside++
		}
	}
	t.Logf("compared %d addresses: %d segment samples, 10000 inside mappings, 1000 outside mappings", count, segmentCount)
}

func TestImageContainingVMAddrTextPreservesLinearPrecedence(t *testing.T) {
	makeImage := func(name string, start, size uint64) *CacheImage {
		m := &macho.File{}
		m.Loads = append(m.Loads, &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: start, Memsz: size}})
		image := &CacheImage{Name: name, pm: m}
		image.LoadAddress = start
		image.TextSegmentSize = uint32(size)
		return image
	}
	t.Run("overlap", func(t *testing.T) {
		first, second := makeImage("first", 100, 200), makeImage("second", 200, 100)
		f := &File{Images: cacheImages{first, second}, sortedImages: []*CacheImage{first, second}}
		want, wantErr := linearImageContainingVMAddr(f, 250)
		got, err := f.GetImageContainingVMAddr(250)
		if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("got image=%p error=%v, want image=%p error=%v", got, err, want, wantErr)
		}
	})
	t.Run("earlier_parse_error", func(t *testing.T) {
		good := makeImage("good", 200, 100)
		f := &File{}
		f.Images = cacheImages{&CacheImage{cache: f}, good}
		f.sortedImages = []*CacheImage{good}
		want, wantErr := linearImageContainingVMAddr(f, 250)
		got, err := f.GetImageContainingVMAddr(250)
		if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("got image=%v error=%v, want image=%v error=%v", got != nil, err, want != nil, wantErr)
		}
	})
}

func TestImageContainingVMAddrIncrementalClose(t *testing.T) {
	image := func(start uint64) *CacheImage {
		m := &macho.File{}
		m.Loads = append(m.Loads, &macho.Segment{SegmentHeader: macho.SegmentHeader{Addr: start, Memsz: 10}})
		return &CacheImage{pm: m}
	}
	first, second := image(200), image(100)
	f := &File{Images: cacheImages{first, second}}
	f.Images = append(f.Images, &CacheImage{cache: f})
	for i, tc := range []struct {
		addr uint64
		want *CacheImage
		next int
	}{
		{200, first, 1},
		{209, first, 1},
		{100, second, 2},
		{200, first, 2},
	} {
		got, err := f.GetImageContainingVMAddr(tc.addr)
		if got != tc.want || err != nil || f.imageSegmentsNext != tc.next || len(f.imageSegments) != tc.next || f.imageSegmentsErr != nil {
			t.Fatalf("step %d: got %p, %v; cursor=%d ranges=%d parse error=%v", i, got, err, f.imageSegmentsNext, len(f.imageSegments), f.imageSegmentsErr)
		}
	}
	if _, err := f.GetImageContainingVMAddr(300); err == nil {
		t.Fatal("expected parse error beyond collected prefix")
	}
	savedErr := f.imageSegmentsErr
	// Replacing the malformed input must not retry a recorded parse failure.
	f.Images[2] = image(300)
	if _, err := f.GetImageContainingVMAddr(300); err != savedErr {
		t.Fatalf("parse error changed: %v, want %v", err, savedErr)
	}
	if got, err := f.GetImageContainingVMAddr(200); got != first || err != nil {
		t.Fatalf("collected hit after error: %p, %v", got, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if f.imageSegments != nil || f.imageSegmentsNext != 0 || f.imageSegmentsErr != nil {
		t.Fatal("Close retained segment index state")
	}
	if _, err := f.GetImageContainingVMAddr(200); err != os.ErrClosed {
		t.Fatalf("lookup after Close: %v", err)
	}
	if f.imageSegments != nil {
		t.Fatal("lookup rebuilt index after Close")
	}
}
