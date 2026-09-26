package dyld

import (
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

func BenchmarkSlidePointerEncoded(b *testing.B) {
	f := &File{MappingsWithSlideInfo: make(map[mtypes.UUID]cacheMappingsWithSlideInfo), SlideInfo: CacheSlideInfo2{ValueAdd: 0x100000, DeltaMask: 0xff00000000000000}}
	for i := range 80 {
		f.MappingsWithSlideInfo[mtypes.UUID{byte(i + 1)}] = cacheMappingsWithSlideInfo{{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{Address: 0x180000000 + uint64(i)*0x10000, Size: 0x10000}}}
	}
	image := &CacheImage{cache: f}
	for b.Loop() {
		if image.SlidePointer(0x8000000000000010) != 0x100010 {
			b.Fatal("wrong pointer")
		}
	}
}

func BenchmarkSlidePointerUnslidHint(b *testing.B) {
	f := &File{MappingsWithSlideInfo: make(map[mtypes.UUID]cacheMappingsWithSlideInfo)}
	for i := range 80 {
		f.MappingsWithSlideInfo[mtypes.UUID{byte(i + 1)}] = cacheMappingsWithSlideInfo{{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{Address: 0x180000000 + uint64(i)*0x10000, Size: 0x10000}}}
	}
	// Interleave two images with different hot mappings, as when walking their
	// CFStrings. Each image retains locality even though the addresses alternate.
	images := [2]*CacheImage{{cache: f}, {cache: f}}
	addresses := [2]uint64{0x180000008, 0x1804f0008}
	n := 0
	b.ReportAllocs()
	for b.Loop() {
		if got := images[n].SlidePointer(addresses[n]); got != addresses[n] {
			b.Fatalf("SlidePointer() = %#x, want %#x", got, addresses[n])
		}
		n ^= 1
	}
}

// BenchmarkSlidePointerUnslidAlternating models the isa/data lookups within
// each CFString: one image alternates between two distant cache mappings.
func BenchmarkSlidePointerUnslidAlternating(b *testing.B) {
	f := &File{MappingsWithSlideInfo: make(map[mtypes.UUID]cacheMappingsWithSlideInfo)}
	for i := range 80 {
		f.MappingsWithSlideInfo[mtypes.UUID{byte(i + 1)}] = cacheMappingsWithSlideInfo{{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{Address: 0x180000000 + uint64(i)*0x10000, Size: 0x10000}}}
	}
	image := &CacheImage{cache: f}
	addresses := [2]uint64{0x180000008, 0x1804f0008}
	n := 0
	b.ReportAllocs()
	for b.Loop() {
		if got := image.SlidePointer(addresses[n]); got != addresses[n] {
			b.Fatalf("SlidePointer() = %#x, want %#x", got, addresses[n])
		}
		n ^= 1
	}
}
