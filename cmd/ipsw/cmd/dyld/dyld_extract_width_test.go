package dyld

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
	dyldpkg "github.com/blacktop/ipsw/pkg/dyld"
)

func TestRebaseMachOPointerWidth(t *testing.T) {
	for _, arch := range []string{"armv7", "arm64_32", "arm64e"} {
		t.Run(arch, func(t *testing.T) {
			dsc, path, want := pointerWidthFixture(t, arch)
			if err := rebaseMachO(dsc, path); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Errorf("file size = %d, want %d", len(got), len(want))
			}
			for i := 0; i < min(len(got), len(want)); i++ {
				if got[i] != want[i] {
					t.Fatalf("byte at %#x = %#x, want %#x", i, got[i], want[i])
				}
			}
		})
	}
}

func TestRebaseMachORejectsTruncatedPointers(t *testing.T) {
	for _, tt := range []struct {
		arch string
		size uint64
	}{
		{"armv7", 4},
		{"arm64_32", 4},
		{"arm64e", 8},
	} {
		t.Run(tt.arch, func(t *testing.T) {
			dsc, path, _ := pointerWidthFixture(t, tt.arch)
			src, err := dsc.Images[0].GetPartialMacho()
			if err != nil {
				t.Fatal(err)
			}
			// Leave the first pointer one byte short of its stored width
			src.Segment("__DATA").Filesz = 0x10 + tt.size - 1
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			err = rebaseMachO(dsc, path)
			if err == nil || !strings.Contains(err.Error(), "extends beyond segment __DATA") {
				t.Fatalf("rebaseMachO() = %v, want truncated pointer error", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("truncated first pointer changed the exported file")
			}
		})
	}
}

func pointerWidthFixture(t *testing.T, arch string) (*dyldpkg.File, string, []byte) {
	t.Helper()
	cache := make([]byte, 0x5000)
	exported := make([]byte, 0x2000)
	write := func(data []byte, off int, value any) {
		t.Helper()
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
		copy(data[off:off+b.Len()], b.Bytes())
	}
	base := uint64(0x10000000)
	magic, cpu := types.Magic32, types.CPUArm
	cacheMagic := "dyld_v1   armv7"
	slideSize := uint64(48)
	if arch == "arm64_32" {
		cpu, cacheMagic = types.CPUArm6432, "dyld_v1arm64_32"
	} else if arch == "arm64e" {
		base, magic, cpu = 0x180000000, types.Magic64, types.CPUArm64
		cacheMagic, slideSize = "dyld_v1  arm64e", 28
	}
	// Nonzero data after a pointer exposes writes wider than its ABI permits
	copy(cache[0x2000:0x3000], bytes.Repeat([]byte{0xa5}, 0x1000))
	if arch == "arm64e" {
		write(cache, 0x4000, dyldpkg.CacheSlideInfo5{Version: 5, PageSize: 0x1000, PageStartsCount: 2, ValueAdd: base})
		write(cache, 0x4018, []uint16{0x10, dyldpkg.DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE})
		write(cache, 0x2010, uint64(1<<63|0x1fd<<52|0x1234))
		write(cache, 0x2ff8, uint64(1<<63|0x5678))
	} else {
		write(cache, 0x4000, dyldpkg.CacheSlideInfo4{
			Version: 4, PageSize: 0x1000, PageStartsOffset: 40, PageStartsCount: 2,
			PageExtrasOffset: 44, PageExtrasCount: 2, DeltaMask: 0xc0000000, ValueAdd: base,
		})
		write(cache, 0x4028, []uint16{dyldpkg.DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA, dyldpkg.DYLD_CACHE_SLIDE4_PAGE_NO_REBASE})
		write(cache, 0x402c, []uint16{0x10 / 4, dyldpkg.DYLD_CACHE_SLIDE4_PAGE_EXTRA_END | 0xffc/4})
		write(cache, 0x2010, uint32(0x12348000))
		write(cache, 0x2ffc, uint32(0x12349000))
	}
	hdr := dyldpkg.CacheHeader{
		UUID: types.UUID{1}, MappingOffset: 0x400, MappingCount: 2,
		MappingWithSlideOffset: 0x440, MappingWithSlideCount: 2,
		ImagesOffset: 0x500, ImagesCount: 1, ImagesTextOffset: 0x580, ImagesTextCount: 1,
		CodeSignatureOffset: 0x600, CodeSignatureSize: 12, SharedRegionStart: base,
	}
	copy(hdr.Magic[:], cacheMagic)
	write(cache, 0, hdr)
	write(cache, 0x400, []dyldpkg.CacheMappingInfo{
		{Address: base, Size: 0x2000, InitProt: 5, MaxProt: 5},
		{Address: base + 0x2000, Size: 0x2000, FileOffset: 0x2000, InitProt: 3, MaxProt: 3},
	})
	write(cache, 0x440, []dyldpkg.CacheMappingAndSlideInfo{
		{Address: base, Size: 0x2000, InitProt: 5, MaxProt: 5},
		{Address: base + 0x2000, Size: 0x2000, FileOffset: 0x2000, InitProt: 3, MaxProt: 3, SlideInfoOffset: 0x4000, SlideInfoSize: slideSize},
	})
	write(cache, 0x500, dyldpkg.CacheImageInfo{Address: base + 0x1000, PathFileOffset: 0x540})
	copy(cache[0x540:], "/usr/lib/libTest.dylib\x00")
	write(cache, 0x580, dyldpkg.CacheImageTextInfo{LoadAddress: base + 0x1000, TextSegmentSize: 0x1000})
	// Empty code-signature superblob
	binary.BigEndian.PutUint32(cache[0x600:], 0xfade0cc0)
	binary.BigEndian.PutUint32(cache[0x604:], 12)

	writeMachO := func(data []byte, fileOffset uint64, flags types.HeaderFlag) {
		t.Helper()
		segSize := binary.Size(types.Segment32{})
		if magic == types.Magic64 {
			segSize = binary.Size(types.Segment64{})
		}
		mh := types.FileHeader{Magic: magic, CPU: cpu, Type: types.MH_DYLIB, NCommands: 2, SizeCommands: uint32(2 * segSize), Flags: flags}
		off := mh.Put(data, binary.LittleEndian)
		for i, name := range []string{"__TEXT", "__DATA"} {
			var segName [16]byte
			copy(segName[:], name)
			addr := base + uint64(i+1)*0x1000
			if magic == types.Magic64 {
				write(data, off, types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: uint32(segSize), Name: segName,
					Addr: addr, Memsz: 0x1000, Offset: fileOffset, Filesz: 0x1000})
			} else {
				write(data, off, types.Segment32{LoadCmd: types.LC_SEGMENT, Len: uint32(segSize), Name: segName,
					Addr: uint32(addr), Memsz: 0x1000, Offset: uint32(fileOffset), Filesz: 0x1000})
			}
			off += segSize
			fileOffset += 0x1000
		}
	}
	writeMachO(cache[0x1000:], 0x1000, types.DylibInCache)
	writeMachO(exported, 0, 0)
	copy(exported[0x1000:], cache[0x2000:0x3000])
	dir := t.TempDir()
	path := filepath.Join(dir, "libTest.dylib")
	if err := os.WriteFile(path, exported, 0o600); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(dir, "dyld_shared_cache_"+arch)
	if err := os.WriteFile(cachePath, cache, 0o600); err != nil {
		t.Fatal(err)
	}
	// Open builds the image index used to recover the original segment extents
	dsc, err := dyldpkg.Open(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dsc.Close() })
	want := bytes.Clone(exported)
	if arch == "arm64e" {
		binary.LittleEndian.PutUint64(want[0x1010:], 0x180001234)
		binary.LittleEndian.PutUint64(want[0x1ff8:], 0x180005678)
	} else {
		binary.LittleEndian.PutUint32(want[0x1010:], 0x22348000)
		binary.LittleEndian.PutUint32(want[0x1ffc:], 0x22349000)
	}
	return dsc, path, want
}
