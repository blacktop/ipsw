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

func TestRebaseMachOUsesOriginalSegmentExtents(t *testing.T) {
	for _, name := range []string{"padded segments", "aligned mapping end"} {
		t.Run(name, func(t *testing.T) {
			fixture := newRebaseFixture(t)
			if name == "aligned mapping end" {
				fixture.original[2].Addr = 0x180002ff8
				fixture.original[2].Offset = 0x2ff8
				fixture.segments[2].Addr = fixture.original[2].Addr
				writeRebaseFixture(t, fixture.cache, 0x2010, uint64(1<<63|0x1fd<<52|0x1234))
				writeRebaseFixture(t, fixture.cache, 0x2ff8, uint64(1<<63|0x5678))
				copy(fixture.exported[0x1000:0x1008], fixture.cache[0x2010:0x2018])
				copy(fixture.exported[0x2000:0x2008], fixture.cache[0x2ff8:0x3000])
			}
			dsc, path := fixture.open(t)
			if err := rebaseMachO(dsc, path); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Clone(fixture.exported)
			binary.LittleEndian.PutUint64(want[0x1000:], 0x180001234)
			binary.LittleEndian.PutUint64(want[0x2000:], 0x180005678)
			if len(got) != len(want) {
				t.Fatalf("file size = %d, want %d", len(got), len(want))
			}
			if !bytes.Equal(got, want) {
				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("byte at %#x = %#x, want %#x; only original pointer extents may change", i, got[i], want[i])
					}
				}
			}
		})
	}
}

func TestRebaseMachORejectsInvalidLayouts(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mutate  func(*rebaseFixture)
		wantErr string
	}{
		{
			name:    "missing segment",
			mutate:  func(f *rebaseFixture) { f.segments = append(f.segments[:1], f.segments[2:]...) },
			wantErr: "exported segment __DATA_CONST does not match",
		},
		{
			name:    "changed address",
			mutate:  func(f *rebaseFixture) { f.segments[1].Addr++ },
			wantErr: "exported segment __DATA_CONST does not match",
		},
		{
			name:    "short file extent",
			mutate:  func(f *rebaseFixture) { f.segments[1].Filesz = 4 },
			wantErr: "exported segment __DATA_CONST does not match",
		},
		{
			name:    "segment exceeds mapping",
			mutate:  func(f *rebaseFixture) { f.original[1].Filesz = 0x1000 },
			wantErr: "exceeds remaining mapping size",
		},
		{
			name:    "pointer exceeds segment",
			mutate:  func(f *rebaseFixture) { f.original[1].Filesz = 4 },
			wantErr: "extends beyond segment __DATA_CONST",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newRebaseFixture(t)
			tt.mutate(fixture)
			dsc, path := fixture.open(t)
			err := rebaseMachO(dsc, path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("rebaseMachO() = %v, want error containing %q", err, tt.wantErr)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, fixture.exported) {
				t.Fatal("invalid first data segment must be rejected before writing pointers")
			}
		})
	}
}

func TestOpenRejectsInvalidSlideInfo(t *testing.T) {
	for _, layout := range []string{"legacy", "modern"} {
		t.Run(layout, func(t *testing.T) {
			for _, corrupt := range []string{"zero page size", "truncated header"} {
				t.Run(corrupt, func(t *testing.T) {
					fixture := newRebaseFixture(t)
					if layout == "legacy" {
						var hdr dyldpkg.CacheHeader
						if err := binary.Read(bytes.NewReader(fixture.cache), binary.LittleEndian, &hdr); err != nil {
							t.Fatal(err)
						}
						hdr.SlideInfoOffsetUnused, hdr.SlideInfoSizeUnused = 0x4000, 42
						writeRebaseFixture(t, fixture.cache, 0, hdr)
						writeRebaseFixture(t, fixture.cache, 0x4000, dyldpkg.CacheSlideInfo2{
							Version: 2, PageSize: 0x1000, PageStartsOffset: 40, PageStartsCount: 1,
						})
					}
					wantErr := "invalid slide info page size: 0"
					if corrupt == "zero page size" {
						binary.LittleEndian.PutUint32(fixture.cache[0x4004:], 0)
					} else {
						fixture.cache = fixture.cache[:0x4008]
						wantErr = "unexpected EOF"
					}
					cachePath, _ := fixture.write(t)
					f, err := dyldpkg.Open(cachePath)
					if f != nil {
						f.Close()
					}
					if err == nil || !strings.Contains(err.Error(), wantErr) {
						t.Fatalf("Open() = %v, want error containing %q", err, wantErr)
					}
				})
			}
		})
	}
}

// rebaseFixture models the original cache layout and Export's padded segments
type rebaseFixture struct {
	cache, exported    []byte
	original, segments []types.Segment64
}

func newRebaseFixture(t *testing.T) *rebaseFixture {
	t.Helper()
	const base, pointerSize = uint64(0x180000000), uint64(8)
	f := &rebaseFixture{cache: make([]byte, 0x5000), exported: make([]byte, 0x4000)}
	hdr := dyldpkg.CacheHeader{
		UUID: types.UUID{1}, MappingOffset: 0x400, MappingCount: 2,
		MappingWithSlideOffset: 0x440, MappingWithSlideCount: 2,
		ImagesOffset: 0x500, ImagesCount: 1, ImagesTextOffset: 0x580, ImagesTextCount: 1,
		CodeSignatureOffset: 0x600, CodeSignatureSize: 12, SharedRegionStart: base,
	}
	const slideSize = uint64(26)
	copy(hdr.Magic[:], "dyld_v1  arm64e")
	writeRebaseFixture(t, f.cache, 0x4000, dyldpkg.CacheSlideInfo5{Version: 5, PageSize: 0x1000, PageStartsCount: 1, ValueAdd: base})
	writeRebaseFixture(t, f.cache, 0x4018, uint16(0x10))
	for i, raw := range []uint64{1<<63 | 1<<52 | 0x1234, 1<<63 | 1<<52 | 0x5678, 1<<63 | 0x9abc} {
		writeRebaseFixture(t, f.cache, 0x2010+i*8, raw)
	}
	writeRebaseFixture(t, f.cache, 0, hdr)
	writeRebaseFixture(t, f.cache, 0x400, []dyldpkg.CacheMappingInfo{
		{Address: base, Size: 0x2000, InitProt: 5, MaxProt: 5},
		{Address: base + 0x2000, Size: 0x1000, FileOffset: 0x2000, InitProt: 3, MaxProt: 3},
	})
	writeRebaseFixture(t, f.cache, 0x440, []dyldpkg.CacheMappingAndSlideInfo{
		{Address: base, Size: 0x2000, InitProt: 5, MaxProt: 5},
		{Address: base + 0x2000, Size: 0x1000, FileOffset: 0x2000, InitProt: 3, MaxProt: 3, SlideInfoOffset: 0x4000, SlideInfoSize: slideSize},
	})
	writeRebaseFixture(t, f.cache, 0x500, dyldpkg.CacheImageInfo{Address: base + 0x1000, PathFileOffset: 0x540})
	copy(f.cache[0x540:], "/usr/lib/libTest.dylib\x00")
	writeRebaseFixture(t, f.cache, 0x580, dyldpkg.CacheImageTextInfo{LoadAddress: base + 0x1000, TextSegmentSize: 0x1000})
	// Empty code-signature superblob
	binary.BigEndian.PutUint32(f.cache[0x600:], 0xfade0cc0)
	binary.BigEndian.PutUint32(f.cache[0x604:], 12)

	f.original = []types.Segment64{
		{Addr: base + 0x1000, Memsz: 0x1000, Offset: 0x1000, Filesz: 0x1000},
		{Addr: base + 0x2010, Memsz: pointerSize, Offset: 0x2010, Filesz: pointerSize},
		{Addr: base + 0x2018, Memsz: pointerSize, Offset: 0x2018, Filesz: pointerSize},
		// LINKEDIT is regenerated during export; its cache chain must not be applied
		{Addr: base + 0x2020, Memsz: pointerSize, Offset: 0x2020, Filesz: pointerSize},
		// A segment with no file data need not have a cache mapping
		{Addr: base + 0x8000, Memsz: 0x1000},
	}
	for i, name := range []string{"__TEXT", "__DATA_CONST", "__AUTH_CONST", "__LINKEDIT", "__BSS"} {
		copy(f.original[i].Name[:], name)
	}
	f.segments = append([]types.Segment64(nil), f.original...)
	for i := range f.segments {
		f.segments[i].Offset = uint64(i) * 0x1000
		if f.original[i].Filesz != 0 {
			f.segments[i].Filesz, f.segments[i].Memsz = 0x1000, 0x1000
		}
	}
	// Nonzero padding reveals writes outside the original segment extents
	copy(f.exported[0x1000:], bytes.Repeat([]byte{0xa5}, 0x3000))
	copy(f.exported[0x1000:0x1000+pointerSize], f.cache[0x2010:0x2010+pointerSize])
	copy(f.exported[0x2000:0x2000+pointerSize], f.cache[0x2018:0x2018+pointerSize])
	return f
}

func (f *rebaseFixture) open(t *testing.T) (*dyldpkg.File, string) {
	t.Helper()
	cachePath, path := f.write(t)
	dsc, err := dyldpkg.Open(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dsc.Close() })
	return dsc, path
}

func (f *rebaseFixture) write(t *testing.T) (string, string) {
	t.Helper()
	writeMachO := func(data []byte, segments []types.Segment64, flags types.HeaderFlag) {
		t.Helper()
		segmentSize := binary.Size(types.Segment64{})
		header := types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_DYLIB, NCommands: uint32(len(segments)), Flags: flags}
		header.SizeCommands = uint32(len(segments) * segmentSize)
		off := header.Put(data, binary.LittleEndian)
		for _, seg := range segments {
			seg.LoadCmd, seg.Len = types.LC_SEGMENT_64, uint32(segmentSize)
			writeRebaseFixture(t, data, off, seg)
			off += segmentSize
		}
	}
	writeMachO(f.cache[0x1000:], f.original, types.DylibInCache)
	writeMachO(f.exported, f.segments, 0)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "dyld_shared_cache_arm64e")
	if err := os.WriteFile(cachePath, f.cache, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "libTest.dylib")
	if err := os.WriteFile(path, f.exported, 0o600); err != nil {
		t.Fatal(err)
	}
	return cachePath, path
}

func writeRebaseFixture(t *testing.T, data []byte, offset int, value any) {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
		t.Fatal(err)
	}
	if offset < 0 || offset > len(data) || b.Len() > len(data)-offset {
		t.Fatalf("fixture write of %d bytes at %#x exceeds buffer of %d bytes", b.Len(), offset, len(data))
	}
	copy(data[offset:], b.Bytes())
}
