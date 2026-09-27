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
	"github.com/spf13/viper"
)

func TestObjCSearchRetainsMatchesAndReturnsImageFailures(t *testing.T) {
	const base = 0x180000000
	data := make([]byte, 0x4000)
	put := func(off int, value any) {
		t.Helper()
		var buf bytes.Buffer
		if err := binary.Write(&buf, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
		copy(data[off:], buf.Bytes())
	}
	hdr := dyldpkg.CacheHeader{
		UUID:          types.UUID{1},
		MappingOffset: 0x400, MappingCount: 1,
		MappingWithSlideOffset: 0x480, MappingWithSlideCount: 1,
		CodeSignatureOffset: 0x800, CodeSignatureSize: 12,
		ImagesOffsetOld: 0x500, ImagesCountOld: 2,
		ImagesTextOffset: 0x600, ImagesTextCount: 2,
	}
	copy(hdr.Magic[:], "dyld_v1  arm64e")
	put(0, hdr)
	binary.BigEndian.PutUint32(data[0x800:], 0xfade0cc0)
	binary.BigEndian.PutUint32(data[0x804:], 12)
	put(0x400, dyldpkg.CacheMappingInfo{Address: base, Size: uint64(len(data)), InitProt: 5, MaxProt: 5})
	put(0x480, dyldpkg.CacheMappingAndSlideInfo{Address: base, Size: uint64(len(data)), InitProt: 5, MaxProt: 5})
	put(0x500, []dyldpkg.CacheImageInfo{
		{Address: base + 0x1000, PathFileOffset: 0x700},
		{Address: base + 0x2000, PathFileOffset: 0x780},
	})
	put(0x600, []dyldpkg.CacheImageTextInfo{
		{LoadAddress: base + 0x1000, TextSegmentSize: 0x1000},
		{LoadAddress: base + 0x2000, TextSegmentSize: 0x1000},
	})
	copy(data[0x700:], "/usr/lib/libSyntheticGood.dylib\x00")
	copy(data[0x780:], "/usr/lib/libSyntheticBroken.dylib\x00")
	put(0x1000, types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_DYLIB, NCommands: 1, SizeCommands: 152})
	seg := types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 152, Addr: base + 0x1000, Memsz: 0x1000, Offset: 0x1000, Filesz: 0x1000, Nsect: 1}
	copy(seg.Name[:], "__DATA")
	put(0x1020, seg)
	sec := types.Section64{Addr: base + 0x1800, Size: 8, Offset: 0x1800}
	copy(sec.Name[:], "__objc_selrefs")
	copy(sec.Seg[:], "__DATA")
	put(0x1068, sec)
	put(0x1800, uint64(base+0x1900))
	copy(data[0x1900:], "syntheticSelector:\x00")
	key := "dyld.search.objc.sel"
	old := viper.Get(key)
	viper.Set(key, "syntheticSelector")
	defer viper.Set(key, old)
	for _, stage := range []string{"Mach-O", "ObjC selector references"} {
		t.Run(stage, func(t *testing.T) {
			if stage == "Mach-O" {
				put(0x2000, uint32(0x12345678))
			} else {
				copy(data[0x2000:0x20b8], data[0x1000:0x10b8])
				seg.Addr, seg.Offset = base+0x2000, 0x2000
				put(0x2020, seg)
				// Parseable Mach-O with an unreadable ObjC section address.
				sec.Addr, sec.Offset = base+0x8000, 0x2800
				put(0x2068, sec)
			}
			path := filepath.Join(t.TempDir(), "synthetic-cache")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			dyldSearchObjcCmd.SetOut(&out)
			defer dyldSearchObjcCmd.SetOut(nil)
			err := dyldSearchObjcCmd.RunE(dyldSearchObjcCmd, []string{path})
			if err == nil || !strings.Contains(err.Error(), "libSyntheticBroken.dylib") || !strings.Contains(err.Error(), "1 images failed") || !strings.Contains(err.Error(), "parse "+stage) {
				t.Fatalf("search error = %v; want contextual partial-scan %s failure", err, stage)
			}
			if !strings.Contains(out.String(), "syntheticSelector:") || !strings.Contains(out.String(), "libSyntheticGood.dylib") {
				t.Fatalf("successful partial matches were lost: %s", out.String())
			}
		})
	}
}
