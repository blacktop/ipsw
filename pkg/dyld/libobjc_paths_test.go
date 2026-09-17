package dyld

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func TestLibObjCPaths(t *testing.T) {
	for _, name := range []string{
		"/usr/lib/libobjc.A.dylib",
		"/System/ExclaveKit/usr/lib/libobjc.A.dylib",
		"/System/NewKit/usr/lib/libobjc.A.dylib",
		"libobjc.A.dylib",
		"/System/NewKit/usr/lib/LIBOBJC.A.DYLIB",
	} {
		t.Run(name, func(t *testing.T) {
			for _, layout := range []string{"legacy", "header"} {
				t.Run(layout, func(t *testing.T) {
					f := libObjCFixture(t, name, layout == "header")
					opt, err := f.GetOptimizations()
					if err != nil {
						t.Fatal(err)
					}
					if got := opt.GetVersion(); got != 16 {
						t.Fatalf("optimization version = %d, want 16", got)
					}
					want := uint64(0x180000320)
					if layout == "header" {
						want = 0x180000900
					}
					if base, err := f.relativeSelectorBase(); err != nil || base != want {
						t.Fatalf("relativeSelectorBase() = %#x, %v; want %#x, nil", base, err, want)
					}
					if _, err := f.getLibObjC(); err != nil {
						t.Fatalf("getLibObjC() = %v", err)
					}
					// The fixture has no symbol table; IMP-cache parsing must reach
					// that check after locating and opening libobjc
					err = f.ImpCachesForImage()
					var formatErr *macho.FormatError
					if !errors.As(err, &formatErr) || !strings.Contains(err.Error(), "missing symbol table") {
						t.Fatalf("ImpCachesForImage() = %v, want missing symbol table", err)
					}
				})
			}
		})
	}
}

func TestLibObjCImagePreference(t *testing.T) {
	for _, tt := range []struct {
		name  string
		paths []string
		want  string
	}{
		{
			name: "standard before ExclaveKit and basename",
			paths: []string{"/System/NewKit/usr/lib/libobjc.A.dylib",
				"/System/ExclaveKit/usr/lib/libobjc.A.dylib", "/usr/lib/libobjc.A.dylib"},
			want: "/usr/lib/libobjc.A.dylib",
		},
		{
			name:  "ExclaveKit before basename",
			paths: []string{"/System/NewKit/usr/lib/libobjc.A.dylib", "/System/ExclaveKit/usr/lib/libobjc.A.dylib"},
			want:  "/System/ExclaveKit/usr/lib/libobjc.A.dylib",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{}
			for _, name := range tt.paths {
				f.Images = append(f.Images, &CacheImage{Name: name})
			}
			image, err := f.libObjCImage()
			if err != nil {
				t.Fatal(err)
			}
			if image.Name != tt.want {
				t.Fatalf("libObjCImage() = %q, want %q", image.Name, tt.want)
			}
		})
	}
}

func TestLibObjCLookupErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		images cacheImages
	}{
		{name: "missing"},
		{name: "different basename", images: cacheImages{{Name: "/usr/lib/libobjc.A.dylib.debug"}}},
		{name: "ambiguous", images: cacheImages{
			{Name: "/System/FirstKit/usr/lib/libobjc.A.dylib"},
			{Name: "/System/SecondKit/usr/lib/libobjc.A.dylib"},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{Images: tt.images}
			_, libErr := f.getLibObjC()
			impErr := f.ImpCachesForImage()
			base, baseErr := f.relativeSelectorBase()
			if base != 0 {
				t.Fatalf("relative selector base = %#x, want 0", base)
			}
			if tt.name != "ambiguous" {
				if !errors.Is(libErr, ErrImageNotFound) || !errors.Is(impErr, ErrImageNotFound) || baseErr != nil {
					t.Fatalf("lookup errors = %v, %v, %v; want ErrImageNotFound, ErrImageNotFound, nil", libErr, impErr, baseErr)
				}
				return
			}
			for _, err := range []error{libErr, impErr, baseErr} {
				if err == nil || errors.Is(err, ErrImageNotFound) {
					t.Fatalf("lookup error = %v, want ambiguous image error", err)
				}
				for _, image := range tt.images {
					if !strings.Contains(err.Error(), image.Name) {
						t.Errorf("error %q does not identify %q", err, image.Name)
					}
				}
			}
		})
	}
}

func libObjCFixture(t *testing.T, name string, headerOpts bool) *File {
	t.Helper()
	const base = uint64(0x180000000)
	data := make([]byte, 0x1000)
	write := func(off int, value any) {
		t.Helper()
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
		copy(data[off:off+b.Len()], b.Bytes())
	}
	seg := types.Segment64{
		LoadCmd: types.LC_SEGMENT_64, Len: uint32(binary.Size(types.Segment64{}) + binary.Size(types.Section64{})),
		Addr: base, Memsz: 0x1000, Filesz: 0x1000, Nsect: 1,
	}
	copy(seg.Name[:], "__TEXT")
	sec := types.Section64{Addr: base + 0x200, Offset: 0x200, Size: uint64(binary.Size(ObjcOptT{}))}
	copy(sec.Seg[:], "__TEXT")
	copy(sec.Name[:], "__objc_opt_ro")
	mh := types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_DYLIB,
		NCommands: 1, SizeCommands: seg.Len, Flags: types.DylibInCache,
	}
	off := mh.Put(data, binary.LittleEndian)
	write(off, seg)
	write(off+binary.Size(seg), sec)
	write(0x200, ObjcOptT{Version: 16, RelativeMethodSelectorBaseAddressCacheOffset: 0x120})
	f := fileWithSharedRegionStart(base)
	f.ByteOrder = binary.LittleEndian
	f.Mappings = map[types.UUID]cacheMappings{
		f.UUID: {{CacheMappingInfo: CacheMappingInfo{Address: base, Size: uint64(len(data))}}},
	}
	f.r = map[types.UUID]io.ReaderAt{f.UUID: bytes.NewReader(data)}
	f.Images = cacheImages{{Name: name, cache: f, cuuid: f.UUID,
		CacheImageTextInfo: CacheImageTextInfo{LoadAddress: base, TextSegmentSize: uint32(len(data))},
	}}
	if headerOpts {
		hdr := f.Headers[f.UUID]
		hdr.MappingOffset = uint32(binary.Size(hdr))
		hdr.ObjcOptsOffset, hdr.ObjcOptsSize = 0x800, objcOptHeaderV1Size
		f.Headers[f.UUID] = hdr
		write(0x800, ObjCOptimizationHeader{Version: 1, RelativeMethodSelectorBaseAddressOffset: 0x900})
	}
	return f
}
