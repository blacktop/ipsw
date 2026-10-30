package dyld

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestFileStringAppendedHeaderRegions(t *testing.T) {
	for _, tt := range []struct {
		name                               string
		mappingOffset                      uint32
		dyld4                              bool
		swiftOffset, dynamicOffset         uint64
		wantRosetta, wantObjc, wantDynamic bool
	}{
		{"macOS 11", 0x140, false, 0x5000, 0x6000, false, false, false},
		{"macOS 12", 0x1c8, true, 0x5000, 0x6000, true, false, false},
		{"dynamic without swift", 0x200, true, 0, 0x6000, true, true, true},
		{"swift without dynamic", 0x200, true, 0x5000, 0, true, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uuid := types.UUID{1}
			hdr := CacheHeader{
				MappingOffset:        tt.mappingOffset,
				SharedRegionStart:    0x100000000,
				RosettaReadOnlyAddr:  0x100001000,
				RosettaReadOnlySize:  0x1000,
				RosettaReadWriteAddr: 0x100002000,
				RosettaReadWriteSize: 0x1000,
				ObjcOptsOffset:       0x3000,
				ObjcOptsSize:         0x1000,
				SwiftOptsOffset:      tt.swiftOffset,
				DynamicDataOffset:    tt.dynamicOffset,
				DynamicDataMaxSize:   0x1000,
			}
			f := File{
				UUID:    uuid,
				IsDyld4: tt.dyld4,
				Headers: map[types.UUID]CacheHeader{uuid: hdr},
				MappingsWithSlideInfo: map[types.UUID]cacheMappingsWithSlideInfo{
					uuid: {{Address: 0x100000000, Size: 0x1000}},
				},
			}
			output := f.String(false)
			for _, region := range []struct {
				label string
				want  bool
			}{
				{"Rosetta RO:", tt.wantRosetta},
				{"Rosetta RW:", tt.wantRosetta},
				{"ObjC Opts:", tt.wantObjc},
				{"Dynamic Config:", tt.wantDynamic},
			} {
				if got := strings.Contains(output, region.label); got != region.want {
					t.Errorf("%s present = %t, want %t", region.label, got, region.want)
				}
			}
		})
	}
}

func TestImagesTextInfo(t *testing.T) {
	for _, tt := range []struct {
		name   string
		header CacheHeader
		want   string
	}{
		{
			name: "legacy image table",
			header: CacheHeader{
				ImagesOffsetOld: 0x400, ImagesCountOld: 2,
				ImagesTextOffset: 0x580, ImagesTextCount: 1,
			},
			want: "ImagesText Info:               0KB, offset:  0x000000580 -> 0x0000005A0\n",
		},
		{
			name: "modern image table",
			header: CacheHeader{
				ImagesOffset: 0x400, ImagesCount: 40,
				ImagesTextOffset: 0x100001000, ImagesTextCount: 33,
			},
			want: "ImagesText Info:               1KB, offset:  0x100001000 -> 0x100001420\n",
		},
		{
			name: "no text info",
			header: CacheHeader{
				ImagesOffsetOld: 0x400, ImagesCountOld: 2,
				ImagesOffset: 0x500, ImagesCount: 3,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uuid := types.UUID{1}
			f := &File{Headers: map[types.UUID]CacheHeader{uuid: tt.header}}
			if got := f.getImagesTextInfo(uuid); got != tt.want {
				t.Fatalf("getImagesTextInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}
