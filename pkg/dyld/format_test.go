package dyld

import (
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestGetImagesTextInfo(t *testing.T) {
	tests := []struct {
		name string
		hdr  CacheHeader
		want string
	}{
		{
			name: "images text array, not images array",
			hdr: CacheHeader{
				ImagesOffset:     0x228,
				ImagesCount:      1,
				ImagesTextOffset: 0x248,
				ImagesTextCount:  1,
			},
			want: "ImagesText Info:               0KB, offset:  0x000000248 -> 0x000000268\n",
		},
		{
			name: "old images fields ignored",
			hdr: CacheHeader{
				ImagesOffsetOld:  0x1c0,
				ImagesCountOld:   0x599,
				ImagesTextOffset: 0xb4e0,
				ImagesTextCount:  0x599,
			},
			want: "ImagesText Info:              44KB, offset:  0x00000B4E0 -> 0x000016800\n",
		},
		{
			name: "no images text",
			hdr: CacheHeader{
				ImagesOffset: 0x228,
				ImagesCount:  1,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid := mtypes.UUID{1}
			f := &File{UUID: uuid, Headers: map[mtypes.UUID]CacheHeader{uuid: tt.hdr}}
			if got := f.getImagesTextInfo(uuid); got != tt.want {
				t.Errorf("getImagesTextInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}
