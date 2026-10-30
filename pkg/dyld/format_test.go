package dyld

import (
	"testing"

	"github.com/blacktop/go-macho/types"
)

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
