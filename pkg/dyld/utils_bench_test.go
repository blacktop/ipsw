package dyld

import (
	"fmt"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func BenchmarkCacheOffsets(b *testing.B) {
	const base = uint64(0x180000000)
	f := &File{
		UUID:                  types.UUID{1},
		Mappings:              make(map[types.UUID]cacheMappings),
		MappingsWithSlideInfo: make(map[types.UUID]cacheMappingsWithSlideInfo),
	}
	// Large cache families expose the cost of scanning every member
	for i := 0; i < 80; i++ {
		uuid := types.UUID{byte(i + 1)}
		addr := base + uint64(i)*0x100000
		f.Mappings[uuid] = cacheMappings{{CacheMappingInfo: CacheMappingInfo{Address: addr, Size: 0x100000}}}
		f.MappingsWithSlideInfo[uuid] = cacheMappingsWithSlideInfo{{
			CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{Address: addr, Size: 0x100000},
		}}
		if i > 0 {
			f.SubCacheInfo = append(f.SubCacheInfo, SubcacheEntry{UUID: uuid, CacheVMOffset: addr - base})
		}
	}
	for _, op := range []string{"VM", "File"} {
		for _, member := range []int{0, 1, 40, 79} {
			b.Run(fmt.Sprintf("%s/member%d", op, member), func(b *testing.B) {
				offset := uint64(member)*0x100000 + 0x1234
				wantUUID := types.UUID{byte(member + 1)}
				want := base + offset
				if op == "File" {
					want = 0x1234
				}
				b.ReportAllocs()
				for b.Loop() {
					var uuid types.UUID
					var got uint64
					var err error
					if op == "VM" {
						uuid, got, err = f.GetCacheVMAddress(offset)
					} else {
						uuid, got, err = f.GetCacheOffset(offset)
					}
					if err != nil || uuid != wantUUID || got != want {
						b.Fatalf("offset %#x = %s, %#x, %v; want %s, %#x, nil", offset, uuid, got, err, wantUUID, want)
					}
				}
			})
		}
	}
}
