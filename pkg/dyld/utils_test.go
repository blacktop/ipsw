package dyld

import (
	"math"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestCacheOffsets(t *testing.T) {
	const base = uint64(0x180000000)
	primary, subcache, symbols := types.UUID{1}, types.UUID{2}, types.UUID{3}
	f := &File{
		UUID:    primary,
		symUUID: symbols,
		Mappings: map[types.UUID]cacheMappings{
			primary: {
				{CacheMappingInfo: CacheMappingInfo{Address: base, Size: 0x1000}},
				{CacheMappingInfo: CacheMappingInfo{Address: base + 0x3000, Size: 0x1000, FileOffset: 0x1000}},
			},
			symbols: {{CacheMappingInfo: CacheMappingInfo{Address: base + 0xa000, Size: 0x1000}}},
		},
	}

	check := func(t *testing.T, offset uint64, wantUUID types.UUID, wantFileOffset uint64, wantErr bool) {
		t.Helper()
		uuid, address, err := f.GetCacheVMAddress(offset)
		if wantErr {
			if err == nil {
				t.Fatalf("GetCacheVMAddress(%#x) = %s, %#x; expected error", offset, uuid, address)
			}
		} else if err != nil || uuid != wantUUID || address != base+offset {
			t.Fatalf("GetCacheVMAddress(%#x) = %s, %#x, %v; want %s, %#x", offset, uuid, address, err, wantUUID, base+offset)
		}
		uuid, fileOffset, err := f.GetCacheOffset(offset)
		if wantErr {
			if err == nil {
				t.Fatalf("GetCacheOffset(%#x) = %s, %#x; expected error", offset, uuid, fileOffset)
			}
		} else if err != nil || uuid != wantUUID || fileOffset != wantFileOffset {
			t.Fatalf("GetCacheOffset(%#x) = %s, %#x, %v; want %s, %#x", offset, uuid, fileOffset, err, wantUUID, wantFileOffset)
		}
	}

	t.Run("no subcaches", func(t *testing.T) {
		check(t, 0, primary, 0, false)
		check(t, 0xfff, primary, 0xfff, false)
		check(t, 0x3123, primary, 0x1123, false)
		check(t, 0x1000, types.UUID{}, 0, true)
		check(t, 0x4000, types.UUID{}, 0, true)
		check(t, 0xa000, types.UUID{}, 0, true)
		check(t, math.MaxUint64, types.UUID{}, 0, true)
		// An overflowing addition must not wrap into an otherwise valid mapping
		f.Mappings[types.UUID{4}] = cacheMappings{{CacheMappingInfo: CacheMappingInfo{Address: 0, Size: 0x1000}}}
		check(t, math.MaxUint64-base+1, types.UUID{}, 0, true)
	})

	f.SubCacheInfo = []SubcacheEntry{{UUID: subcache, CacheVMOffset: 0x6000}}
	f.Mappings[subcache] = cacheMappings{
		{CacheMappingInfo: CacheMappingInfo{Address: base + 0x6000, Size: 0x1000}},
		{CacheMappingInfo: CacheMappingInfo{Address: base + 0x8000, Size: 0x1000, FileOffset: 0x1000}},
	}
	t.Run("split cache", func(t *testing.T) {
		check(t, 0x3123, primary, 0x1123, false)
		check(t, 0x6000, subcache, 0, false)
		check(t, 0x8123, subcache, 0x1123, false)
		check(t, 0x7000, types.UUID{}, 0, true)
		check(t, 0x9000, types.UUID{}, 0, true)
	})
	t.Run("mapping outside subcache offset interval", func(t *testing.T) {
		f.Mappings[primary] = append(f.Mappings[primary], &CacheMapping{
			CacheMappingInfo: CacheMappingInfo{Address: base + 0xb000, Size: 0x1000, FileOffset: 0x2000},
		})
		check(t, 0xb123, primary, 0x2123, false)
	})
	t.Run("unordered subcache offsets", func(t *testing.T) {
		other := types.UUID{5}
		f.Mappings[other] = cacheMappings{{CacheMappingInfo: CacheMappingInfo{
			Address: base + 0xc000, Size: 0x1000,
		}}}
		f.SubCacheInfo = append([]SubcacheEntry{{UUID: other, CacheVMOffset: 0xc000}}, f.SubCacheInfo...)
		check(t, 0x8123, subcache, 0x1123, false)
		check(t, 0xc123, other, 0x123, false)
	})

	delete(f.Mappings, primary)
	t.Run("missing primary mappings", func(t *testing.T) {
		check(t, 0, types.UUID{}, 0, true)
	})
}
