package dyld

import (
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestSwiftOptimizationReadersRejectAbsentFields(t *testing.T) {
	uuid := types.UUID{1}
	f := &File{UUID: uuid, IsDyld4: true, Headers: map[types.UUID]CacheHeader{
		uuid: {MappingOffset: 0x140, SwiftOptsOffset: 0x5000, SwiftOptsSize: 0x1000},
	}}
	for _, tc := range []struct {
		name string
		read func() (*SwiftHashTable, error)
	}{
		{"type", f.getSwiftTypeHashTable},
		{"metadata", f.getSwiftMetadataTable},
		{"foreign type", f.getSwiftForeignTypeHashTable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if table, err := tc.read(); table != nil || err == nil || err.Error() != "no swift optimization header" {
				t.Fatalf("absent Swift opts = %v, %v", table, err)
			}
		})
	}
}
