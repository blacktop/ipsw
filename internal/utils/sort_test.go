package utils

import (
	"slices"
	"testing"
)

func TestSortDevicesPreservesVariantSuffix(t *testing.T) {
	tests := []struct {
		name    string
		devices []string
		want    []string
	}{
		{
			name:    "variant suffixes survive the round trip",
			devices: []string{"iPad16,4-B", "iPad16,3-A", "iPad16,4-A"},
			want:    []string{"iPad16,3-A", "iPad16,4-A", "iPad16,4-B"},
		},
		{
			name:    "variant and plain product types sort together",
			devices: []string{"iPhone12,1", "iPad16,4-A", "iPad16,4"},
			want:    []string{"iPad16,4", "iPad16,4-A", "iPhone12,1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SortDevices(tt.devices)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("SortDevices(%v) = %#v, want %#v", tt.devices, got, tt.want)
			}
		})
	}
}
