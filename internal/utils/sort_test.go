package utils

import (
	"slices"
	"testing"
)

// TestDeconstructDeviceVariantSuffix pins the variant suffix Apple ships on
// some product types ("iPad16,4-A"). DeconstructDevice().String() is how
// SortDevices rebuilds every name it is handed, so a suffix that does not
// round-trip is silently dropped from kernelcache filenames and IPSW folders.
func TestDeconstructDeviceVariantSuffix(t *testing.T) {
	tests := []struct {
		name      string
		device    string
		wantName  string
		wantFam   string
		wantMajor int
		wantMinor int
	}{
		{
			name:      "product type with variant suffix",
			device:    "iPad16,4-A",
			wantName:  "iPad16,4-A",
			wantFam:   "iPad",
			wantMajor: 16,
			wantMinor: 4,
		},
		{
			name:      "product type without variant suffix",
			device:    "iPhone12,1",
			wantName:  "iPhone12,1",
			wantFam:   "iPhone",
			wantMajor: 12,
			wantMinor: 1,
		},
		{
			name:      "multi-character variant suffix",
			device:    "iPad14,6-B2",
			wantName:  "iPad14,6-B2",
			wantFam:   "iPad",
			wantMajor: 14,
			wantMinor: 6,
		},
		{
			name:     "board config is not a product type",
			device:   "n66ap",
			wantName: "0,0",
		},
		{
			name:     "empty device name",
			device:   "",
			wantName: "0,0",
		},
		{
			name:     "trailing hyphen with no variant",
			device:   "iPad16,4-",
			wantName: "0,0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeconstructDevice(tt.device)
			if got.String() != tt.wantName {
				t.Errorf("DeconstructDevice(%q).String() = %q, want %q", tt.device, got.String(), tt.wantName)
			}
			if got.Family != tt.wantFam || got.Major != tt.wantMajor || got.Minor != tt.wantMinor {
				t.Errorf("DeconstructDevice(%q) = %s%d,%d, want %s%d,%d",
					tt.device, got.Family, got.Major, got.Minor, tt.wantFam, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

// TestSortDevicesPreservesVariantSuffix is the regression: before the variant
// suffix was parsed, every "-A"/"-B" product type fell through to the zero
// Device and came back out of SortDevices as the string "0,0".
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

// TestSortDevicesUnparsableNamesUnchanged (control) pins the pre-existing
// behaviour for names the regex never matched: they still collapse to the zero
// Device. The fix widens what parses, it does not change this fallback.
func TestSortDevicesUnparsableNamesUnchanged(t *testing.T) {
	got := SortDevices([]string{"n66ap", "UniversalMac"})
	want := []string{"0,0", "0,0"}
	if !slices.Equal(got, want) {
		t.Fatalf("SortDevices() = %#v, want %#v", got, want)
	}
}
