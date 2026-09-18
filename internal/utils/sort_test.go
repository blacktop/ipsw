package utils

import (
	"slices"
	"testing"
)

// TestDeconstructDeviceVariantSuffix pins that a product type's variant suffix
// ("iPad16,4-A") parses and round-trips through String(), which is how
// SortDevices rebuilds every name it is handed.
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

// TestSortDevicesPreservesVariantSuffix pins that variant-suffixed product
// types survive SortDevices with their suffix.
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

// TestSortDevicesUnparsableNamesUnchanged pins that a name that is not a
// product type collapses to the zero Device.
func TestSortDevicesUnparsableNamesUnchanged(t *testing.T) {
	got := SortDevices([]string{"n66ap", "UniversalMac"})
	want := []string{"0,0", "0,0"}
	if !slices.Equal(got, want) {
		t.Fatalf("SortDevices() = %#v, want %#v", got, want)
	}
}

// TestSortDevicesReverseInsertionOrder pins that the order SortDevices returns
// does not depend on the order it was handed, variant suffixes included.
func TestSortDevicesReverseInsertionOrder(t *testing.T) {
	want := []string{"iPad16,4", "iPad16,4-A", "iPad16,4-B", "iPhone12,1"}

	forward := SortDevices([]string{"iPad16,4", "iPad16,4-A", "iPad16,4-B", "iPhone12,1"})
	if !slices.Equal(forward, want) {
		t.Fatalf("SortDevices(forward) = %#v, want %#v", forward, want)
	}

	reverse := SortDevices([]string{"iPhone12,1", "iPad16,4-B", "iPad16,4-A", "iPad16,4"})
	if !slices.Equal(reverse, want) {
		t.Fatalf("SortDevices(reverse) = %#v, want %#v", reverse, want)
	}
}

// TestDevicesLessIsAStrictOrdering pins that the sort key is a strict weak
// ordering over names that differ only in their variant suffix: exactly one of
// Less(i,j) / Less(j,i) holds, and neither holds for a device against itself.
func TestDevicesLessIsAStrictOrdering(t *testing.T) {
	a := DeconstructDevice("iPad16,4-A")
	b := DeconstructDevice("iPad16,4-B")
	devs := Devices{a, b}

	if !devs.Less(0, 1) {
		t.Errorf("Less(iPad16,4-A, iPad16,4-B) = false, want true")
	}
	if devs.Less(1, 0) {
		t.Errorf("Less(iPad16,4-B, iPad16,4-A) = true, want false")
	}

	self := Devices{a, a}
	if self.Less(0, 1) || self.Less(1, 0) {
		t.Errorf("Less() reported an ordering between a device and itself")
	}
}

// TestDeconstructDeviceRoundTripsSampleProductTypes pins that a representative
// sample of shipped product types, variant-suffixed and plain, survive String().
func TestDeconstructDeviceRoundTripsSampleProductTypes(t *testing.T) {
	products := []string{
		"iPad14,3-A", "iPad14,3-B", "iPad14,6-A", "iPad14,6-B",
		"iPad16,3-A", "iPad16,4-A", "iPad16,4-B", "iPad17,1-A", "iPad17,2-B",
		"iPad14,6", "iPhone12,1", "iPhone17,1", "Mac16,8", "AppleTV11,1", "Watch7,1",
	}

	for _, p := range products {
		if got := DeconstructDevice(p).String(); got != p {
			t.Errorf("DeconstructDevice(%q).String() = %q, want %q (name does not round trip)", p, got, p)
		}
	}
}
