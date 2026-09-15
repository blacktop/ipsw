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

// TestSortDevicesReverseInsertionOrder pins that the order SortDevices returns
// does not depend on the order it was handed. The Less key gained the variant
// suffix, and two names differing only in that suffix compared equal before, so
// their relative order was whatever sort.Sort happened to leave behind.
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

// TestDevicesLessIsAStrictOrdering pins that the new sort key is a strict weak
// ordering over names that differ only in their variant suffix: exactly one of
// Less(i,j) / Less(j,i) holds, and neither holds for a device against itself.
// On base both directions were false for every such pair, which is what made
// the order of two variants of one model arbitrary.
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

// TestDeconstructDeviceRoundTripsEveryRealProductType is the corpus check: every
// product type Apple ships that DeconstructDevice claims to parse must survive
// String(), because SortDevices rebuilds every name it is handed from the parsed
// struct. The variant-suffixed entries here are the ones that came back "0,0".
func TestDeconstructDeviceRoundTripsEveryRealProductType(t *testing.T) {
	// A sample of the variant-suffixed product types the embedded Xcode
	// device_traits DB ships, alongside plain ones for contrast.
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
