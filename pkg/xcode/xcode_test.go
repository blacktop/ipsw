package xcode

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestByProductTypeSortsVariantSuffixedProductTypes covers the second
// utils.DeconstructDevice caller. ByProductType.Less builds its sort key from
// the parsed Family/Major/Minor, so before the suffix was parsed every
// variant-suffixed product type collapsed to the zero Device and sorted as
// "0000" — ahead of every real device, whatever its family.
func TestByProductTypeSortsVariantSuffixedProductTypes(t *testing.T) {
	tests := []struct {
		name     string
		products []string
		want     []string
	}{
		{
			name:     "variant suffixed product type sorts by its real family",
			products: []string{"iPhone12,1", "iPad16,4-A", "iPad14,6"},
			want:     []string{"iPad14,6", "iPad16,4-A", "iPhone12,1"},
		},
		{
			name:     "reverse insertion order gives the same result",
			products: []string{"iPad14,6", "iPad16,4-A", "iPhone12,1"},
			want:     []string{"iPad14,6", "iPad16,4-A", "iPhone12,1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devices := make([]Device, 0, len(tt.products))
			for _, p := range tt.products {
				devices = append(devices, Device{ProductType: p})
			}

			sort.Sort(ByProductType{Devices: devices})

			got := make([]string, 0, len(devices))
			for _, d := range devices {
				got = append(got, d.ProductType)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("sort.Sort(ByProductType) = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestByProductTypeSortsEmbeddedDeviceList runs the real corpus `ipsw
// device-list` sorts: the embedded Xcode device_traits DB, which ships 24
// variant-suffixed product types. Before the suffix was parsed all of them
// deconstructed to the zero Device and sorted as "0000", so every one of them
// was hoisted to the front of the list ahead of AppleTV.
func TestByProductTypeSortsEmbeddedDeviceList(t *testing.T) {
	devices, err := GetDevices()
	if err != nil {
		t.Fatalf("GetDevices() error = %v", err)
	}

	var variants int
	for _, d := range devices {
		if _, suffix, found := strings.Cut(d.ProductType, "-"); found && len(suffix) > 0 {
			variants++
		}
	}
	if variants == 0 {
		t.Fatal("expected the embedded device_traits DB to ship variant-suffixed product types, found none")
	}

	sort.Sort(ByProductType{Devices: devices})

	// The first device out of the sort must be a real one, not a variant-suffixed
	// product type that lost its identity on the way through DeconstructDevice.
	var first string
	for _, d := range devices {
		if d.ProductType != "" {
			first = d.ProductType
			break
		}
	}
	if strings.Contains(first, "-") {
		t.Errorf("sorted device list starts with the variant-suffixed %q; variant product types are sorting as the zero Device", first)
	}
	if !strings.HasPrefix(first, "AppleTV") {
		t.Errorf("sorted device list starts with %q, want the first AppleTV product type", first)
	}
}

// TestByProductTypeSameModelVariantsStillTie (control) pins a limitation this
// change does NOT remove, so it is not mistaken for one that was fixed.
// ByProductType.Less builds its own key from Family/Major/Minor only — it never
// reads Device.Variant — so two variants of one model still compare equal and
// keep their input order. Green on both sides of the fix: the pair enters the
// widened DeconstructDevice and comes back out with the same ordering. Fixing
// it means changing xcode.go's key, which is a separate change.
func TestByProductTypeSameModelVariantsStillTie(t *testing.T) {
	devices := []Device{{ProductType: "iPad16,4-B"}, {ProductType: "iPad16,4-A"}}
	d := ByProductType{Devices: devices}

	if d.Less(0, 1) || d.Less(1, 0) {
		t.Errorf("ByProductType.Less() now orders two variants of one model; xcode.go's sort key gained a variant term")
	}
}
