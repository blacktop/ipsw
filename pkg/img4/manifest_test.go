package img4

import (
	"bytes"
	"testing"
)

func TestManifestParsing(t *testing.T) {
	// Test with minimal valid manifest data
	testManifestData := createTestManifestData(t)

	manifest, err := ParseManifest(testManifestData)
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}

	if manifest.Tag != "IM4M" {
		t.Errorf("Expected tag 'IM4M', got '%s'", manifest.Tag)
	}

	// Test error cases
	errorTests := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"invalid ASN.1", []byte("not asn1 data")},
		{"short data", []byte{0x30, 0x01}},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseManifest(tt.data)
			if err == nil {
				t.Errorf("Expected error for %s", tt.name)
			}
		})
	}
}

func TestManifestMarshal(t *testing.T) {
	// Create test manifest data
	testData := createTestManifestData(t)

	manifest, err := ParseManifest(testData)
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}

	// Test marshal
	data, err := manifest.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty marshaled data")
	}

	// Test roundtrip
	parsed, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("Roundtrip ParseManifest() error = %v", err)
	}

	if parsed.Tag != manifest.Tag {
		t.Errorf("Roundtrip Tag = %v, want %v", parsed.Tag, manifest.Tag)
	}
}

func TestManifestString(t *testing.T) {
	manifest, err := ParseManifest(createTestManifestData(t))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}

	str := manifest.String()
	if str == "" {
		t.Error("Expected non-empty string representation")
	}

	// Check that it contains expected components
	if !bytes.Contains([]byte(str), []byte("IM4M")) {
		t.Error("Expected string to contain 'IM4M'")
	}
}

func BenchmarkManifestParsing(b *testing.B) {
	testData := createTestManifestData(b)

	b.ResetTimer()
	for range b.N {
		_, _ = ParseManifest(testData)
	}
}

// Helper function to create test manifest data
func createTestManifestData(t testing.TB) []byte {
	// Create a manifest with a few properties programmatically
	manifest := Manifest{
		IM4M: IM4M{
			Tag:     "IM4M",
			Version: 1,
		},
		ManifestBody: ManifestBody{
			Properties: []Property{
				{Name: "CHIP", Value: 0x8010},
				{Name: "BORD", Value: 0x01},
				{Name: "ECID", Value: uint64(0x1234567890ABCDEF)},
				{Name: "CPRO", Value: true},
			},
		},
	}

	data, err := manifest.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal manifest: %v", err)
	}

	return data
}
