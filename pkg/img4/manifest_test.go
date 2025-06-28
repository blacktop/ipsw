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
func createTestManifestData(testing.TB) []byte {
	// For manifest testing, we'll create a minimal valid IM4M structure manually
	// This avoids the complex property marshaling issues while still testing the basic parsing
	
	// Create minimal IM4M ASN.1 structure
	// SEQUENCE { IA5String("IM4M"), INTEGER(1), SET { } }
	im4mData := []byte{
		0x30, 0x0f,                         // SEQUENCE (15 bytes)
		0x16, 0x04, 0x49, 0x4d, 0x34, 0x4d, // IA5String "IM4M"
		0x02, 0x01, 0x01,                   // INTEGER 1 (version)
		0x31, 0x04,                         // SET (4 bytes) - empty manifest body for testing
		0x04, 0x02, 0x00, 0x00,             // OCTET STRING (empty placeholder)
	}
	
	return im4mData
}