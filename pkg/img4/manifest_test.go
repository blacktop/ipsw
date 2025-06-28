package img4

import (
	"bytes"
	"os"
	"path/filepath"
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

// TestAppleManifestParsing tests parsing real Apple IM4M files
func TestAppleManifestParsing(t *testing.T) {
	testFiles := []string{
		"../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/cryptex1/macOS Customer/apticket.j180dap.im4m",
		"../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/macOS Customer/apticket.j180dap.im4m",
	}

	for _, testFile := range testFiles {
		t.Run(filepath.Base(filepath.Dir(testFile)), func(t *testing.T) {
			// Skip if file doesn't exist
			if _, err := os.Stat(testFile); os.IsNotExist(err) {
				t.Skipf("Test file not found: %s", testFile)
			}

			// Read the Apple IM4M file
			data, err := os.ReadFile(testFile)
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Parse the manifest
			manifest, err := ParseManifest(data)
			if err != nil {
				t.Fatalf("Failed to parse Apple manifest: %v", err)
			}

			// Verify basic structure
			if manifest.Tag != "IM4M" {
				t.Errorf("Expected tag 'IM4M', got '%s'", manifest.Tag)
			}

			// Check for expected properties
			if len(manifest.Properties) == 0 {
				t.Error("Expected manifest to have properties")
			}

			// Log some properties for debugging
			t.Logf("Manifest has %d properties", len(manifest.Properties))
			for _, prop := range manifest.Properties {
				t.Logf("  Property: %s = %v (type: %T)", prop.Name, prop.Value, prop.Value)
			}

			// Check for images
			if len(manifest.Images) > 0 {
				t.Logf("Manifest has %d images", len(manifest.Images))
				for _, img := range manifest.Images {
					t.Logf("  Image: %s with %d properties", img.Name, len(img.Properties))
					// Check if any image has DGST property
					for _, prop := range img.Properties {
						if prop.Name == "DGST" {
							t.Logf("    DGST found in image %s (type: %T)", img.Name, prop.Value)
						}
					}
				}
			}
		})
	}
}

// TestAppleManifestMarshalRoundtrip tests parsing and re-marshaling Apple IM4M files
func TestAppleManifestMarshalRoundtrip(t *testing.T) {
	testFiles := []string{
		"../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/cryptex1/macOS Customer/apticket.j180dap.im4m",
		"../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/macOS Customer/apticket.j180dap.im4m",
	}

	for _, testFile := range testFiles {
		t.Run(filepath.Base(filepath.Dir(testFile)), func(t *testing.T) {
			// Skip if file doesn't exist
			if _, err := os.Stat(testFile); os.IsNotExist(err) {
				t.Skipf("Test file not found: %s", testFile)
			}

			// Read the original Apple IM4M file
			originalData, err := os.ReadFile(testFile)
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Parse the manifest
			manifest, err := ParseManifest(originalData)
			if err != nil {
				t.Fatalf("Failed to parse Apple manifest: %v", err)
			}

			// Marshal it back
			marshaledData, err := manifest.Marshal()
			if err != nil {
				t.Fatalf("Failed to marshal manifest: %v", err)
			}

			// Parse the marshaled data again
			manifest2, err := ParseManifest(marshaledData)
			if err != nil {
				t.Fatalf("Failed to parse marshaled manifest: %v", err)
			}

			// Compare properties
			if len(manifest.Properties) != len(manifest2.Properties) {
				t.Errorf("Property count mismatch: original=%d, marshaled=%d", 
					len(manifest.Properties), len(manifest2.Properties))
			}

			// Compare images
			if len(manifest.Images) != len(manifest2.Images) {
				t.Errorf("Image count mismatch: original=%d, marshaled=%d", 
					len(manifest.Images), len(manifest2.Images))
			}

			// The manifests should be functionally equivalent even if not byte-identical
			// (due to potential ASN.1 encoding differences)
			t.Logf("Original size: %d bytes, Marshaled size: %d bytes", 
				len(originalData), len(marshaledData))
		})
	}
}

// TestAppleManifestInIMG4 tests creating and extracting IMG4 files with Apple IM4M manifests
func TestAppleManifestInIMG4(t *testing.T) {
	testFiles := []string{
		"../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/cryptex1/macOS Customer/apticket.j180dap.im4m",
		"../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/macOS Customer/apticket.j180dap.im4m",
	}

	// Create a simple test payload
	testPayload := []byte("test kernel data")
	payload, err := CreatePayload(&CreatePayloadConfig{
		Type:        "krnl",
		Version:     "1.0.0",
		Data:        testPayload,
		Compression: CompressionAlgorithmLZSS,
	})
	if err != nil {
		t.Fatalf("Failed to create test payload: %v", err)
	}

	payloadData, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal test payload: %v", err)
	}

	for _, testFile := range testFiles {
		t.Run(filepath.Base(filepath.Dir(testFile)), func(t *testing.T) {
			// Skip if file doesn't exist
			if _, err := os.Stat(testFile); os.IsNotExist(err) {
				t.Skipf("Test file not found: %s", testFile)
			}

			// Read the Apple IM4M file
			manifestData, err := os.ReadFile(testFile)
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Create IMG4 with the manifest
			img, err := Create(&CreateConfig{
				PayloadData:  payloadData,
				ManifestData: manifestData,
			})
			if err != nil {
				t.Fatalf("Failed to create IMG4: %v", err)
			}

			// Marshal the IMG4
			img4Data, err := img.Marshal()
			if err != nil {
				t.Fatalf("Failed to marshal IMG4: %v", err)
			}

			// Parse the IMG4 back
			parsedImg, err := Parse(img4Data)
			if err != nil {
				t.Fatalf("Failed to parse IMG4: %v", err)
			}

			// Verify components
			if parsedImg.Payload == nil {
				t.Error("Expected IMG4 to have payload")
			}
			if parsedImg.Manifest == nil {
				t.Error("Expected IMG4 to have manifest")
			}

			// Extract and verify the manifest
			if parsedImg.Manifest != nil {
				extractedManifestData, err := parsedImg.Manifest.Marshal()
				if err != nil {
					t.Fatalf("Failed to marshal extracted manifest: %v", err)
				}

				// Parse both original and extracted to compare
				originalManifest, err := ParseManifest(manifestData)
				if err != nil {
					t.Fatalf("Failed to parse original manifest: %v", err)
				}

				extractedManifest, err := ParseManifest(extractedManifestData)
				if err != nil {
					t.Fatalf("Failed to parse extracted manifest: %v", err)
				}

				// Compare key properties
				if originalManifest.Tag != extractedManifest.Tag {
					t.Errorf("Tag mismatch: original=%s, extracted=%s",
						originalManifest.Tag, extractedManifest.Tag)
				}

				if len(originalManifest.Properties) != len(extractedManifest.Properties) {
					t.Errorf("Property count mismatch: original=%d, extracted=%d",
						len(originalManifest.Properties), len(extractedManifest.Properties))
				}

				if len(originalManifest.Images) != len(extractedManifest.Images) {
					t.Errorf("Image count mismatch: original=%d, extracted=%d",
						len(originalManifest.Images), len(extractedManifest.Images))
				}

				t.Logf("Successfully created and extracted IMG4 with Apple manifest")
				t.Logf("Original manifest size: %d, Extracted manifest size: %d",
					len(manifestData), len(extractedManifestData))
			}
		})
	}
}
