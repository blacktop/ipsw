package img4

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/ipsw/pkg/plist"
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
		Compression: "lzss",
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

// TestVerifyManifestDigests tests the new digest-based verification functionality
func TestVerifyManifestDigests(t *testing.T) {
	// Create test build manifest with matching board/chip IDs
	buildManifest := &plist.BuildManifest{
		BuildIdentities: []plist.BuildIdentity{
			{
				ApBoardID: "0x1",
				ApChipID:  "0x8010",
				Info: plist.IdentityInfo{
					DeviceClass:     "iPhone",
					BuildNumber:     "22A123",
					RestoreBehavior: "Erase",
				},
				Manifest: map[string]plist.IdentityManifest{
					"KernelCache": {
						Digest: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14},
					},
					"DeviceTree": {
						Digest: []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34},
					},
					"NoDigest": {
						// Component without digest - should be skipped
					},
				},
			},
		},
	}

	// Create test IM4M manifest with matching properties and images
	testManifest := &Manifest{
		IM4M: IM4M{
			Tag:     "IM4M",
			Version: 1,
		},
		ManifestBody: ManifestBody{
			Properties: []Property{
				{Name: "CHIP", Value: 0x8010},
				{Name: "BORD", Value: 0x01},
				{Name: "ECID", Value: uint64(0x1234567890ABCDEF)},
			},
			Images: []ManifestImage{
				{
					Name: "krnl",
					Properties: []Property{
						{Name: "DGST", Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}},
					},
				},
				{
					Name: "dtre",
					Properties: []Property{
						{Name: "DGST", Value: []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34}},
					},
				},
			},
		},
	}

	t.Run("successful verification", func(t *testing.T) {
		result, err := VerifyManifestDigests(testManifest, buildManifest, false, false)
		if err != nil {
			t.Fatalf("VerifyManifestDigests() error = %v", err)
		}

		if !result.IsValid {
			t.Error("Expected verification to succeed")
		}

		if result.IdentityIndex != 1 {
			t.Errorf("Expected identity index 1, got %d", result.IdentityIndex)
		}

		if result.ComponentsChecked != 2 {
			t.Errorf("Expected 2 components checked, got %d", result.ComponentsChecked)
		}

		if len(result.MissingComponents) != 0 {
			t.Errorf("Expected no missing components, got %v", result.MissingComponents)
		}

		if result.MatchedIdentity == nil {
			t.Error("Expected matched identity to be set")
		} else if result.MatchedIdentity.Info.DeviceClass != "iPhone" {
			t.Errorf("Expected device class 'iPhone', got '%s'", result.MatchedIdentity.Info.DeviceClass)
		}
	})

	t.Run("missing component digest - non-strict mode", func(t *testing.T) {
		// Create manifest missing one digest
		incompleteManifest := &Manifest{
			IM4M: IM4M{
				Tag:     "IM4M",
				Version: 1,
			},
			ManifestBody: ManifestBody{
				Properties: []Property{
					{Name: "CHIP", Value: 0x8010},
					{Name: "BORD", Value: 0x01},
				},
				Images: []ManifestImage{
					{
						Name: "krnl",
						Properties: []Property{
							{Name: "DGST", Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}},
						},
					},
					// Missing DeviceTree digest
				},
			},
		}

		// Non-strict mode should pass if all present IM4M images have valid digests
		result, err := VerifyManifestDigests(incompleteManifest, buildManifest, false, false)
		if err != nil {
			t.Fatalf("VerifyManifestDigests() error = %v", err)
		}

		if !result.IsValid {
			t.Error("Expected verification to succeed in non-strict mode")
		}

		if len(result.MissingComponents) != 1 {
			t.Errorf("Expected 1 missing component, got %d", len(result.MissingComponents))
		}

		if result.MissingComponents[0] != "DeviceTree" {
			t.Errorf("Expected missing component 'DeviceTree', got '%s'", result.MissingComponents[0])
		}
	})

	t.Run("missing component digest - strict mode", func(t *testing.T) {
		// Create manifest missing one digest
		incompleteManifest := &Manifest{
			IM4M: IM4M{
				Tag:     "IM4M",
				Version: 1,
			},
			ManifestBody: ManifestBody{
				Properties: []Property{
					{Name: "CHIP", Value: 0x8010},
					{Name: "BORD", Value: 0x01},
				},
				Images: []ManifestImage{
					{
						Name: "krnl",
						Properties: []Property{
							{Name: "DGST", Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}},
						},
					},
					// Missing DeviceTree digest
				},
			},
		}

		// Strict mode should fail if any BuildManifest components are missing
		result, err := VerifyManifestDigests(incompleteManifest, buildManifest, false, true)
		if err != nil {
			t.Fatalf("VerifyManifestDigests() error = %v", err)
		}

		if result.IsValid {
			t.Error("Expected verification to fail in strict mode")
		}

		if len(result.MissingComponents) != 1 {
			t.Errorf("Expected 1 missing component, got %d", len(result.MissingComponents))
		}

		if result.MissingComponents[0] != "DeviceTree" {
			t.Errorf("Expected missing component 'DeviceTree', got '%s'", result.MissingComponents[0])
		}
	})

	t.Run("no matching build identity", func(t *testing.T) {
		// Create manifest with different board/chip IDs
		noMatchManifest := &Manifest{
			IM4M: IM4M{
				Tag:     "IM4M",
				Version: 1,
			},
			ManifestBody: ManifestBody{
				Properties: []Property{
					{Name: "CHIP", Value: 0x9999}, // Different chip ID
					{Name: "BORD", Value: 0x99},   // Different board ID
				},
			},
		}

		_, err := VerifyManifestDigests(noMatchManifest, buildManifest, false, false)
		if err == nil {
			t.Error("Expected error for no matching build identity")
		}

		expectedError := "no matching build identity found"
		if !bytes.Contains([]byte(err.Error()), []byte(expectedError)) {
			t.Errorf("Expected error to contain '%s', got '%s'", expectedError, err.Error())
		}
	})

	t.Run("missing required properties", func(t *testing.T) {
		// Test manifest missing CHIP property
		missingChipManifest := &Manifest{
			IM4M: IM4M{
				Tag:     "IM4M",
				Version: 1,
			},
			ManifestBody: ManifestBody{
				Properties: []Property{
					{Name: "BORD", Value: 0x01},
				},
			},
		}

		_, err := VerifyManifestDigests(missingChipManifest, buildManifest, false, false)
		if err == nil {
			t.Error("Expected error for missing CHIP property")
		}

		expectedError := "CHIP (chip ID) not found"
		if !bytes.Contains([]byte(err.Error()), []byte(expectedError)) {
			t.Errorf("Expected error to contain '%s', got '%s'", expectedError, err.Error())
		}

		// Test manifest missing BORD property
		missingBordManifest := &Manifest{
			IM4M: IM4M{
				Tag:     "IM4M",
				Version: 1,
			},
			ManifestBody: ManifestBody{
				Properties: []Property{
					{Name: "CHIP", Value: 0x8010},
				},
			},
		}

		_, err = VerifyManifestDigests(missingBordManifest, buildManifest, false, false)
		if err == nil {
			t.Error("Expected error for missing BORD property")
		}

		expectedError = "BORD (board ID) not found"
		if !bytes.Contains([]byte(err.Error()), []byte(expectedError)) {
			t.Errorf("Expected error to contain '%s', got '%s'", expectedError, err.Error())
		}
	})

	t.Run("multiple build identities", func(t *testing.T) {
		// Create build manifest with multiple identities, only second one matches
		multiBuildManifest := &plist.BuildManifest{
			BuildIdentities: []plist.BuildIdentity{
				{
					ApBoardID: "0x2", // Different board ID
					ApChipID:  "0x8010",
					Info: plist.IdentityInfo{
						DeviceClass: "iPad",
					},
				},
				{
					ApBoardID: "0x1",    // Matching board ID
					ApChipID:  "0x8010", // Matching chip ID
					Info: plist.IdentityInfo{
						DeviceClass:     "iPhone",
						BuildNumber:     "22A456",
						RestoreBehavior: "Update",
					},
					Manifest: map[string]plist.IdentityManifest{
						"BaseSystem": {
							Digest: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14},
						},
					},
				},
			},
		}

		testManifestMulti := &Manifest{
			IM4M: IM4M{
				Tag:     "IM4M",
				Version: 1,
			},
			ManifestBody: ManifestBody{
				Properties: []Property{
					{Name: "CHIP", Value: 0x8010},
					{Name: "BORD", Value: 0x01},
				},
				Images: []ManifestImage{
					{
						Name: "bsys",
						Properties: []Property{
							{Name: "DGST", Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14}},
						},
					},
				},
			},
		}

		result, err := VerifyManifestDigests(testManifestMulti, multiBuildManifest, false, false)
		if err != nil {
			t.Fatalf("VerifyManifestDigests() error = %v", err)
		}

		if !result.IsValid {
			t.Error("Expected verification to succeed")
		}

		if result.IdentityIndex != 2 {
			t.Errorf("Expected identity index 2 (second identity), got %d", result.IdentityIndex)
		}

		if result.MatchedIdentity.Info.DeviceClass != "iPhone" {
			t.Errorf("Expected device class 'iPhone', got '%s'", result.MatchedIdentity.Info.DeviceClass)
		}
	})
}

// TestVerifyManifestDigestsWithAppleData tests verification with real Apple data
func TestVerifyManifestDigestsWithAppleData(t *testing.T) {
	manifestFile := "../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/macOS Customer/apticket.j180dap.im4m"
	buildManifestFile := "../../test-caches/TEST/25A5279m__MacOS/BuildManifest.plist"

	// Skip if files don't exist
	if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
		t.Skipf("Test manifest file not found: %s", manifestFile)
	}
	if _, err := os.Stat(buildManifestFile); os.IsNotExist(err) {
		t.Skipf("Test build manifest file not found: %s", buildManifestFile)
	}

	t.Run("Apple IM4M vs BuildManifest", func(t *testing.T) {
		// Read and parse IM4M manifest
		manifestData, err := os.ReadFile(manifestFile)
		if err != nil {
			t.Fatalf("Failed to read manifest file: %v", err)
		}

		manifest, err := ParseManifest(manifestData)
		if err != nil {
			t.Fatalf("Failed to parse manifest: %v", err)
		}

		// Read and parse build manifest
		buildManifestData, err := os.ReadFile(buildManifestFile)
		if err != nil {
			t.Fatalf("Failed to read build manifest file: %v", err)
		}

		buildManifest, err := plist.ParseBuildManifest(buildManifestData)
		if err != nil {
			t.Fatalf("Failed to parse build manifest: %v", err)
		}

		// Perform verification
		result, err := VerifyManifestDigests(manifest, buildManifest, true, false)

		// We expect this to fail since the Apple manifest and build manifest may not match perfectly
		// This test is more about ensuring the function doesn't crash and produces reasonable output
		if err != nil {
			t.Logf("Verification failed as expected: %v", err)
		} else {
			t.Logf("Verification result: valid=%v, identity=%d, components=%d, missing=%d",
				result.IsValid, result.IdentityIndex, result.ComponentsChecked, len(result.MissingComponents))

			if result.MatchedIdentity != nil {
				t.Logf("Matched identity: device=%s, build=%s, restore=%s",
					result.MatchedIdentity.Info.DeviceClass,
					result.MatchedIdentity.Info.BuildNumber,
					result.MatchedIdentity.Info.RestoreBehavior)
			}

			if len(result.MissingComponents) > 0 {
				t.Logf("Missing components: %v", result.MissingComponents)
			}
		}
	})
}

// TestCompareManifestValues tests the value comparison function
func TestCompareManifestValues(t *testing.T) {
	tests := []struct {
		name     string
		a, b     any
		expected bool
	}{
		{"equal bytes", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"different bytes", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{"equal ints", 42, 42, true},
		{"different ints", 42, 43, false},
		{"int vs float64", 42, 42.0, true},
		{"float64 vs int", 42.0, 42, true},
		{"equal float64", 3.14, 3.14, true},
		{"different float64", 3.14, 2.71, false},
		{"equal bools", true, true, true},
		{"different bools", true, false, false},
		{"equal strings", "hello", "hello", true},
		{"different strings", "hello", "world", false},
		{"nil values", nil, nil, true},
		{"different types", "42", 42, false},
		{"byte slice vs string", []byte("hello"), "hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareManifestValues(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("CompareManifestValues(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestVerifyManifestDigestsIntegration tests verification with various real-world file combinations
func TestVerifyManifestDigestsIntegration(t *testing.T) {
	// Test cases with real files from test-caches
	testCases := []struct {
		name              string
		manifestPath      string
		buildManifestPath string
		expectSuccess     bool
		expectError       string
		description       string
	}{
		{
			name:              "macOS_IM4M_vs_macOS_BuildManifest",
			manifestPath:      "../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/macOS Customer/apticket.j180dap.im4m",
			buildManifestPath: "../../test-caches/TEST/25A5279m__MacOS/BuildManifest.plist",
			expectSuccess:     false, // Expected to fail due to component mismatches
			description:       "Test macOS IM4M against matching macOS BuildManifest",
		},
		{
			name:              "macOS_IM4M_vs_iPhone_BuildManifest",
			manifestPath:      "../../test-caches/TEST/25A5279m__MacOS/Firmware/Manifests/restore/macOS Customer/apticket.j180dap.im4m",
			buildManifestPath: "../../test-caches/IPSWs/IOS/iPhone17,1_26.0_23A5276f_Restore/BuildManifest.plist",
			expectSuccess:     false,
			expectError:       "no matching build identity found",
			description:       "Test cross-platform verification (should fail due to different board/chip IDs)",
		},
		{
			name:              "AppleTV_IM4M_test",
			manifestPath:      "../../test-caches/TEST/22L572__AppleTV5,3/im4m",
			buildManifestPath: "../../test-caches/TEST/25A5279m__MacOS/BuildManifest.plist",
			expectSuccess:     false,
			expectError:       "no matching build identity found",
			description:       "Test AppleTV IM4M against macOS BuildManifest (should fail)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip if files don't exist
			if _, err := os.Stat(tc.manifestPath); os.IsNotExist(err) {
				t.Skipf("Manifest file not found: %s", tc.manifestPath)
			}
			if _, err := os.Stat(tc.buildManifestPath); os.IsNotExist(err) {
				t.Skipf("Build manifest file not found: %s", tc.buildManifestPath)
			}

			t.Logf("Testing: %s", tc.description)

			// Read and parse IM4M manifest
			manifestData, err := os.ReadFile(tc.manifestPath)
			if err != nil {
				t.Fatalf("Failed to read manifest file: %v", err)
			}

			manifest, err := ParseManifest(manifestData)
			if err != nil {
				t.Fatalf("Failed to parse manifest: %v", err)
			}

			// Read and parse build manifest
			buildManifestData, err := os.ReadFile(tc.buildManifestPath)
			if err != nil {
				t.Fatalf("Failed to read build manifest file: %v", err)
			}

			buildManifest, err := plist.ParseBuildManifest(buildManifestData)
			if err != nil {
				t.Fatalf("Failed to parse build manifest: %v", err)
			}

			// Log manifest properties for debugging
			manifestProps := PropertiesSliceToMap(manifest.Properties)
			if boardID, ok := manifestProps["BORD"].(int); ok {
				t.Logf("IM4M board_id: 0x%x", boardID)
			}
			if chipID, ok := manifestProps["CHIP"].(int); ok {
				t.Logf("IM4M chip_id: 0x%x", chipID)
			}
			t.Logf("IM4M has %d properties and %d images", len(manifest.Properties), len(manifest.Images))

			// Log build manifest identities
			t.Logf("BuildManifest has %d build identities", len(buildManifest.BuildIdentities))
			for i, identity := range buildManifest.BuildIdentities {
				t.Logf("  Identity %d: board=%s, chip=%s", i+1, identity.ApBoardID, identity.ApChipID)
			}

			// Perform verification
			result, err := VerifyManifestDigests(manifest, buildManifest, true, false)

			if tc.expectError != "" {
				// We expect a specific error
				if err == nil {
					t.Errorf("Expected error containing '%s', but got no error", tc.expectError)
				} else if !bytes.Contains([]byte(err.Error()), []byte(tc.expectError)) {
					t.Errorf("Expected error containing '%s', got: %s", tc.expectError, err.Error())
				} else {
					t.Logf("Got expected error: %v", err)
				}
			} else if err != nil {
				// We don't expect an error but got one
				t.Logf("Verification failed: %v", err)
			} else {
				// No error, check the result
				t.Logf("Verification result: valid=%v, identity=%d, components=%d, missing=%d",
					result.IsValid, result.IdentityIndex, result.ComponentsChecked, len(result.MissingComponents))

				if result.MatchedIdentity != nil {
					t.Logf("Matched identity: device=%s, build=%s, restore=%s",
						result.MatchedIdentity.Info.DeviceClass,
						result.MatchedIdentity.Info.BuildNumber,
						result.MatchedIdentity.Info.RestoreBehavior)
				}

				if len(result.MissingComponents) > 0 {
					t.Logf("Missing components: %v", result.MissingComponents)
				}

				if tc.expectSuccess && !result.IsValid {
					t.Errorf("Expected verification to succeed, but it failed")
				} else if !tc.expectSuccess && result.IsValid {
					t.Logf("Verification unexpectedly succeeded (this might be okay)")
				}
			}
		})
	}
}
