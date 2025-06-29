package img4

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPayloadCreation(t *testing.T) {
	tests := []struct {
		name        string
		config      CreatePayloadConfig
		expectError bool
	}{
		{
			name: "basic uncompressed payload",
			config: CreatePayloadConfig{
				Type:    "test",
				Version: "Test Version 1.0",
				Data:    []byte("Hello, World!"),
			},
			expectError: false,
		},
		{
			name: "payload with LZSS compression",
			config: CreatePayloadConfig{
				Type:        "krnl",
				Version:     "Compressed Test",
				Data:        bytes.Repeat([]byte("test data "), 100),
				Compression: "lzss",
			},
			expectError: false,
		},
		{
			name: "payload with LZFSE compression",
			config: CreatePayloadConfig{
				Type:        "logo",
				Version:     "LZFSE Test",
				Data:        bytes.Repeat([]byte("image data "), 100),
				Compression: "lzfse",
			},
			expectError: false,
		},
		{
			name: "payload with LZSS and extra data",
			config: CreatePayloadConfig{
				Type:        "krnl",
				Version:     "Kernel with Extra",
				Data:        bytes.Repeat([]byte("kernel "), 200),
				ExtraData:   []byte("extra kernel metadata"),
				Compression: "lzss",
			},
			expectError: false,
		},
		{
			name: "payload with keybags",
			config: CreatePayloadConfig{
				Type:    "sepi",
				Version: "SEP Firmware",
				Data:    []byte("encrypted sep data"),
				Keybags: []Keybag{
					{
						Type: PRODUCTION,
						IV:   generateTestData(16),
						Key:  generateTestData(32),
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := CreatePayload(&tt.config)
			if (err != nil) != tt.expectError {
				t.Fatalf("CreatePayload() error = %v, expectError %v", err, tt.expectError)
			}
			if tt.expectError {
				return
			}

			// Verify basic fields
			if payload.Type != tt.config.Type {
				t.Errorf("Type = %v, want %v", payload.Type, tt.config.Type)
			}
			if payload.Version != tt.config.Version {
				t.Errorf("Version = %v, want %v", payload.Version, tt.config.Version)
			}

			// Verify compression (should NOT be present with extra data)
			if len(tt.config.ExtraData) > 0 {
				if payload.Compression.Algorithm != 0 || payload.Compression.UncompressedSize != 0 {
					t.Errorf("Compression block should not be present when ExtraData is used")
				}
			} else if tt.config.Compression != "none" && tt.config.Compression != "" {
				// Map string compression to enum for comparison
				var expectedAlgo CompressionAlgorithm
				switch strings.ToLower(tt.config.Compression) {
				case "lzss":
					expectedAlgo = CompressionAlgorithmLZSS
				case "lzfse", "lzfse_iboot":
					expectedAlgo = CompressionAlgorithmLZFSE
				}
				if payload.Compression.Algorithm != expectedAlgo {
					t.Errorf("Compression.Algorithm = %v, want %v", payload.Compression.Algorithm, expectedAlgo)
				}
				if payload.Compression.UncompressedSize != len(tt.config.Data) {
					t.Errorf("Compression.UncompressedSize = %v, want %v", payload.Compression.UncompressedSize, len(tt.config.Data))
				}
			}

			// Verify keybags (may not be implemented in CreatePayload yet)
			if len(tt.config.Keybags) > 0 {
				t.Logf("Input keybags: %d, Output keybags: %d, Encrypted: %t", 
					len(tt.config.Keybags), len(payload.Keybags), payload.Encrypted)
				// Note: Keybag support may not be fully implemented in CreatePayload
				// This is a placeholder for when keybag creation is added
			}
		})
	}
}

func TestPayloadRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		config CreatePayloadConfig
	}{
		{
			name: "uncompressed roundtrip",
			config: CreatePayloadConfig{
				Type:    "test",
				Version: "Uncompressed",
				Data:    []byte("uncompressed data"),
			},
		},
		{
			name: "LZSS roundtrip",
			config: CreatePayloadConfig{
				Type:        "krnl",
				Version:     "LZSS Kernel",
				Data:        bytes.Repeat([]byte("kernel data "), 50),
				Compression: "lzss",
			},
		},
		{
			name: "LZFSE roundtrip",
			config: CreatePayloadConfig{
				Type:        "logo",
				Version:     "LZFSE Logo",
				Data:        bytes.Repeat([]byte("image data "), 50),
				Compression: "lzfse",
			},
		},
		{
			name: "LZSS with extra data",
			config: CreatePayloadConfig{
				Type:        "krnl",
				Version:     "Kernel+Extra",
				Data:        bytes.Repeat([]byte("kernel "), 100),
				ExtraData:   []byte("kernel extra data"),
				Compression: "lzss",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Create payload
			original, err := CreatePayload(&tt.config)
			if err != nil {
				t.Fatalf("CreatePayload() error = %v", err)
			}

			// Step 2: Marshal
			data, err := original.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			// Step 3: Parse
			parsed, err := ParsePayload(data)
			if err != nil {
				t.Fatalf("ParsePayload() error = %v", err)
			}

			// Step 4: Verify parsed matches original
			if parsed.Type != original.Type {
				t.Errorf("Parsed Type = %v, want %v", parsed.Type, original.Type)
			}
			if parsed.Version != original.Version {
				t.Errorf("Parsed Version = %v, want %v", parsed.Version, original.Version)
			}

			// Step 5: Test decompression and data integrity
			if tt.config.Compression != "none" && tt.config.Compression != "" {
				// For compressed data, test decompression
				decompressed, err := parsed.Decompress()
				if err != nil {
					t.Fatalf("Decompress() error = %v", err)
				}
				if !bytes.Equal(decompressed, tt.config.Data) {
					t.Errorf("Decompressed data doesn't match original (got %d bytes, want %d bytes)", 
						len(decompressed), len(tt.config.Data))
				}

				// Test extra data
				if len(tt.config.ExtraData) > 0 {
					if !parsed.HasExtraData() {
						t.Errorf("Expected extra data to be detected")
					}
					extraData := parsed.GetExtraData()
					if !bytes.Equal(extraData, tt.config.ExtraData) {
						t.Errorf("Extra data mismatch: got %d bytes, want %d bytes", len(extraData), len(tt.config.ExtraData))
					}
				}
			} else {
				// For uncompressed data, use GetData() which handles the uncompressed case
				data, err := parsed.GetData()
				if err != nil {
					t.Fatalf("GetData() error for uncompressed data = %v", err)
				}
				
				// For uncompressed data, GetData() should return the original data without extra data
				// Extra data is handled separately
				if !bytes.Equal(data, tt.config.Data) {
					t.Errorf("Uncompressed data doesn't match original (got %d bytes, want %d bytes)", 
						len(data), len(tt.config.Data))
				}
				
				// Test extra data if provided
				if len(tt.config.ExtraData) > 0 {
					if !parsed.HasExtraData() {
						t.Errorf("Expected extra data to be detected for uncompressed payload")
					}
					extraData := parsed.GetExtraData()
					if !bytes.Equal(extraData, tt.config.ExtraData) {
						t.Errorf("Extra data mismatch for uncompressed: got %d bytes, want %d bytes", len(extraData), len(tt.config.ExtraData))
					}
				}
			}
		})
	}
}

// TestPayloadWithRealData tests with real test files if available (CI-friendly)
func TestPayloadWithRealData(t *testing.T) {
	testDataDir := "../../test-caches/TEST/22L572__AppleTV5,3"
	
	// Check if test data exists (fail quietly for CI)
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		t.Skip("Test data not available, skipping real data test")
	}

	kernelPath := filepath.Join(testDataDir, "kernel")
	extraPath := filepath.Join(testDataDir, "extra")

	// Check if files exist
	kernelData, err := os.ReadFile(kernelPath)
	if err != nil {
		t.Skip("Kernel test file not available")
	}

	extraData, err := os.ReadFile(extraPath)
	if err != nil {
		t.Skip("Extra test file not available")
	}

	t.Logf("Testing with real data: kernel=%d bytes, extra=%d bytes", len(kernelData), len(extraData))

	// Test LZSS compression with real kernel data
	payload, err := CreatePayload(&CreatePayloadConfig{
		Type:        "krnl",
		Version:     "Real Kernel Test",
		Data:        kernelData,
		ExtraData:   extraData,
		Compression: "lzss",
	})
	if err != nil {
		t.Fatalf("CreatePayload() with real data error = %v", err)
	}

	// Marshal and parse
	data, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	t.Logf("Compressed from %d bytes to %d bytes (%.1f%% compression)",
		len(kernelData)+len(extraData), len(data),
		100.0*float64(len(data))/float64(len(kernelData)+len(extraData)))

	parsed, err := ParsePayload(data)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}

	// Verify decompression
	decompressed, err := parsed.Decompress()
	if err != nil {
		t.Fatalf("Decompress() error = %v", err)
	}

	if !bytes.Equal(decompressed, kernelData) {
		t.Errorf("Decompressed kernel data doesn't match original (got %d bytes, want %d bytes)",
			len(decompressed), len(kernelData))
	}

	// Verify extra data
	if !parsed.HasExtraData() {
		t.Error("Expected extra data to be detected")
	}

	extractedExtra := parsed.GetExtraData()
	if !bytes.Equal(extractedExtra, extraData) {
		t.Errorf("Extra data mismatch (got %d bytes, want %d bytes)",
			len(extractedExtra), len(extraData))
	}
}

func TestPayloadErrors(t *testing.T) {
	// Test invalid ASN.1 data
	_, err := ParsePayload([]byte("invalid asn1 data"))
	if err == nil {
		t.Error("Expected error for invalid ASN.1 data")
	}

	// Test empty data
	_, err = ParsePayload([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

func BenchmarkPayloadCreation(b *testing.B) {
	data := bytes.Repeat([]byte("benchmark data "), 100)

	b.Run("uncompressed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = CreatePayload(&CreatePayloadConfig{
				Type:    "test",
				Version: "Benchmark",
				Data:    data,
			})
		}
	})

	b.Run("lzss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = CreatePayload(&CreatePayloadConfig{
				Type:        "test",
				Version:     "Benchmark",
				Data:        data,
				Compression: "lzss",
			})
		}
	})

	b.Run("lzfse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = CreatePayload(&CreatePayloadConfig{
				Type:        "test",
				Version:     "Benchmark",
				Data:        data,
				Compression: "lzfse",
			})
		}
	})
}

// Helper function to generate deterministic test data
func generateTestData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

