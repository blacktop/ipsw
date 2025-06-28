package img4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRestoreInfoCreation(t *testing.T) {
	tests := []struct {
		name       string
		nonce      uint64
		properties map[string]any
	}{
		{
			name:  "simple boot nonce",
			nonce: 0x1234567890abcdef,
		},
		{
			name:  "zero nonce",
			nonce: 0x0000000000000000,
		},
		{
			name:  "max nonce",
			nonce: 0xffffffffffffffff,
		},
		{
			name:  "boot nonce with properties",
			nonce: 0xfedcba0987654321,
			properties: map[string]any{
				"TEST": "test value",
				"NUM":  42,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var restoreInfo *RestoreInfo

			if tt.properties != nil {
				props := make(map[string]any)
				props["BNCN"] = tt.nonce
				for k, v := range tt.properties {
					props[k] = v
				}
				restoreInfo = New(props)
			} else {
				restoreInfo = NewWithBootNonce(tt.nonce)
			}

			if restoreInfo == nil {
				t.Fatal("Expected RestoreInfo but got nil")
			}

			if restoreInfo.Tag != "IM4R" {
				t.Errorf("Expected tag 'IM4R', got '%s'", restoreInfo.Tag)
			}

			// Check boot nonce
			bootNonce, hasNonce := restoreInfo.BootNonce()
			if !hasNonce {
				t.Error("Expected boot nonce to be present")
			} else if bootNonce != tt.nonce {
				t.Errorf("Expected nonce 0x%x, got 0x%x", tt.nonce, bootNonce)
			}
		})
	}
}

func TestRestoreInfoParsing(t *testing.T) {
	// Create test IM4R data
	testNonce := uint64(0x1234567890abcdef)
	restoreInfo := NewWithBootNonce(testNonce)

	// Marshal to bytes
	data, err := restoreInfo.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Parse back
	parsed, err := ParseRestoreInfo(data)
	if err != nil {
		t.Fatalf("ParseRestoreInfo() error = %v", err)
	}

	if parsed.Tag != "IM4R" {
		t.Errorf("Expected tag 'IM4R', got '%s'", parsed.Tag)
	}

	// Verify boot nonce
	parsedNonce, hasNonce := parsed.BootNonce()
	if !hasNonce {
		t.Error("Expected boot nonce to be present in parsed data")
	} else if parsedNonce != testNonce {
		t.Errorf("Expected nonce 0x%x, got 0x%x", testNonce, parsedNonce)
	}
}

func TestRestoreInfoBootNonceBytes(t *testing.T) {
	testCases := []struct {
		name      string
		nonceHex  string
		expectErr bool
	}{
		{
			name:     "valid 8-byte nonce",
			nonceHex: "1234567890abcdef",
		},
		{
			name:     "valid zeros",
			nonceHex: "0000000000000000",
		},
		{
			name:     "valid max value",
			nonceHex: "ffffffffffffffff",
		},
		{
			name:      "invalid short nonce",
			nonceHex:  "12345678",
			expectErr: true,
		},
		{
			name:      "invalid long nonce",
			nonceHex:  "1234567890abcdef1234",
			expectErr: true,
		},
		{
			name:      "invalid hex",
			nonceHex:  "invalid-hex-data",
			expectErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			nonceBytes, err := hex.DecodeString(tt.nonceHex)
			if err != nil && !tt.expectErr {
				t.Fatalf("Failed to decode test hex: %v", err)
			}
			if err != nil && tt.expectErr {
				return // Expected error in hex decode
			}

			if len(nonceBytes) != 8 && tt.expectErr {
				t.Logf("Correctly detected invalid nonce length: %d", len(nonceBytes))
				return
			}

			if len(nonceBytes) == 8 {
				// Convert to uint64 and back for validation
				nonce := uint64(nonceBytes[0])<<56 |
					uint64(nonceBytes[1])<<48 |
					uint64(nonceBytes[2])<<40 |
					uint64(nonceBytes[3])<<32 |
					uint64(nonceBytes[4])<<24 |
					uint64(nonceBytes[5])<<16 |
					uint64(nonceBytes[6])<<8 |
					uint64(nonceBytes[7])

				restoreInfo := NewWithBootNonce(nonce)
				if restoreInfo == nil {
					t.Fatal("Expected RestoreInfo but got nil")
				}

				retrievedNonce, hasNonce := restoreInfo.BootNonce()
				if !hasNonce {
					t.Error("Expected boot nonce to be present")
				} else if retrievedNonce != nonce {
					t.Errorf("Expected nonce 0x%x, got 0x%x", nonce, retrievedNonce)
				}
			}
		})
	}
}

func TestRestoreInfoMarshal(t *testing.T) {
	restoreInfo := NewWithBootNonce(0x1234567890abcdef)

	data, err := restoreInfo.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty marshaled data")
	}

	// Test roundtrip
	parsed, err := ParseRestoreInfo(data)
	if err != nil {
		t.Fatalf("Roundtrip ParseRestoreInfo() error = %v", err)
	}

	if parsed.Tag != restoreInfo.Tag {
		t.Errorf("Roundtrip Tag = %v, want %v", parsed.Tag, restoreInfo.Tag)
	}

	originalNonce, _ := restoreInfo.BootNonce()
	parsedNonce, hasNonce := parsed.BootNonce()
	if !hasNonce {
		t.Error("Expected boot nonce in roundtrip data")
	} else if parsedNonce != originalNonce {
		t.Errorf("Roundtrip nonce = 0x%x, want 0x%x", parsedNonce, originalNonce)
	}
}

func TestRestoreInfoString(t *testing.T) {
	restoreInfo := NewWithBootNonce(0x1234567890abcdef)

	str := restoreInfo.String()
	if str == "" {
		t.Error("Expected non-empty string representation")
	}

	// Check that it contains expected components
	if !bytes.Contains([]byte(str), []byte("IM4R")) {
		t.Error("Expected string to contain 'IM4R'")
	}

	if !bytes.Contains([]byte(str), []byte("1234567890abcdef")) {
		t.Error("Expected string to contain boot nonce")
	}
}

func TestCreateRestoreInfoFromBytes(t *testing.T) {
	// Test CreateRestoreInfo with []byte nonce
	testCases := []struct {
		name          string
		nonceBytes    []byte
		expectedNonce uint64
		expectError   bool
	}{
		{
			name:          "valid 8-byte nonce",
			nonceBytes:    []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef},
			expectedNonce: 0x1234567890abcdef,
			expectError:   false,
		},
		{
			name:          "zero nonce bytes",
			nonceBytes:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectedNonce: 0x0000000000000000,
			expectError:   false,
		},
		{
			name:          "max value nonce bytes",
			nonceBytes:    []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			expectedNonce: 0xffffffffffffffff,
			expectError:   false,
		},
		{
			name:        "invalid short nonce",
			nonceBytes:  []byte{0x12, 0x34, 0x56, 0x78},
			expectError: true,
		},
		{
			name:        "invalid long nonce",
			nonceBytes:  []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34},
			expectError: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			restoreInfo, err := CreateRestoreInfo(tt.nonceBytes)
			if (err != nil) != tt.expectError {
				t.Fatalf("CreateRestoreInfo() error = %v, expectError %v", err, tt.expectError)
			}

			if tt.expectError {
				return // No further validation needed for error cases
			}

			if restoreInfo == nil {
				t.Fatal("Expected RestoreInfo but got nil")
			}

			if restoreInfo.Tag != "IM4R" {
				t.Errorf("Expected tag 'IM4R', got '%s'", restoreInfo.Tag)
			}

			// Verify the boot nonce was correctly read from bytes
			bootNonce, hasNonce := restoreInfo.BootNonce()
			if !hasNonce {
				t.Error("Expected boot nonce to be present")
			} else if bootNonce != tt.expectedNonce {
				t.Errorf("Expected nonce 0x%x, got 0x%x", tt.expectedNonce, bootNonce)
			}
		})
	}
}

func TestRestoreInfoErrors(t *testing.T) {
	// Test parsing invalid data
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
			_, err := ParseRestoreInfo(tt.data)
			if err == nil {
				t.Errorf("Expected error for %s", tt.name)
			}
		})
	}
}

func BenchmarkRestoreInfoCreation(b *testing.B) {
	b.Run("NewWithBootNonce", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewWithBootNonce(0x1234567890abcdef)
		}
	})

	props := map[string]any{
		"BNCN": uint64(0x1234567890abcdef),
		"TEST": "test value",
		"NUM":  42,
	}

	b.Run("New", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = New(props)
		}
	})
}

func BenchmarkRestoreInfoParsing(b *testing.B) {
	restoreInfo := NewWithBootNonce(0x1234567890abcdef)
	data, err := restoreInfo.Marshal()
	if err != nil {
		b.Fatalf("Failed to marshal test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseRestoreInfo(data)
	}
}
