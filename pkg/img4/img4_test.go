package img4

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseIm4r(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func() ([]byte, error)
		expectError bool
		expectNonce string
	}{
		{
			name: "ParseStandaloneIm4r",
			setupFunc: func() ([]byte, error) {
				// Create a simple IM4R with BNCN structure
				nonce := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
				return createTestIm4rData(nonce), nil
			},
			expectError: false,
			expectNonce: "1234567890abcdef",
		},
		{
			name: "ParseIm4rWithInvalidData",
			setupFunc: func() ([]byte, error) {
				return []byte("invalid data"), nil
			},
			expectError: true,
		},
		{
			name: "ParseEmptyIm4r",
			setupFunc: func() ([]byte, error) {
				return []byte{}, nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.setupFunc()
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			restoreInfo, err := ParseIm4r(bytes.NewReader(data))
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if restoreInfo == nil {
				t.Fatal("Expected RestoreInfo but got nil")
			}

			if restoreInfo.Generator.Name != "BNCN" {
				t.Errorf("Expected generator name 'BNCN', got '%s'", restoreInfo.Generator.Name)
			}

			actualNonce := hex.EncodeToString(restoreInfo.Generator.Data)
			if actualNonce != tt.expectNonce {
				t.Errorf("Expected nonce %s, got %s", tt.expectNonce, actualNonce)
			}
		})
	}
}

func TestParseStandaloneIm4rGenerator(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    string
		expectError bool
	}{
		{
			name:        "SimpleBNCNFormat",
			input:       append([]byte("BNCN"), []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}...),
			expected:    "1234567890abcdef",
			expectError: false,
		},
		{
			name:        "RawNonceOnly",
			input:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			expected:    "1122334455667788",
			expectError: false,
		},
		{
			name:        "TooShortData",
			input:       []byte{0x11, 0x22},
			expected:    "",
			expectError: true, // Too short to be valid
		},
		{
			name:        "EmptyData",
			input:       []byte{},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseStandaloneIm4rGenerator(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			actual := hex.EncodeToString(result)
			if actual != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, actual)
			}
		})
	}
}

func TestCreateIm4p(t *testing.T) {
	tests := []struct {
		name        string
		fourcc      string
		description string
		data        []byte
		kbags       []Keybag
		expectError bool
	}{
		{
			name:        "ValidIm4p",
			fourcc:      "test",
			description: "Test payload",
			data:        []byte("Hello, World!"),
			kbags:       nil,
			expectError: false,
		},
		{
			name:        "Im4pWithKeybags",
			fourcc:      "krnl",
			description: "Kernel",
			data:        []byte("kernel data"),
			kbags: []Keybag{
				{Type: PRODUCTION, IV: make([]byte, 16), Key: make([]byte, 32)},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im4p := CreateIm4p("IM4P", tt.fourcc, tt.description, tt.data, tt.kbags)
			if im4p == nil {
				t.Fatal("Expected IM4P but got nil")
			}

			if im4p.Name != "IM4P" {
				t.Errorf("Expected name 'IM4P', got '%s'", im4p.Name)
			}

			if im4p.Type != tt.fourcc {
				t.Errorf("Expected fourcc '%s', got '%s'", tt.fourcc, im4p.Type)
			}

			if im4p.Description != tt.description {
				t.Errorf("Expected description '%s', got '%s'", tt.description, im4p.Description)
			}

			if !bytes.Equal(im4p.Data, tt.data) {
				t.Error("Data doesn't match expected")
			}

			if len(tt.kbags) > 0 && len(im4p.Kbags) != len(tt.kbags) {
				t.Errorf("Expected %d keybags, got %d", len(tt.kbags), len(im4p.Kbags))
			}
		})
	}
}

func TestCreateIm4pFile(t *testing.T) {
	fourcc := "test"
	description := "Test payload"
	data := []byte("test data")

	result, err := CreateIm4pFile(fourcc, description, data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("Expected non-empty result")
	}

	// Verify we can parse the created IM4P
	im4p, err := ParseIm4p(bytes.NewReader(result))
	if err != nil {
		t.Fatalf("Failed to parse created IM4P: %v", err)
	}

	if im4p.Type != fourcc {
		t.Errorf("Expected fourcc '%s', got '%s'", fourcc, im4p.Type)
	}

	if im4p.Description != description {
		t.Errorf("Expected description '%s', got '%s'", description, im4p.Description)
	}

	if !bytes.Equal(im4p.Data, data) {
		t.Error("Data doesn't match expected")
	}
}

func TestCreateImg4File(t *testing.T) {
	// Create test IM4P data
	im4pData, err := CreateIm4pFile("test", "Test payload", []byte("test data"))
	if err != nil {
		t.Fatalf("Failed to create IM4P: %v", err)
	}

	// Create test IM4R data
	nonce := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
	im4rData := createTestIm4rData(nonce)

	tests := []struct {
		name             string
		im4pData         []byte
		manifestData     []byte
		restoreInfoData  []byte
		expectError      bool
	}{
		{
			name:             "OnlyIm4p",
			im4pData:         im4pData,
			manifestData:     nil,
			restoreInfoData:  nil,
			expectError:      false,
		},
		{
			name:             "WithRestoreInfo",
			im4pData:         im4pData,
			manifestData:     nil,
			restoreInfoData:  im4rData,
			expectError:      false,
		},
		{
			name:             "EmptyIm4p",
			im4pData:         []byte{},
			manifestData:     nil,
			restoreInfoData:  nil,
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CreateImg4File(tt.im4pData, tt.manifestData, tt.restoreInfoData)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(result) == 0 {
				t.Fatal("Expected non-empty result")
			}

			// Verify we can parse the created IMG4
			img4, err := Parse(bytes.NewReader(result))
			if err != nil {
				t.Fatalf("Failed to parse created IMG4: %v", err)
			}

			if img4.Name != "IM4P" { // This is the payload name
				t.Errorf("Expected name 'IM4P', got '%s'", img4.Name)
			}
		})
	}
}

func TestDetectFileType(t *testing.T) {
	// Create test IM4P
	im4pData, err := CreateIm4pFile("test", "Test", []byte("data"))
	if err != nil {
		t.Fatalf("Failed to create IM4P: %v", err)
	}

	// Create test IMG4
	img4Data, err := CreateImg4File(im4pData, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create IMG4: %v", err)
	}

	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "DetectIm4p",
			data:     im4pData,
			expected: "IM4P",
		},
		{
			name:     "DetectImg4",
			data:     img4Data,
			expected: "IMG4",
		},
		{
			name:     "InvalidData",
			data:     []byte("invalid"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DetectFileType(bytes.NewReader(tt.data))
			if tt.expected == "" {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestDetectCompressionType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "NoCompression",
			data:     []byte("regular data"),
			expected: "none",
		},
		{
			name:     "LZFSECompression",
			data:     []byte("bvx2compressed"),
			expected: "LZFSE",
		},
		{
			name:     "LZSSCompression",
			data:     []byte("complzssdata"),
			expected: "LZSS",
		},
		{
			name:     "TooShort",
			data:     []byte("hi"),
			expected: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectCompressionType(tt.data)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestKeybagString(t *testing.T) {
	kbag := Keybag{
		Type: PRODUCTION,
		IV:   []byte{0x01, 0x02, 0x03, 0x04},
		Key:  []byte{0x05, 0x06, 0x07, 0x08},
	}

	result := kbag.String()
	if result == "" {
		t.Error("Expected non-empty string representation")
	}

	// Check that it contains expected components
	if !bytes.Contains([]byte(result), []byte("PRODUCTION")) {
		t.Error("Expected string to contain 'PRODUCTION'")
	}
}

func TestKbagType(t *testing.T) {
	tests := []struct {
		kType    kbagType
		expected string
		short    string
	}{
		{PRODUCTION, "PRODUCTION", "prod"},
		{DEVELOPMENT, "DEVELOPMENT", "dev"},
		{DECRYPTED, "DECRYPTED", "dec"},
		{kbagType(99), "UNKNOWN(99)", "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.kType.String() != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, tt.kType.String())
			}

			if tt.kType.Short() != tt.short {
				t.Errorf("Expected short '%s', got '%s'", tt.short, tt.kType.Short())
			}
		})
	}
}

func TestValidateImg4Structure(t *testing.T) {
	// Create a valid IMG4 for testing
	im4pData, err := CreateIm4pFile("test", "Test payload", []byte("test data"))
	if err != nil {
		t.Fatalf("Failed to create IM4P: %v", err)
	}

	img4Data, err := CreateImg4File(im4pData, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create IMG4: %v", err)
	}

	result, err := ValidateImg4Structure(bytes.NewReader(img4Data))
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.IsValid {
		t.Errorf("Expected valid structure, got invalid: %v", result.Errors)
	}

	if result.Structure != "IMG4" {
		t.Errorf("Expected structure 'IMG4', got '%s'", result.Structure)
	}
}

func TestIntegrationWithFileSystem(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "img4_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test IM4R creation and parsing
	t.Run("Im4rFileOperations", func(t *testing.T) {
		nonce := []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
		im4rData := createTestIm4rData(nonce)

		// Write to file
		im4rPath := filepath.Join(tempDir, "test.im4r")
		if err := os.WriteFile(im4rPath, im4rData, 0644); err != nil {
			t.Fatalf("Failed to write IM4R file: %v", err)
		}

		// Read and parse
		f, err := os.Open(im4rPath)
		if err != nil {
			t.Fatalf("Failed to open IM4R file: %v", err)
		}
		defer f.Close()

		restoreInfo, err := ParseIm4r(f)
		if err != nil {
			t.Fatalf("Failed to parse IM4R file: %v", err)
		}

		expectedNonce := hex.EncodeToString(nonce)
		actualNonce := hex.EncodeToString(restoreInfo.Generator.Data)
		if actualNonce != expectedNonce {
			t.Errorf("Expected nonce %s, got %s", expectedNonce, actualNonce)
		}
	})

	// Test IM4P creation and parsing
	t.Run("Im4pFileOperations", func(t *testing.T) {
		testData := []byte("This is test payload data for IM4P")
		im4pData, err := CreateIm4pFile("test", "Test Description", testData)
		if err != nil {
			t.Fatalf("Failed to create IM4P: %v", err)
		}

		// Write to file
		im4pPath := filepath.Join(tempDir, "test.im4p")
		if err := os.WriteFile(im4pPath, im4pData, 0644); err != nil {
			t.Fatalf("Failed to write IM4P file: %v", err)
		}

		// Read and parse
		im4p, err := OpenIm4p(im4pPath)
		if err != nil {
			t.Fatalf("Failed to open IM4P file: %v", err)
		}

		if im4p.Type != "test" {
			t.Errorf("Expected fourcc 'test', got '%s'", im4p.Type)
		}

		if !bytes.Equal(im4p.Data, testData) {
			t.Error("Payload data doesn't match")
		}
	})
}

// Helper function to create test IM4R data using the same approach as the production code
func createTestIm4rData(nonce []byte) []byte {
	// Create generator data containing BNCN + boot nonce
	generatorData := make([]byte, 0, 4+len(nonce))
	generatorData = append(generatorData, []byte("BNCN")...)
	generatorData = append(generatorData, nonce...)

	// Use the same structure as the actual createIm4rData function
	im4rStruct := struct {
		Name      string `asn1:"ia5"`
		Generator []byte
	}{
		Name:      "IM4R",
		Generator: generatorData,
	}

	im4rData, err := asn1.Marshal(im4rStruct)
	if err != nil {
		// Fallback to simple format if marshaling fails
		result := append([]byte("IM4RBNCN"), nonce...)
		return result
	}

	return im4rData
}

func BenchmarkParseIm4r(b *testing.B) {
	nonce := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
	im4rData := createTestIm4rData(nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseIm4r(bytes.NewReader(im4rData))
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
	}
}

func BenchmarkCreateIm4p(b *testing.B) {
	testData := []byte("benchmark test data")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		im4p := CreateIm4p("IM4P", "test", "Benchmark", testData, nil)
		if im4p == nil {
			b.Fatal("Failed to create IM4P")
		}
	}
}